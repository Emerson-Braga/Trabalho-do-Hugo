#!/usr/bin/env python3
"""
Analisador de acuracia de seguranca do testbed.

Consolida os relatorios brutos das ferramentas (OWASP ZAP, RESTest, Postman/Newman),
casa cada alerta contra o gabarito (ground_truth.json) e calcula, por ferramenta e por
perfil, as metricas da Etapa B do plano:

    TPR (recall) = TP / (TP + FN)         quantas das falhas injetadas foram detectadas
    Precisao     = TP / (TP + FP)         quantos alertas eram falhas reais
    FPR bruto    = FP / (FP + TP)         proporcao de ruido no relatorio
    F1           = 2*P*R / (P+R)

Casamento alerta<->gabarito: um alerta conta como TP se sua rota casa (normalizada,
com curinga de path param) E sua classe/CWE/owasp casa com uma entrada do gabarito
marcada como detectavel por aquela ferramenta. Caso contrario e FP.

Uso:
    python3 analyze.py --profile vulneravel --results ../results --gt ground_truth.json
Saidas em results/:
    matriz-ferramenta-vulnerabilidade.csv   (cruzamento ferramenta x vuln, Etapa B)
    metricas-acuracia.csv                    (TPR/FPR/precisao/F1 por ferramenta)
    metricas-acuracia.md                     (mesma tabela em Markdown para o artigo)
"""
import argparse, csv, json, os, re, sys, xml.etree.ElementTree as ET
from collections import defaultdict

# ----------------------------------------------------------------- helpers
PATHPARAM = re.compile(r"/\d+(?=/|$)")

def norm_route(r):
    """Normaliza rota: remove query, host e substitui ids numericos por {id}."""
    if not r:
        return ""
    r = re.sub(r"https?://[^/]+", "", r)
    r = r.split("?")[0].rstrip("/")
    r = PATHPARAM.sub("/{id}", r)
    return r or "/"

def route_match(alert_route, gt_route):
    a, g = norm_route(alert_route), norm_route(gt_route)
    return g == "*" or a == g or a.startswith(g)

# ----------------------------------------------------------------- parsers
def parse_zap(path):
    """Le zap-<perfil>.json (formato do zap-api-scan)."""
    out = []
    if not os.path.exists(path):
        return out
    with open(path) as fh:
        data = json.load(fh)
    sites = data.get("site", data.get("@site", []))
    if isinstance(sites, dict):
        sites = [sites]
    for site in sites:
        for al in site.get("alerts", []):
            try:
                pid = int(al.get("pluginid", al.get("pluginId", -1)))
            except (TypeError, ValueError):
                pid = -1
            for inst in al.get("instances", [{}]) or [{}]:
                out.append({
                    "tool": "zap",
                    "plugin": pid,
                    "name": al.get("name", al.get("alert", "")),
                    "route": inst.get("uri", ""),
                    "risk": al.get("riskdesc", al.get("riskcode", "")),
                })
    return out

def parse_postman(path):
    """Le results/postman-findings.json (array normalizado gerado pela colecao)."""
    if not os.path.exists(path):
        return []
    with open(path) as fh:
        try:
            arr = json.load(fh)
        except json.JSONDecodeError:
            return []
    return [{"tool": "postman", "id": a.get("id"), "route": a.get("route", ""),
             "name": a.get("class", ""), "risk": a.get("severity", "")} for a in arr]

def parse_restest(path):
    """Le results/restest-<perfil>.csv (uma linha por caso de teste)."""
    out = []
    if not os.path.exists(path):
        return out
    with open(path, newline="") as fh:
        for row in csv.DictReader(fh):
            verdict = (row.get("oracleResult") or row.get("result") or "").lower()
            if verdict in ("fail", "failed", "false", "vulnerable", "bypass"):
                out.append({"tool": "restest",
                            "route": row.get("path", row.get("endpoint", "")),
                            "name": row.get("faultType", row.get("oracle", "")),
                            "risk": row.get("severity", "")})
    return out

# ----------------------------------------------------------------- matching
def classify(alerts, gt, tool):
    """Retorna (tp_ids:set, fp:int, matched_alerts:list[(alert, gt_id|None)])."""
    tp_ids, fp = set(), 0
    matched = []
    gt_tool = [g for g in gt if tool in g.get("detectable_by", [])]
    for al in alerts:
        hit = None
        for g in gt_tool:
            if not route_match(al.get("route", ""), g["route"]):
                continue
            # criterio de classe: id explicito (postman/restest) ou plugin-id (zap)
            if al.get("id") and al["id"] == g["id"]:
                hit = g; break
            if al.get("plugin") and al["plugin"] in g.get("zap_alert_ids", []):
                hit = g; break
            if not al.get("id") and not al.get("plugin"):
                # restest: casa por rota + palavras-chave da classe
                name = al.get("name", "").lower()
                if any(k in name for k in g.get("match_keywords", [])):
                    hit = g; break
        if hit:
            tp_ids.add(hit["id"]); matched.append((al, hit["id"]))
        else:
            fp += 1; matched.append((al, None))
    return tp_ids, fp, matched

def metrics(tp, fp, fn):
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    prec   = tp / (tp + fp) if (tp + fp) else 0.0
    fpr    = fp / (fp + tp) if (fp + tp) else 0.0
    f1     = 2 * prec * recall / (prec + recall) if (prec + recall) else 0.0
    return recall, prec, fpr, f1

# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="vulneravel")
    ap.add_argument("--results", default="../results")
    ap.add_argument("--gt", default="ground_truth.json")
    args = ap.parse_args()

    with open(args.gt) as fh:
        gt = json.load(fh)["injected"]

    R = args.results
    p = args.profile
    tools = {
        "zap":     parse_zap(os.path.join(R, f"zap-{p}.json")),
        "restest": parse_restest(os.path.join(R, f"restest-{p}.csv")),
        "postman": parse_postman(os.path.join(R, "postman-findings.json")),
    }

    # ---- gabarito esperado por ferramenta neste perfil
    expected = defaultdict(set)
    if p.startswith("vuln"):
        for g in gt:
            for t in g.get("detectable_by", []):
                expected[t].add(g["id"])
    # perfil protegido: expected vazio -> qualquer TP e regressao de seguranca

    os.makedirs(R, exist_ok=True)
    rows_metrics = []
    matrix = defaultdict(dict)   # vuln_id -> {tool: 'TP'|'FN'}

    for tool, alerts in tools.items():
        tp_ids, fp, matched = classify(alerts, gt, tool)
        exp = expected[tool]
        tp = len(tp_ids & exp) if exp else len(tp_ids)
        fn = len(exp - tp_ids)
        recall, prec, fpr, f1 = metrics(tp, fp, fn)
        rows_metrics.append({
            "ferramenta": tool, "perfil": p,
            "TP": tp, "FP": fp, "FN": fn,
            "TPR_recall": round(recall, 3), "precisao": round(prec, 3),
            "FPR_bruto": round(fpr, 3), "F1": round(f1, 3),
            "n_alertas": len(alerts),
        })
        for vid in exp:
            matrix[vid][tool] = "TP" if vid in tp_ids else "FN"

    # ---- matriz ferramenta x vulnerabilidade
    gt_index = {g["id"]: g for g in gt}
    mpath = os.path.join(R, f"matriz-ferramenta-vulnerabilidade-{p}.csv")
    with open(mpath, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["vuln_id", "owasp", "classe", "rota", "zap", "restest", "postman"])
        for vid, g in gt_index.items():
            w.writerow([vid, g["owasp"], g["class"], g["route"],
                        matrix[vid].get("zap", "-"),
                        matrix[vid].get("restest", "-"),
                        matrix[vid].get("postman", "-")])

    # ---- metricas CSV + Markdown
    cpath = os.path.join(R, f"metricas-acuracia-{p}.csv")
    with open(cpath, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows_metrics[0].keys()))
        w.writeheader(); w.writerows(rows_metrics)

    mdpath = os.path.join(R, f"metricas-acuracia-{p}.md")
    with open(mdpath, "w") as fh:
        fh.write(f"### Acuracia de deteccao - perfil {p}\n\n")
        fh.write("| Ferramenta | TP | FP | FN | TPR (recall) | Precisao | FPR bruto | F1 |\n")
        fh.write("|---|---|---|---|---|---|---|---|\n")
        for r in rows_metrics:
            fh.write(f"| {r['ferramenta']} | {r['TP']} | {r['FP']} | {r['FN']} | "
                     f"{r['TPR_recall']} | {r['precisao']} | {r['FPR_bruto']} | {r['F1']} |\n")

    print(f"[analyze] perfil={p}")
    for r in rows_metrics:
        print(f"  {r['ferramenta']:8s} TP={r['TP']} FP={r['FP']} FN={r['FN']} "
              f"TPR={r['TPR_recall']} prec={r['precisao']} FPR={r['FPR_bruto']} F1={r['F1']}")
    print(f"[analyze] escrito: {mpath}\n           {cpath}\n           {mdpath}")

if __name__ == "__main__":
    sys.exit(main())
