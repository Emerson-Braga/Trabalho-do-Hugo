#!/usr/bin/env python3
"""
Converte os report.json do RESTest em CSVs no formato lido pelo analyze.py.

Entrada: results/restest-raw/<perfil>-s<seed>/report.json
Saida:   results/restest-<perfil>-s<seed>.csv (uma por execucao)

Uma linha por (operacao, codigo de falha) com severidade de erro. Avisos (ex.: F920, status
nao declarado no contrato) nao sao falhas de seguranca e ficam fora.

Atribuicao ao gabarito (regra explicita, sem palavras-chave):
  - 500 (F100) em searchProducts no perfil vulneravel, ausente no protegido do mesmo seed
    -> VULN-SQLI-01. A diferenca entre perfis isola a injecao da falha generica.
  - 500 em getProduct aparece nos dois perfis (ID nao numerico, defeito de robustez): nao e
    atribuido a VULN-SQLI-02, porque o oraculo nao distingue as duas causas.
  - Qualquer outra falha fica como NAO-ATRIBUIDO e conta como falso positivo no analyze.py.

Uso:
    python3 analysis/restest_convert.py --results results
"""
import argparse, csv, glob, json, os, re

ATRIBUICOES = {
    # (perfil, operacao, codigo) -> (id_gabarito, rota)
    ("vulneravel", "searchProducts", 100): ("VULN-SQLI-01", "/api/products/search"),
}

def carregar_erros(path):
    """Mapa (operacao, codigo) -> linha do relatorio, so para severidade de erro."""
    with open(path, encoding="utf-8") as fh:
        rel = json.load(fh)
    erros = {}
    for f in rel.get("faultsByOperation", []):
        if f.get("severity") == "error":
            erros[(f["operation"], f["code"])] = f
    rotas = {op["operation"]: op["path"] for op in rel.get("operations", [])}
    return erros, rotas

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default=os.path.join(os.path.dirname(__file__), "..", "results"))
    args = ap.parse_args()
    raw = os.path.join(args.results, "restest-raw")

    padrao = re.compile(r"^(vulneravel|protegido)-s(\d+)$")
    for pasta in sorted(os.listdir(raw)):
        m = padrao.match(pasta)
        if not m:
            continue
        perfil, seed = m.group(1), m.group(2)
        path = os.path.join(raw, pasta, "report.json")
        if not os.path.exists(path):
            print(f"[restest] {pasta}: report.json ausente, pulando"); continue

        ref = os.path.join(raw, f"protegido-s{seed}", "report.json")
        erros_prot = carregar_erros(ref)[0] if os.path.exists(ref) else {}
        erros, rotas = carregar_erros(path)

        saida = os.path.join(args.results, f"restest-{perfil}-s{seed}.csv")
        with open(saida, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["rota", "operacao", "codigo", "titulo", "severidade", "contagem",
                        "id_gabarito", "observacao"])
            for (op, code), f in sorted(erros.items()):
                rota = rotas.get(op, "")
                id_g, obs = "NAO-ATRIBUIDO", "sem correspondencia no gabarito (falso positivo)"
                chave = (perfil, op, code)
                if chave in ATRIBUICOES:
                    if (op, code) not in erros_prot:
                        id_g, rota = ATRIBUICOES[chave]
                        obs = "500 so no vulneravel: atribuido por diferenca entre perfis"
                    else:
                        obs = "500 nos dois perfis: defeito de robustez, nao atribuido ao SQLi"
                w.writerow([rota, op, f"F{code}", f.get("title", ""), f["severity"],
                            f.get("count", 0), id_g, obs])
        print(f"[restest] {pasta}: {len(erros)} linhas de erro -> {saida}")

if __name__ == "__main__":
    main()
