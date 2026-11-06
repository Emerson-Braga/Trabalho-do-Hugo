#!/usr/bin/env python3
"""
Resume as execucoes do RESTest por seed: TP, FP e FN por perfil, com media e desvio padrao.

Reutiliza parse_restest e classify do analyze.py, para que o casamento com o gabarito seja o
mesmo da analise principal. Saida: results/restest-repeticoes.md
"""
import glob, json, os, re, statistics as st, sys
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import analyze  # noqa: E402

def main():
    results = os.path.join(HERE, "..", "results")
    gt = json.load(open(os.path.join(HERE, "ground_truth.json"), encoding="utf-8"))["injected"]
    linhas = defaultdict(list)  # perfil -> lista de (seed, tp, fp, fn)

    for path in sorted(glob.glob(os.path.join(results, "restest-*-s*.csv"))):
        m = re.search(r"restest-(vulneravel|protegido)-s(\d+)\.csv$", path)
        if not m:
            continue
        perfil, seed = m.group(1), int(m.group(2))
        alertas = analyze.parse_restest(path)
        tp_ids, fp, _ = analyze.classify(alertas, gt, "restest")
        esperado = {g["id"] for g in gt if "restest" in g.get("detectable_by", [])} if perfil == "vulneravel" else set()
        tp = len(tp_ids & esperado)
        fn = len(esperado - tp_ids)
        linhas[perfil].append((seed, tp, fp, fn))

    def resumo(valores):
        if len(valores) < 2:
            return f"{valores[0]:.1f} (1 execucao)" if valores else "-"
        return f"{st.mean(valores):.1f} ± {st.pstdev(valores):.1f}"

    saida = os.path.join(results, "restest-repeticoes.md")
    with open(saida, "w", encoding="utf-8") as fh:
        fh.write("### RESTest: repeticoes por seed\n\n")
        fh.write("| Perfil | Seeds | TP (média ± dp) | FN (média ± dp) | FP (média ± dp) |\n")
        fh.write("|---|---|---|---|---|\n")
        for perfil in ["vulneravel", "protegido"]:
            execs = sorted(linhas.get(perfil, []))
            if not execs:
                continue
            seeds = ", ".join(str(s) for s, *_ in execs)
            fh.write(f"| {perfil} | {seeds} | {resumo([t for _, t, _, _ in execs])} | "
                     f"{resumo([n for _, _, _, n in execs])} | {resumo([f for _, _, f, _ in execs])} |\n")
        fh.write("\nDetalhe por seed (TP, FP, FN):\n\n")
        for perfil in ["vulneravel", "protegido"]:
            for seed, tp, fp, fn in sorted(linhas.get(perfil, [])):
                fh.write(f"- {perfil}, seed {seed}: TP={tp}, FP={fp}, FN={fn}\n")
    print(open(saida, encoding="utf-8").read())
    print(f"[restest-repeticoes] escrito: {saida}")

if __name__ == "__main__":
    main()
