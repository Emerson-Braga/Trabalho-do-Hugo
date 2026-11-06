#!/usr/bin/env python3
"""
Amostra CPU (%) e memoria residente (MB) de cada container do testbed com `docker stats`.

Metrica do slide: CPU em % (100 = um core inteiro) e RAM em MB. Usa a memoria do container
(working set do cgroup, como o `docker stats` mostra), nao a heap da JVM.
Uso: python3 analysis/recursos.py --profile vulneravel --scenario carga --duration 120
Saida: results/recursos-<perfil>-<cenario>.csv (timestamp, container, cpu_pct, mem_mb)
"""
import argparse, csv, json, os, re, subprocess, time

UNIDADES = {"B": 1, "kB": 1e3, "KB": 1e3, "KiB": 1024, "MB": 1e6, "MiB": 1024**2,
            "GB": 1e9, "GiB": 1024**3}

def para_bytes(texto):
    m = re.match(r"([\d.]+)\s*([A-Za-z]+)", texto.strip())
    if not m:
        return 0.0
    return float(m.group(1)) * UNIDADES.get(m.group(2), 1)

def amostra():
    """Uma leitura de docker stats para os containers apisec-*."""
    out = subprocess.run(["docker", "stats", "--no-stream", "--format", "{{json .}}"],
                         capture_output=True, text=True, timeout=60).stdout
    linhas = []
    for linha in out.splitlines():
        if not linha.strip():
            continue
        d = json.loads(linha)
        nome = d["Name"]
        if not nome.startswith("apisec-"):
            continue
        cpu = float(d["CPUPerc"].rstrip("%") or 0)
        mem = para_bytes(d["MemUsage"].split("/")[0]) / 1024**2
        linhas.append((nome, round(cpu, 2), round(mem, 1)))
    return linhas

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", required=True)
    ap.add_argument("--scenario", required=True, help="ex.: carga, varredura")
    ap.add_argument("--duration", type=int, default=120)
    ap.add_argument("--interval", type=float, default=5.0)
    ap.add_argument("--results", default=os.path.join(os.path.dirname(__file__), "..", "results"))
    args = ap.parse_args()

    os.makedirs(args.results, exist_ok=True)
    saida = os.path.join(args.results, f"recursos-{args.profile}-{args.scenario}.csv")
    fim = time.time() + args.duration
    n = 0
    with open(saida, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["timestamp", "container", "cpu_pct", "mem_mb"])
        while time.time() < fim:
            t0 = time.time()
            ts = int(t0)
            for nome, cpu, mem in amostra():
                w.writerow([ts, nome, cpu, mem])
            n += 1
            time.sleep(max(0.0, args.interval - (time.time() - t0)))
    print(f"[recursos] {n} amostras -> {saida}")

if __name__ == "__main__":
    main()
