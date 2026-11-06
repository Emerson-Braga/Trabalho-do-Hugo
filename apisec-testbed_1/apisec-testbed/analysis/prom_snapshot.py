#!/usr/bin/env python3
"""
Exporta series de CPU/RAM/latencia do Prometheus para CSV, congelando as medidas
da Etapa C no momento da varredura. Sem dependencias externas.
"""
import argparse, csv, json, os, time, urllib.parse, urllib.request

# CPU/RAM vem das metricas da propria JVM (Micrometer) do gateway e do target.
# O cAdvisor no Docker Desktop nao separa containers por nome (ids de cgroup), por isso nao e usado aqui.
QUERIES = {
    "cpu_proc":   'process_cpu_usage{job=~"gateway|target-service"}',
    "heap_bytes": 'sum by (job) (jvm_memory_used_bytes{area="heap"})',
    "lat_p95_gw": 'histogram_quantile(0.95, sum by (le,uri) (rate(http_server_requests_seconds_bucket{application="gateway"}[1m])))',
    "lat_p95_sut":'histogram_quantile(0.95, sum by (le,uri) (rate(http_server_requests_seconds_bucket{application="target-service"}[1m])))',
}

def query_range(prom, expr, start, end, step=15):
    qs = urllib.parse.urlencode({"query": expr, "start": start, "end": end, "step": step})
    with urllib.request.urlopen(f"{prom}/api/v1/query_range?{qs}", timeout=30) as r:
        return json.loads(r.read())

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prom", default="http://localhost:9090")
    ap.add_argument("--profile", default="vulneravel")
    ap.add_argument("--minutes", type=int, default=30)
    ap.add_argument("--run", default="", help="sufixo da rodada (ex.: r1)")
    ap.add_argument("--results", default=os.path.join(os.path.dirname(__file__), "..", "results"))
    args = ap.parse_args()

    end = int(time.time()); start = end - args.minutes * 60
    os.makedirs(args.results, exist_ok=True)
    sufixo = f"-{args.run}" if args.run else ""
    out = os.path.join(args.results, f"telemetria-{args.profile}{sufixo}.csv")
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["metrica", "serie", "timestamp", "valor"])
        for name, expr in QUERIES.items():
            try:
                res = query_range(args.prom, expr, start, end)
            except Exception as e:
                print(f"[prom] falha em {name}: {e}"); continue
            for s in res.get("data", {}).get("result", []):
                # serie = servico + rota (quando houver), para nao misturar gateway com target
                m = s["metric"]
                label = "/".join(v for v in (m.get("job"), m.get("uri"), m.get("name")) if v) or json.dumps(m)
                for ts, val in s["values"]:
                    w.writerow([name, label, int(ts), val])
    print(f"[prom] telemetria -> {out}")

if __name__ == "__main__":
    main()
