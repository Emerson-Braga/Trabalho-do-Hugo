#!/usr/bin/env python3
"""
Exporta series de CPU/RAM/latencia do Prometheus para CSV, congelando as medidas
da Etapa C no momento da varredura. Sem dependencias externas.
"""
import argparse, csv, json, os, time, urllib.parse, urllib.request

QUERIES = {
    "cpu_cores":  'sum by (name) (rate(container_cpu_usage_seconds_total{name=~"apisec-.*"}[1m]))',
    "mem_bytes":  'container_memory_working_set_bytes{name=~"apisec-.*"}',
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
    ap.add_argument("--results", default=os.path.join(os.path.dirname(__file__), "..", "results"))
    args = ap.parse_args()

    end = int(time.time()); start = end - args.minutes * 60
    os.makedirs(args.results, exist_ok=True)
    out = os.path.join(args.results, f"telemetria-{args.profile}.csv")
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh); w.writerow(["metrica", "serie", "timestamp", "valor"])
        for name, expr in QUERIES.items():
            try:
                res = query_range(args.prom, expr, start, end)
            except Exception as e:
                print(f"[prom] falha em {name}: {e}"); continue
            for s in res.get("data", {}).get("result", []):
                label = s["metric"].get("name") or s["metric"].get("uri") or json.dumps(s["metric"])
                for ts, val in s["values"]:
                    w.writerow([name, label, int(ts), val])
    print(f"[prom] telemetria -> {out}")

if __name__ == "__main__":
    main()
