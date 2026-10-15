#!/usr/bin/env python3
"""
Load test da Etapa C: mede latencia e overhead do caminho protegido vs. controle.

Dispara requisicoes concorrentes contra rotas representativas e grava, por rota,
p50/p90/p95/p99, throughput e taxa de erro em results/latencia-<perfil>.csv.
Comparado entre os perfis, isola o custo (ms) introduzido pela validacao de JWT
no gateway e pelo Spring Security no servico.

Usa apenas a biblioteca padrao (sem dependencias externas).
"""
import argparse, csv, json, os, statistics, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

ROUTES = [
    ("GET", "/api/products", None),
    ("GET", "/api/products/search?q=roteador&order=name", None),
    ("GET", "/api/orders/2", "AUTH"),
]

def one_request(base, method, path, token):
    url = base + path
    req = urllib.request.Request(url, method=method)
    if token:
        req.add_header("Authorization", "Bearer " + token)
    t0 = time.perf_counter()
    code = 0
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read(); code = r.status
    except urllib.error.HTTPError as e:
        code = e.code
    except Exception:
        code = -1
    return (time.perf_counter() - t0) * 1000.0, code

def login(base, user="alice", pw="alice123"):
    try:
        data = json.dumps({"username": user, "password": pw}).encode()
        req = urllib.request.Request(base + "/api/auth/login", data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read()).get("access_token", "")
    except Exception:
        return ""

def pctl(xs, p):
    if not xs:
        return 0.0
    xs = sorted(xs)
    k = max(0, min(len(xs) - 1, int(round((p / 100.0) * (len(xs) - 1)))))
    return round(xs[k], 2)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="http://localhost:8080")
    ap.add_argument("--profile", default="vulneravel")
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--duration", type=int, default=60)
    ap.add_argument("--results", default=os.path.join(os.path.dirname(__file__), "..", "results"))
    args = ap.parse_args()

    token = login(args.base)
    print(f"[loadtest] base={args.base} perfil={args.profile} token={'ok' if token else 'ausente'}")

    per_route = {f"{m} {p}": {"lat": [], "codes": {}} for m, p, _ in ROUTES}
    end = time.time() + args.duration
    submitted = 0

    with ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {}
        while time.time() < end:
            for m, p, auth in ROUTES:
                fut = ex.submit(one_request, args.base, m, p, token if auth else None)
                futures[fut] = f"{m} {p}"
                submitted += 1
            # colhe o que ja terminou para nao acumular
            done = [f for f in list(futures) if f.done()]
            for f in done:
                key = futures.pop(f)
                lat, code = f.result()
                per_route[key]["lat"].append(lat)
                per_route[key]["codes"][code] = per_route[key]["codes"].get(code, 0) + 1
        for f in as_completed(list(futures)):
            key = futures[f]
            lat, code = f.result()
            per_route[key]["lat"].append(lat)
            per_route[key]["codes"][code] = per_route[key]["codes"].get(code, 0) + 1

    os.makedirs(args.results, exist_ok=True)
    out = os.path.join(args.results, f"latencia-{args.profile}.csv")
    with open(out, "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["rota", "n", "p50_ms", "p90_ms", "p95_ms", "p99_ms",
                    "media_ms", "throughput_rps", "erro_pct"])
        for key, d in per_route.items():
            lat = d["lat"]; n = len(lat)
            ok = sum(v for c, v in d["codes"].items() if 200 <= c < 400)
            err = n - ok
            w.writerow([key, n, pctl(lat, 50), pctl(lat, 90), pctl(lat, 95),
                        pctl(lat, 99), round(statistics.mean(lat), 2) if lat else 0,
                        round(n / args.duration, 1), round(100 * err / n, 1) if n else 0])
    print(f"[loadtest] {submitted} req enviadas -> {out}")

if __name__ == "__main__":
    main()
