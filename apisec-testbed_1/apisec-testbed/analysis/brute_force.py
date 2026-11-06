#!/usr/bin/env python3
"""
Teste de brute force com rajada (VULN-AUTH-01: sem rate limit / lockout).

Envia N tentativas de login com senha errada em paralelo, em uma unica rajada. O gateway
limita por IP (token bucket): se a rajada nao recebe nenhum 429, nao ha bloqueio e a falha
esta presente. Uma rajada sequencial (loop de Newman) nunca estoura o burst, por isso este
teste nao fica no Postman.

Veredito:
    VULN-AUTH-01      -> nenhum 429 em N tentativas validas (sem bloqueio)
    SEM-ACHADO        -> ao menos um 429 (rate limit ativo)
    INCONCLUSIVO      -> mais de 10% das tentativas falharam por conexao (resultado nao confiavel)

Uso:
    python3 analysis/brute_force.py --profile protegido --attempts 100
Saida: results/brute-force-<perfil>.json
"""
import argparse, json, os, urllib.error, urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor


def tentativa(base, user, i):
    """Uma tentativa de login com senha errada. Devolve o status HTTP (0 = falha de conexao)."""
    body = json.dumps({"username": user, "password": f"senha-errada-{i}"}).encode()
    req = urllib.request.Request(base + "/api/auth/login", data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 0


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", default="vulneravel")
    ap.add_argument("--base", default="http://localhost:8080")
    ap.add_argument("--user", default="alice")
    ap.add_argument("--attempts", type=int, default=100)
    ap.add_argument("--workers", type=int, default=20)
    ap.add_argument("--results", default=os.path.join(here, "..", "results"))
    ap.add_argument("--run", default="", help="sufixo da rodada (ex.: r1)")
    args = ap.parse_args()

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        codigos = list(pool.map(lambda i: tentativa(args.base, args.user, i), range(args.attempts)))

    contagem = Counter(codigos)
    erros = contagem.get(0, 0)
    n429 = contagem.get(429, 0)

    if erros > 0.1 * args.attempts:
        veredito, achado = "INCONCLUSIVO", None
    elif n429 == 0:
        veredito, achado = "VULN-AUTH-01", "VULN-AUTH-01"
    else:
        veredito, achado = "SEM-ACHADO", None

    resultado = {
        "profile": args.profile,
        "attempts": args.attempts,
        "status": {str(k): v for k, v in sorted(contagem.items())},
        "http_429": n429,
        "erros_conexao": erros,
        "veredito": veredito,
        "achado": achado,
    }
    os.makedirs(args.results, exist_ok=True)
    sufixo = f"-{args.run}" if args.run else ""
    caminho = os.path.join(args.results, f"brute-force-{args.profile}{sufixo}.json")
    with open(caminho, "w") as fh:
        json.dump(resultado, fh, indent=2)
        fh.write("\n")

    print(f"[brute-force] perfil={args.profile} tentativas={args.attempts} "
          f"status={resultado['status']} -> {veredito}")
    print(f"[brute-force] escrito: {caminho}")


if __name__ == "__main__":
    main()
