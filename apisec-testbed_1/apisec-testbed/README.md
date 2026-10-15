# APISec Testbed — Benchmarking Empírico de Segurança de APIs em Microsserviços

Reprodução empírica evoluída do mapeamento de **Mendes et al. (2025)**. Onde o artigo
mede *popularidade* de ferramentas e estratégias, este testbed mede **eficácia**
(TPR/FPR), **cobertura** (matriz ferramenta × vulnerabilidade) e **custo**
(latência, CPU, RAM) num ambiente controlado e reproduzível.

Disciplina: Segurança em Redes de Computadores — Prof. Hugo Kuribayashi (Unifesspa).

---

## Desenho experimental

Um único binário do microsserviço alvo roda em dois perfis, e a **estratégia de defesa é a única variável independente**:

| Perfil | Spring Security / RBAC | API Gateway + OAuth2/JWT (Keycloak) | Rate limit | Falhas injetadas |
|---|---|---|---|---|
| **A — VULNERÁVEL** (controle) | desligado | desligado (gateway só roteia) | não | SQLi, BOLA, Broken Auth, Misconfig |
| **B — PROTEGIDO** | ligado | ligado | sim | as mesmas, agora mitigadas |

Comparar A e B responde: *cada estratégia popularizada por Mendes et al. de fato
mitiga a vulnerabilidade que promete, e a que custo de latência/recursos?*

### Vulnerabilidades injetadas (OWASP API Security Top 10 : 2023)

| id | OWASP | Classe | Rota |
|---|---|---|---|
| VULN-SQLI-01/02 | API8 | SQL Injection | `/api/products/search`, `/api/products/{id}` |
| VULN-BOLA-01 | API1 | Broken Object Level Authorization | `/api/orders/{id}` |
| VULN-BOLA-02 | API3 | Excessive Data Exposure | `/api/orders/{id}` |
| VULN-AUTH-01/02 | API2 | Broken Auth (sem rate limit / user enumeration) | `/api/auth/login` |
| VULN-MISC-01/02/03 | API8 | Misconfig (debug/actuator, CORS, stack trace) | `/api/debug/*` |

Gabarito completo em `analysis/ground_truth.json` — é contra ele que TPR/FPR são calculados.

---

## Arquitetura

```
[ ZAP / RESTest / Newman ]  --edge-->  [ API Gateway :8080 ]
                                          | (rede interna)
                                          v
                                   [ Keycloak :8083 ]  <-- OAuth2/JWT
                                          |
                                          v
                              [ target-service :8081 (Spring Boot) ]
                                          |
   [ cAdvisor ] [ Prometheus :9090 ] [ Grafana :3000 ]  <-- telemetria
```

O microsserviço **não** expõe porta ao host: só é alcançável pelo gateway, garantindo
que toda requisição de teste passe pela camada de defesa.

---

## Como rodar (na sua máquina, com Docker)

> Requer Docker + Docker Compose v2. **Não** funciona no ambiente de nuvem do Claude
> (sem daemon Docker) — foi por isso gerado como pacote pronto para você executar.

```bash
# 1. perfil de controle (vulnerável)
make up-vuln

# 2. varreduras
make scan-zap      PROFILE=vulneravel
make scan-postman  PROFILE=vulneravel
make scan-restest  PROFILE=vulneravel      # requer imagem/jar do RESTest (isa-group)

# 3. carga + telemetria (Etapa C)
make loadtest  PROFILE=vulneravel
make snapshot  PROFILE=vulneravel

# 4. consolida métricas
make analyze   PROFILE=vulneravel

# 5. repita tudo no perfil protegido
make up-protected
make scan-zap PROFILE=protegido && make scan-postman PROFILE=protegido
make loadtest PROFILE=protegido && make snapshot PROFILE=protegido
make analyze  PROFILE=protegido
```

Grafana em `http://localhost:3000` (admin/admin) já traz o painel *APISec Benchmark*
com latência p95, CPU e RAM por container.

---

## Saídas (pasta `results/`)

| Arquivo | Conteúdo | Etapa do plano |
|---|---|---|
| `zap-<perfil>.{json,html,xml}` | alertas brutos DAST | A |
| `newman-<perfil>.json` / `postman-findings.json` | falhas de lógica/autorização | A |
| `restest-<perfil>.csv` | veredictos do fuzzing por contrato | A |
| `matriz-ferramenta-vulnerabilidade-<perfil>.csv` | **cruzamento ferramenta × vuln** | B |
| `metricas-acuracia-<perfil>.{csv,md}` | **TPR, FPR, precisão, F1** por ferramenta | B |
| `latencia-<perfil>.csv` | p50/p90/p95/p99, throughput, erro por rota | C |
| `telemetria-<perfil>.csv` | séries de CPU/RAM/latência do Prometheus | C |

A tabela `metricas-acuracia-<perfil>.md` entra direto no artigo. O analisador foi
validado com relatórios sintéticos; a lógica de casamento alerta↔gabarito
(normalização de rota + plugin-id/keywords) está em `analysis/analyze.py`.

---

## Reprodutibilidade (Ciência Aberta)

Todo o ambiente é código: `docker-compose.yml`, `.env.*`, realm do Keycloak, scripts de
varredura e de análise. Publicar este diretório num repositório público (com os
`results/` brutos) satisfaz o item de artefatos do plano.

## Limitações metodológicas honestas

- A comparação por popularidade de Mendes et al. e a comparação por eficácia daqui
  medem coisas diferentes; o TPR/FPR depende do **conjunto de payloads** de cada
  ferramenta e da configuração usada — reporte versões e perfis de scan.
- BOLA/IDOR e excessive data exposure raramente são pegos por DAST caixa-preta sem
  oráculo de autorização; por isso o gabarito marca essas classes como detectáveis
  por RESTest/Postman, e não por ZAP baseline. Não é falha do ZAP, é limite do método.
- Um único host de teste: números de CPU/RAM são **relativos** entre os perfis, não
  absolutos transferíveis para produção.

## Estrutura

```
apisec-testbed/
├── docker-compose.yml          .env.vulneravel  .env.protegido  Makefile
├── services/
│   ├── target-service/         # Spring Boot: SUT com flags de vulnerabilidade
│   └── gateway/                # Spring Cloud Gateway + OAuth2 + rate limit
├── keycloak/realm-export.json  # realm apisec (alice, bob, admin)
├── openapi/target-api.yaml     # contrato que guia ZAP api-scan e RESTest
├── scans/                      # run_zap.sh, coleção Postman, config RESTest
├── observability/              # prometheus.yml, dashboards Grafana
└── analysis/                   # ground_truth.json, analyze.py, loadtest.py, prom_snapshot.py
```
