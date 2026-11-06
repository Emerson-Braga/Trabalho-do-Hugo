# Testbed de benchmarking de seguranca de APIs - atalhos de operacao
COMPOSE=docker compose

.PHONY: help build up-vuln up-protected down logs \
        scan-zap scan-postman scan-restest loadtest analyze snapshot clean

help:
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sed 's/:.*## /\t/'

build: ## Compila e constroi as imagens
	$(COMPOSE) build

up-vuln: ## Sobe o SUT no perfil VULNERAVEL (controle)
	cp .env.vulneravel .env && $(COMPOSE) up -d --build
	@echo ">> perfil VULNERAVEL no ar. Gateway http://localhost:8080  Grafana http://localhost:3000"

up-protected: ## Sobe o SUT no perfil PROTEGIDO (defesas ativas)
	cp .env.protegido .env && $(COMPOSE) up -d --build
	@echo ">> perfil PROTEGIDO no ar."

down: ## Derruba tudo
	$(COMPOSE) --profile tools down -v

logs: ## Logs agregados
	$(COMPOSE) logs -f --tail=100

# --------- varreduras (PROFILE=vulneravel|protegido) -----------------
PROFILE?=vulneravel

scan-zap: ## Varredura DAST OWASP ZAP
	$(COMPOSE) --profile tools run --rm zap sh -c "cd /zap/wrk && ./run_zap.sh $(PROFILE)"

# token de alice: perfil protegido exige o Keycloak (gateway e target so aceitam esse emissor);
# perfil vulneravel usa o login local (o gateway nao valida JWT)
ifeq ($(PROFILE),protegido)
AUTH_ARGS=--env-var auth_url=http://keycloak:8080/realms/apisec/protocol/openid-connect/token \
  --env-var 'auth_body=grant_type=password&client_id=apisec-client&username=alice&password=alice123' \
  --env-var auth_ctype=application/x-www-form-urlencoded
else
AUTH_ARGS=--env-var auth_url=http://gateway:8080/api/auth/login \
  --env-var 'auth_body={"username":"alice","password":"alice123"}' \
  --env-var auth_ctype=application/json
endif

scan-postman: ## Testes de logica/autorizacao via Newman
	$(COMPOSE) --profile tools run --rm newman \
	  run /etc/newman/apisec-collection.postman_collection.json \
	  --env-var base_url=http://gateway:8080 $(AUTH_ARGS) \
	  --reporters cli,json --reporter-json-export /results/newman-$(PROFILE).json -n 12 || true
	@echo ">> extraia results/postman-findings-$(PROFILE).json do log Newman (script POSTMAN_FINDINGS_JSON)"

scan-brute: ## Brute force por rajada paralela (VULN-AUTH-01: sem rate limit)
	python3 analysis/brute_force.py --profile $(PROFILE) --attempts 100

# RESTest: imagem construida a partir de commit fixo (scans/restest/Dockerfile).
# Exige a stack do PROFILE no ar. Codigo 1 do RESTest = erros encontrados (esperado), nao falha.
scan-restest: ## Fuzzing por contrato com RESTest (SEED=1 por padrao; 2 min)
	docker build -t apisec-restest:f947873 scans/restest
	@SEED=$${SEED:-1}; PROJ=$$(pwd -W 2>/dev/null || pwd); \
	if [ "$(PROFILE)" = "protegido" ]; then \
	  T=$$(curl -s -X POST http://localhost:8083/realms/apisec/protocol/openid-connect/token -d 'grant_type=password&client_id=apisec-client&username=alice&password=alice123' | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'); \
	else \
	  T=$$(curl -s -X POST http://localhost:8080/api/auth/login -H 'Content-Type: application/json' -d '{"username":"alice","password":"alice123"}' | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p'); \
	fi; \
	mkdir -p results/restest-raw/$(PROFILE)-s$$SEED; \
	docker run --rm --network apisec-testbed_edge --memory 2g --cpus 2 \
	  -e RESTEST_AUTH="header:Authorization=Bearer $$T" \
	  -v "$$PROJ/scans/restest/spec-testbed.yaml:/spec/spec.yaml:ro" \
	  -v "$$PROJ/results/restest-raw/$(PROFILE)-s$$SEED:/out" \
	  apisec-restest:f947873 run /spec/spec.yaml --url http://gateway:8080 --budget 2m \
	  --out /out --seed $$SEED --set engine.maxConcurrency=4 || [ $$? -eq 1 ]; \
	python3 analysis/restest_convert.py --results results

loadtest: ## Mede latencia/overhead sob carga (Etapa C)
	python3 analysis/loadtest.py --base http://localhost:8080 --profile $(PROFILE) --duration 120

analyze: ## Consolida TPR/FPR e a matriz ferramenta x vulnerabilidade
	cd analysis && python3 analyze.py --profile $(PROFILE) --results ../results --gt ground_truth.json

snapshot: ## Exporta series do Prometheus (CPU/RAM/latencia) do intervalo recente
	python3 analysis/prom_snapshot.py --prom http://localhost:9090 --profile $(PROFILE) --minutes 30

clean:
	$(COMPOSE) --profile tools down -v --remove-orphans
