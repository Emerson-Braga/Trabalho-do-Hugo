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

scan-restest: ## Fuzzing orientado a contrato via RESTest
	@echo "ERRO: scan-restest ainda nao implementado. Rodar RESTest (isa-group) e gravar results/restest-$(PROFILE).csv"
	@exit 1

loadtest: ## Mede latencia/overhead sob carga (Etapa C)
	python3 analysis/loadtest.py --base http://localhost:8080 --profile $(PROFILE) --duration 120

analyze: ## Consolida TPR/FPR e a matriz ferramenta x vulnerabilidade
	cd analysis && python3 analyze.py --profile $(PROFILE) --results ../results --gt ground_truth.json

snapshot: ## Exporta series do Prometheus (CPU/RAM/latencia) do intervalo recente
	python3 analysis/prom_snapshot.py --prom http://localhost:9090 --profile $(PROFILE) --minutes 30

clean:
	$(COMPOSE) --profile tools down -v --remove-orphans
