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

scan-postman: ## Testes de logica/autorizacao via Newman
	$(COMPOSE) --profile tools run --rm newman \
	  run /etc/newman/apisec-collection.postman_collection.json \
	  --env-var base_url=http://gateway:8080 \
	  --reporters cli,json --reporter-json-export /results/newman-$(PROFILE).json -n 12 || true
	@echo ">> extraia results/postman-findings.json do log Newman (script POSTMAN_FINDINGS_JSON)"

scan-restest: ## Fuzzing orientado a contrato via RESTest
	@echo "Rodar RESTest a partir do jar/imagem isa-group; saida em results/restest-$(PROFILE).csv"

loadtest: ## Mede latencia/overhead sob carga (Etapa C)
	python3 analysis/loadtest.py --base http://localhost:8080 --profile $(PROFILE) --duration 120

analyze: ## Consolida TPR/FPR e a matriz ferramenta x vulnerabilidade
	cd analysis && python3 analyze.py --profile $(PROFILE) --results ../results --gt ground_truth.json

snapshot: ## Exporta series do Prometheus (CPU/RAM/latencia) do intervalo recente
	python3 analysis/prom_snapshot.py --prom http://localhost:9090 --profile $(PROFILE) --minutes 30

clean:
	$(COMPOSE) --profile tools down -v --remove-orphans
