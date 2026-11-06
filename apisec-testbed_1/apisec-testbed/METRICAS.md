# Definição das métricas

## Acurácia (analysis/analyze.py)

- **Unidade de contagem**: cada ferramenta conta o que ela própria reporta.
  - ZAP: **instância de alerta** (um alerta com 153 URIs conta 153). Contado por tipo de alerta, o FP cai de 165 para 3.
  - Postman e brute force: **achado** (uma falha por ID).
  - RESTest: **par operação × código de falha** (uma linha por operação e tipo de erro, com o número de ocorrências no relatório).
- **TP**: falha do gabarito detectada pela ferramenta, casando por rota e por ID. Um alerta casa com no máximo uma entrada.
- **FN**: falha do gabarito que a ferramenta deveria detectar (lista `detectable_by`) e não detectou.
- **FP**: alerta ou achado que não casa com nenhuma entrada do gabarito. Inclui os defeitos documentados em `DEFEITOS-CONHECIDOS.md`.
- **Precisão** = TP / (TP + FP).
- **TPR (recall)** = TP / (TP + FN).
- **FDR** = FP / (FP + TP) = 1 − precisão. **Não é a FPR clássica**, porque a FPR exige verdadeiros negativos, e o testbed não define o conjunto de casos negativos.
- **F1** = média harmônica entre precisão e TPR.
- **Perfil protegido**: não há falhas esperadas. Alerta que casa com uma falha injetada é contado como **regressão**; os demais, como FP.

## Recursos (analysis/recursos.py)

- **CPU (%)**: campo `CPUPerc` do `docker stats`. 100% = um core inteiro.
- **RAM (MB)**: memória residente do container (`MemUsage`), em MiB. Não é a heap da JVM.
- Amostragem a cada 5 s durante o cenário. Os valores reportados são médias das amostras.

## Latência (analysis/loadtest.py)

- **Cliente**: p50, p90, p95 e p99 medidos pelo gerador de carga, em ms.
- **Servidor**: p95 do histograma `http.server.requests` do Prometheus. Resolução limitada pelos buckets.
- Carga em concorrência fixa (20 threads). Como o gerador satura o sistema, a latência do cliente inclui fila no gerador. Por isso a comparação entre cenários é relativa, não absoluta.
