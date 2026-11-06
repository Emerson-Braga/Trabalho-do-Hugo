# Defeitos conhecidos do SUT

Defeitos de robustez do microsserviço alvo que **não fazem parte do gabarito** (`analysis/ground_truth.json`).
Decisão: documentados e não corrigidos, para que todas as medições sejam feitas sobre o mesmo código.
Os dois perfis compartilham esses defeitos, então a comparação entre eles continua válida.

## 1. `GET /api/products/{id}` responde 500 a id não numérico

- **Causa:** o controller converte o `{id}` para número sem validar. Um valor como `SZkUNFaQm4GZIwMeu`
  gera `NumberFormatException`, que não é tratada e vira resposta 500.
- **Onde aparece:** perfil vulnerável e protegido (no protegido, 1119 respostas 500 em 3 rodadas de 2 min).
- **Impacto nas métricas:**
  - O RESTest reporta esses 500 como falso positivo (`NAO-ATRIBUIDO`).
  - VULN-SQLI-02 (injeção no `{id}`) não pode ser atribuída com segurança, porque o 500 aparece nos dois perfis.
    Por isso o RESTest não atribui SQLI-02 (ver `analysis/restest_convert.py`).
  - O ZAP também gera alertas "Server Error" (100000) nessa rota.
- **Correção possível (não aplicada):** validar o id e responder 400 ou 404. Exige refazer todas as medições.

## 2. Tolerância de entrada: login e pedido aceitam dados fora do contrato

- **`POST /api/auth/login`:** aceita o corpo JSON seguido de texto extra (ex.: `bla`). O Jackson ignora
  tokens finais por padrão.
- **`GET /api/orders/{id}`:** aceita id com espaço no começo (` 1`) e o converte para 1.
- **Classificação:** são falhas de validação de entrada, não de segurança. Não há ganho de acesso.
- **Impacto nas métricas:** o RESTest reporta como F206 ("dados inválidos aceitos"). Como não correspondem
  ao gabarito, contam como falso positivo do RESTest (3 por perfil, nas três sementes).

## Como descrever no artigo

Os dois defeitos são limitações do alvo, não das ferramentas. Eles inflam os falsos positivos do RESTest
e impedem a atribuição de SQLI-02 pelo oráculo de 500. As conclusões sobre BOLA, enumeração, CORS,
rate limit e stack trace não dependem deles.
