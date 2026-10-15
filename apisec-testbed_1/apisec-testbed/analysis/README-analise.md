# Como o TPR/FPR e calculado

- **TP**: alerta cuja rota (normalizada, com {id}) e classe casam com uma entrada de
  ground_truth.json marcada como detectavel por aquela ferramenta.
- **FP**: alerta que nao casa com nenhuma entrada -> ruido.
- **FN**: vulnerabilidade injetada (esperada para a ferramenta) que nenhum alerta cobriu.
- TPR=TP/(TP+FN)  Precisao=TP/(TP+FP)  FPR_bruto=FP/(FP+TP)  F1=2PR/(P+R)

No perfil PROTEGIDO o gabarito esperado e vazio: qualquer TP e regressao de seguranca.
