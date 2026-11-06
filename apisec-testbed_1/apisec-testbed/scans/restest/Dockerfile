# RESTest (isa-group) compilado a partir de um commit fixo, para reprodutibilidade.
# Build isolado: nao faz parte do docker-compose e nao altera os outros servicos.
FROM eclipse-temurin:21-jdk

RUN apt-get update \
 && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/*

ARG RESTEST_REF=f947873671a9ef8514a88bc43a49022d56d2d07c
WORKDIR /opt
RUN git clone https://github.com/isa-group/RESTest.git \
 && cd RESTest \
 && git checkout "$RESTEST_REF" \
 && chmod +x mvnw restest \
 && ./mvnw -q install -DskipTests

WORKDIR /opt/RESTest
ENTRYPOINT ["./restest"]
