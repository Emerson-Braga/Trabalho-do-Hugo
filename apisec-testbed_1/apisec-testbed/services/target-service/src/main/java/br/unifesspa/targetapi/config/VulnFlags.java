package br.unifesspa.targetapi.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Chaves de ativacao das vulnerabilidades injetadas (variavel independente do experimento).
 *
 * Perfil VULNERAVEL  -> todas true  (baseline sem estrategia de defesa)
 * Perfil PROTEGIDO   -> todas false (Spring Security + RBAC + parametrizacao ativos)
 *
 * O mesmo binario roda nos dois perfis: isso isola a estrategia de defesa como
 * unica variavel entre as duas condicoes experimentais.
 */
@ConfigurationProperties(prefix = "vuln")
public class VulnFlags {

    /** API1:2023 - Broken Object Level Authorization (BOLA). */
    private boolean bola = true;
    /** API3/API8 - SQL Injection via concatenacao de string. */
    private boolean sqlInjection = true;
    /** API2:2023 - Broken Authentication (segredo fraco, exp ignorada, login permissivo). */
    private boolean brokenAuth = true;
    /** API8:2023 - Security Misconfiguration (actuator aberto, CORS *, stacktrace, leak de segredo). */
    private boolean misconfiguration = true;

    public boolean isBola() { return bola; }
    public void setBola(boolean bola) { this.bola = bola; }

    public boolean isSqlInjection() { return sqlInjection; }
    public void setSqlInjection(boolean sqlInjection) { this.sqlInjection = sqlInjection; }

    public boolean isBrokenAuth() { return brokenAuth; }
    public void setBrokenAuth(boolean brokenAuth) { this.brokenAuth = brokenAuth; }

    public boolean isMisconfiguration() { return misconfiguration; }
    public void setMisconfiguration(boolean misconfiguration) { this.misconfiguration = misconfiguration; }

    public String profileName() {
        boolean anyVuln = bola || sqlInjection || brokenAuth || misconfiguration;
        return anyVuln ? "VULNERAVEL" : "PROTEGIDO";
    }
}
