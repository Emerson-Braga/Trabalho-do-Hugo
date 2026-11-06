package br.unifesspa.targetapi.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Liberacao de /actuator apenas na porta de gerenciamento (interna, nao publicada no host).
 *
 * A regra casa pela porta local da requisicao: o mesmo caminho pedido pela porta de servico
 * (8081, alcancada so via gateway) continua protegido pela cadeia normal. O Prometheus raspa
 * as metricas na rede telemetry sem token.
 */
@Configuration
public class ManagementSecurityConfig {

    @Value("${management.server.port:8081}")
    private int managementPort;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain managementChain(HttpSecurity http) throws Exception {
        return http
                .securityMatcher(req -> req.getLocalPort() == managementPort
                        && req.getRequestURI().startsWith("/actuator"))
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(a -> a.anyRequest().permitAll())
                .build();
    }
}
