package br.unifesspa.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;

/**
 * Liberacao de /actuator apenas na porta de gerenciamento (interna, nao publicada no host).
 *
 * A regra casa pela porta local da requisicao, nao so pelo caminho: a mesma URL pedida pelo
 * edge (porta 8080) continua exigindo autenticacao. Assim o Prometheus raspa as metricas sem
 * token e o edge nao expoe o actuator.
 */
@Configuration
public class ManagementSecurityConfig {

    @Value("${management.server.port:8080}")
    private int managementPort;

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityWebFilterChain managementChain(ServerHttpSecurity http) {
        ServerWebExchangeMatcher interno = exchange -> {
            var req = exchange.getRequest();
            boolean portaInterna = req.getLocalAddress() != null
                    && req.getLocalAddress().getPort() == managementPort;
            boolean actuator = req.getPath().value().startsWith("/actuator");
            return portaInterna && actuator
                    ? ServerWebExchangeMatcher.MatchResult.match()
                    : ServerWebExchangeMatcher.MatchResult.notMatch();
        };
        return http
                .securityMatcher(interno)
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(e -> e.anyExchange().permitAll())
                .build();
    }
}
