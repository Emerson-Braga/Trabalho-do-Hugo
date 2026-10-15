package br.unifesspa.gateway;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * Camada de defesa sob avaliacao no gateway.
 *
 * GATEWAY_ENFORCE=true  -> valida assinatura/exp/iss do JWT emitido pelo Keycloak (OAuth2)
 * GATEWAY_ENFORCE=false -> gateway atua apenas como roteador (condicao de controle)
 */
@Configuration
@EnableWebFluxSecurity
public class GatewaySecurityConfig {

    @Value("${gateway.enforce-jwt:true}")
    private boolean enforce;

    @Bean
    public SecurityWebFilterChain chain(ServerHttpSecurity http) {
        http.csrf(ServerHttpSecurity.CsrfSpec::disable)
            .cors(c -> c.configurationSource(corsSource()));

        if (!enforce) {
            return http.authorizeExchange(e -> e.anyExchange().permitAll()).build();
        }
        return http
            .authorizeExchange(e -> e
                .pathMatchers("/api/auth/**", "/actuator/health",
                              "/v3/api-docs/**", "/swagger-ui/**").permitAll()
                .anyExchange().authenticated())
            .oauth2ResourceServer(o -> o.jwt(jwt -> {}))
            .build();
    }

    private UrlBasedCorsConfigurationSource corsSource() {
        CorsConfiguration c = new CorsConfiguration();
        c.setAllowedOrigins(List.of("http://localhost:3000"));
        c.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE"));
        c.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
        src.registerCorsConfiguration("/**", c);
        return src;
    }
}
