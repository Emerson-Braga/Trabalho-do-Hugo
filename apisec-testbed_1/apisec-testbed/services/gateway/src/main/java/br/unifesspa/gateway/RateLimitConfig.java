package br.unifesspa.gateway;

import org.springframework.cloud.gateway.filter.ratelimit.KeyResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import reactor.core.publisher.Mono;

/**
 * Chave do rate limiter: IP de origem. Usado para medir a eficacia do
 * API Gateway contra brute force / DoS de aplicacao (lacuna apontada por Mendes et al., 2025).
 */
@Configuration
public class RateLimitConfig {

    @Bean
    public KeyResolver ipKeyResolver() {
        return exchange -> Mono.just(
                exchange.getRequest().getRemoteAddress() == null
                        ? "unknown"
                        : exchange.getRequest().getRemoteAddress().getAddress().getHostAddress());
    }
}
