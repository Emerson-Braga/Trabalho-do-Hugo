package br.unifesspa.targetapi.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Validacao dos tokens emitidos pelo Keycloak no perfil PROTEGIDO.
 *
 * O gateway ja valida o JWT; o target valida de novo (defesa em profundidade) para que
 * a identidade usada na autorizacao seja a mesma do Keycloak. O principal e o
 * preferred_username (o dono do pedido na tabela orders) e os papeis do realm viram ROLE_*.
 */
@Configuration
public class KeycloakJwtConfig {

    @Bean
    public JwtDecoder keycloakJwtDecoder(
            @Value("${security.keycloak.jwks-uri}") String jwksUri,
            @Value("${security.keycloak.issuer}") String issuer) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwksUri).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        return decoder;
    }

    @Bean
    public JwtAuthenticationConverter keycloakAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setPrincipalClaimName("preferred_username");
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            List<String> roles = realmAccess == null
                    ? List.of()
                    : (List<String>) realmAccess.getOrDefault("roles", List.of());
            return roles.stream()
                    .map(r -> (GrantedAuthority) new SimpleGrantedAuthority("ROLE_" + r.toUpperCase()))
                    .collect(Collectors.toList());
        });
        return converter;
    }
}
