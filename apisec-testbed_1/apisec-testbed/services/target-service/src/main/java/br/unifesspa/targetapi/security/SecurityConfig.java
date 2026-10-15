package br.unifesspa.targetapi.security;

import br.unifesspa.targetapi.config.VulnFlags;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {

    private static final String[] PUBLIC = {
            "/api/auth/**", "/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/actuator/health"
    };

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, VulnFlags flags, TokenAuthFilter tokenFilter)
            throws Exception {

        http.csrf(csrf -> csrf.disable())   // API stateless: CSRF nao se aplica a Bearer token
            .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .addFilterBefore(tokenFilter, UsernamePasswordAuthenticationFilter.class);

        if (flags.isMisconfiguration()) {
            // FALHA INJETADA (API8:2023): CORS totalmente permissivo com credenciais
            http.cors(cors -> cors.configurationSource(req -> {
                CorsConfiguration c = new CorsConfiguration();
                c.setAllowedOriginPatterns(List.of("*"));
                c.setAllowedMethods(List.of("*"));
                c.setAllowedHeaders(List.of("*"));
                c.setAllowCredentials(true);
                return c;
            }));
            // FALHA INJETADA: actuator e endpoints de debug liberados sem autenticacao
            http.authorizeHttpRequests(a -> a
                    .requestMatchers("/actuator/**", "/api/debug/**").permitAll()
                    .requestMatchers(PUBLIC).permitAll()
                    .requestMatchers("/api/products/**").permitAll()
                    .anyRequest().authenticated());
        } else {
            UrlBasedCorsConfigurationSource src = new UrlBasedCorsConfigurationSource();
            CorsConfiguration c = new CorsConfiguration();
            c.setAllowedOrigins(List.of("http://localhost:3000"));
            c.setAllowedMethods(List.of("GET", "POST"));
            c.setAllowedHeaders(List.of("Authorization", "Content-Type"));
            c.setAllowCredentials(false);
            src.registerCorsConfiguration("/**", c);
            http.cors(cors -> cors.configurationSource(src));
            http.authorizeHttpRequests(a -> a
                    .requestMatchers(PUBLIC).permitAll()
                    .requestMatchers("/actuator/**").hasRole("ADMIN")
                    .requestMatchers("/api/debug/**").denyAll()
                    .anyRequest().authenticated());
        }
        return http.build();
    }
}
