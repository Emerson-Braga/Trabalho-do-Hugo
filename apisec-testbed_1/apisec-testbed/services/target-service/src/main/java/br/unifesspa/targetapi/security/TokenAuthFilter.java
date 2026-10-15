package br.unifesspa.targetapi.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class TokenAuthFilter extends OncePerRequestFilter {

    private final LocalJwtService jwt;

    public TokenAuthFilter(LocalJwtService jwt) {
        this.jwt = jwt;
    }

    @Override
    @SuppressWarnings("unchecked")
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        String header = req.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            Claims c = jwt.validate(header.substring(7));
            if (c != null) {
                List<String> roles = (List<String>) c.getOrDefault("roles", List.of("ROLE_USER"));
                var authorities = roles.stream()
                        .map(r -> new SimpleGrantedAuthority(r.startsWith("ROLE_") ? r : "ROLE_" + r))
                        .collect(Collectors.toList());
                var auth = new UsernamePasswordAuthenticationToken(c.getSubject(), null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
        chain.doFilter(req, res);
    }
}
