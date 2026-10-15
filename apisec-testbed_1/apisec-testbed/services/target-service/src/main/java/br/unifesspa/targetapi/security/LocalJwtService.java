package br.unifesspa.targetapi.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Service;
import br.unifesspa.targetapi.config.VulnFlags;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

/**
 * Emissao/validacao de token de servico.
 *
 * VULNERAVEL (vuln.broken-auth=true):
 *   - segredo fraco e curto ("secret"), sujeito a brute force offline;
 *   - expiracao NAO verificada na validacao (token nunca morre);
 *   - claim de papel aceita do proprio token sem checagem de emissor.
 * PROTEGIDO:
 *   - segredo forte de 256 bits vindo de variavel de ambiente;
 *   - expiracao verificada; emissor e audiencia checados.
 */
@Service
public class LocalJwtService {

    public static final String WEAK_SECRET = "secret";
    private static final String ISSUER = "target-service";

    private final VulnFlags flags;
    private final String strongSecret;

    public LocalJwtService(VulnFlags flags,
                           @org.springframework.beans.factory.annotation.Value("${security.jwt.secret:}") String strongSecret) {
        this.flags = flags;
        this.strongSecret = (strongSecret == null || strongSecret.isBlank())
                ? "uma-chave-hmac-de-256-bits-gerada-para-o-testbed-unifesspa-2026"
                : strongSecret;
    }

    private SecretKey key() {
        String raw = flags.isBrokenAuth() ? WEAK_SECRET : strongSecret;
        byte[] bytes = raw.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {                       // jjwt exige >=256 bits para HS256
            byte[] padded = new byte[32];
            for (int i = 0; i < 32; i++) padded[i] = bytes[i % bytes.length];
            bytes = padded;
        }
        return Keys.hmacShaKeyFor(bytes);
    }

    public String issue(String subject, List<String> roles, long ttlSeconds) {
        Date now = new Date();
        return Jwts.builder()
                .setSubject(subject)
                .setIssuer(ISSUER)
                .claim("roles", roles)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + ttlSeconds * 1000L))
                .signWith(key(), SignatureAlgorithm.HS256)
                .compact();
    }

    /** @return claims validas, ou null se o token for invalido. */
    public Claims validate(String token) {
        try {
            var parser = Jwts.parserBuilder().setSigningKey(key());
            if (flags.isBrokenAuth()) {
                // FALHA INJETADA: tolerancia de relogio absurda anula a verificacao de expiracao
                parser.setAllowedClockSkewSeconds(Long.MAX_VALUE / 1000);
            } else {
                parser.requireIssuer(ISSUER).setAllowedClockSkewSeconds(30);
            }
            return parser.build().parseClaimsJws(token).getBody();
        } catch (Exception e) {
            return null;
        }
    }
}
