package br.unifesspa.targetapi.controller;

import br.unifesspa.targetapi.config.VulnFlags;
import br.unifesspa.targetapi.security.LocalJwtService;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * API2:2023 - Broken Authentication.
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final JdbcTemplate jdbc;
    private final LocalJwtService jwt;
    private final VulnFlags flags;

    public AuthController(JdbcTemplate jdbc, LocalJwtService jwt, VulnFlags flags) {
        this.jdbc = jdbc;
        this.jwt = jwt;
        this.flags = flags;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> body) {
        String username = body.getOrDefault("username", "");
        String password = body.getOrDefault("password", "");

        if (flags.isBrokenAuth()) {
            // FALHA INJETADA 1: sem rate limit / lockout -> brute force livre
            // FALHA INJETADA 2: comparacao de senha em texto plano via SQL concatenado
            String sql = "SELECT role FROM users WHERE username = '" + username
                       + "' AND password = '" + password + "'";
            List<String> roles = jdbc.queryForList(sql, String.class);
            if (roles.isEmpty()) {
                // FALHA INJETADA 3: user enumeration (mensagem distingue usuario de senha)
                Integer exists = jdbc.queryForObject(
                        "SELECT COUNT(*) FROM users WHERE username = ?", Integer.class, username);
                String msg = (exists != null && exists > 0) ? "senha incorreta" : "usuario inexistente";
                return ResponseEntity.status(401).body(Map.of("error", msg));
            }
            // FALHA INJETADA 4: TTL de 10 anos + segredo fraco
            return ResponseEntity.ok(Map.of(
                    "access_token", jwt.issue(username, List.of(roles.get(0)), 315_360_000L),
                    "token_type", "Bearer"));
        }

        List<Map<String, Object>> rows = jdbc.queryForList(
                "SELECT role, password FROM users WHERE username = ?", username);
        if (rows.isEmpty() || !constantTimeEquals(String.valueOf(rows.get(0).get("password")), password)) {
            return ResponseEntity.status(401).body(Map.of("error", "credenciais invalidas"));
        }
        return ResponseEntity.ok(Map.of(
                "access_token", jwt.issue(username, List.of(String.valueOf(rows.get(0).get("role"))), 900L),
                "token_type", "Bearer", "expires_in", 900));
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        int diff = a.length() ^ b.length();
        for (int i = 0; i < a.length() && i < b.length(); i++) diff |= a.charAt(i) ^ b.charAt(i);
        return diff == 0;
    }
}
