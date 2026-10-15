package br.unifesspa.targetapi.controller;

import br.unifesspa.targetapi.config.VulnFlags;
import br.unifesspa.targetapi.security.LocalJwtService;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * API8:2023 - Security Misconfiguration: endpoint de diagnostico esquecido em producao.
 */
@RestController
@RequestMapping("/api/debug")
public class DebugController {

    private final VulnFlags flags;

    public DebugController(VulnFlags flags) {
        this.flags = flags;
    }

    @GetMapping("/config")
    public Map<String, Object> config() {
        Map<String, Object> out = new HashMap<>();
        out.put("profile", flags.profileName());
        if (flags.isMisconfiguration()) {
            // FALHA INJETADA: vazamento de segredo e de variaveis de ambiente
            out.put("jwt_secret", LocalJwtService.WEAK_SECRET);
            out.put("db_url", "jdbc:h2:mem:targetdb");
            out.put("env", System.getenv());
        }
        return out;
    }

    @GetMapping("/error")
    public String boom() {
        // FALHA INJETADA: stack trace completo devolvido ao cliente (server.error.include-stacktrace=always)
        throw new IllegalStateException("falha interna simulada para inspecao de stack trace");
    }
}
