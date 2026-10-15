package br.unifesspa.targetapi.controller;

import br.unifesspa.targetapi.config.VulnFlags;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * API1:2023 - Broken Object Level Authorization (BOLA)
 * API3:2023 - Broken Object Property Level Authorization (excessive data exposure / mass assignment)
 */
@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final JdbcTemplate jdbc;
    private final VulnFlags flags;

    public OrderController(JdbcTemplate jdbc, VulnFlags flags) {
        this.jdbc = jdbc;
        this.flags = flags;
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> byId(@PathVariable("id") long id, Authentication auth) {
        List<Map<String, Object>> rows =
                jdbc.queryForList("SELECT id, owner, item, total, card_last4 FROM orders WHERE id = ?", id);
        if (rows.isEmpty()) return ResponseEntity.notFound().build();
        Map<String, Object> order = rows.get(0);

        if (flags.isBola()) {
            // FALHA INJETADA: nenhuma verificacao de propriedade do objeto.
            // Qualquer token valido le o pedido de qualquer usuario (IDOR/BOLA),
            // e o numero do cartao e devolvido junto (excessive data exposure).
            return ResponseEntity.ok(order);
        }
        String subject = auth != null ? auth.getName() : null;
        boolean admin = auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals("ROLE_ADMIN"));
        if (!admin && !String.valueOf(order.get("owner")).equals(subject)) {
            return ResponseEntity.status(404).body(Map.of("error", "nao encontrado"));
        }
        return ResponseEntity.ok(Map.of(
                "id", order.get("id"), "owner", order.get("owner"),
                "item", order.get("item"), "total", order.get("total")));
    }

    @GetMapping
    public List<Map<String, Object>> mine(Authentication auth) {
        if (flags.isBola()) {
            // FALHA INJETADA: lista global em endpoint que deveria ser escopado ao dono
            return jdbc.queryForList("SELECT id, owner, item, total, card_last4 FROM orders");
        }
        return jdbc.queryForList("SELECT id, owner, item, total FROM orders WHERE owner = ?",
                auth != null ? auth.getName() : "");
    }
}
