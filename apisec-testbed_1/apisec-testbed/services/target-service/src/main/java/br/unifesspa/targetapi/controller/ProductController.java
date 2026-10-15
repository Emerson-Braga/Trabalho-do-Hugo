package br.unifesspa.targetapi.controller;

import br.unifesspa.targetapi.config.VulnFlags;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * API8:2023 / CWE-89 - SQL Injection em parametro de busca.
 */
@RestController
@RequestMapping("/api/products")
public class ProductController {

    private final JdbcTemplate jdbc;
    private final VulnFlags flags;

    public ProductController(JdbcTemplate jdbc, VulnFlags flags) {
        this.jdbc = jdbc;
        this.flags = flags;
    }

    @GetMapping
    public List<Map<String, Object>> all() {
        return jdbc.queryForList("SELECT id, name, price, category FROM products");
    }

    @GetMapping("/search")
    public List<Map<String, Object>> search(@RequestParam(name = "q", defaultValue = "") String q,
                                            @RequestParam(name = "order", defaultValue = "id") String order) {
        if (flags.isSqlInjection()) {
            // FALHA INJETADA: concatenacao direta -> injecao classica, UNION e boolean-based
            String sql = "SELECT id, name, price, category FROM products WHERE name LIKE '%" + q
                       + "%' ORDER BY " + order;
            return jdbc.queryForList(sql);
        }
        String safeOrder = List.of("id", "name", "price").contains(order) ? order : "id";
        return jdbc.queryForList(
                "SELECT id, name, price, category FROM products WHERE name LIKE ? ORDER BY " + safeOrder,
                "%" + q + "%");
    }

    @GetMapping("/{id}")
    public Map<String, Object> byId(@PathVariable("id") String id) {
        if (flags.isSqlInjection()) {
            return jdbc.queryForList("SELECT id, name, price, category FROM products WHERE id = " + id)
                    .stream().findFirst().orElse(Map.of());
        }
        return jdbc.queryForList("SELECT id, name, price, category FROM products WHERE id = ?",
                Integer.parseInt(id)).stream().findFirst().orElse(Map.of());
    }
}
