package com.example.productservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

@RestController
@RequestMapping("/api/products")
public class ProductController {

    // Dữ liệu giả/static list — Resource Server không có DB User/Product
    private final List<Map<String, Object>> products = new CopyOnWriteArrayList<>(new ArrayList<>(List.of(
            Map.of("id", 1, "name", "Laptop", "price", 1500),
            Map.of("id", 2, "name", "Phone", "price", 800)
    )));

    // Mọi user đã đăng nhập (có JWT hợp lệ) đều xem được
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<?> getProducts() {
        return ResponseEntity.ok(products);
    }

    // Chỉ ADMIN được xóa (filter map role -> ROLE_ADMIN nên hasRole('ADMIN') khớp)
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> deleteProduct(@PathVariable int id) {
        boolean removed = products.removeIf(p -> ((Integer) p.get("id")) == id);
        if (!removed) {
            return ResponseEntity.status(404).body("Product not found: " + id);
        }
        return ResponseEntity.ok("Deleted product: " + id);
    }
}
