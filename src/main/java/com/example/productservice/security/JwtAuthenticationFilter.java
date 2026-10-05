package com.example.productservice.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Resource Server filter: tin tưởng chữ ký JWT do Identity-Service ký
 * (dùng chung Secret Key). Không truy vấn DB User.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${app.jwt.secret}")
    private String secret;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // 1. Lấy chuỗi JWT từ Header "Authorization: Bearer <token>"
        String header = request.getHeader("Authorization");
        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            String token = header.substring(7);
            try {
                // 2. Verify chữ ký (JJWT 0.11.5) bằng chung Secret Key
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(getSigningKey())
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                // 3. Trích xuất username (sub) và role từ Claims.
                // Identity-Service hiện ký claim "role" (số ít); đề bài ghi "roles".
                // Hỗ trợ cả hai, cả dạng String lẫn Collection.
                String username = claims.getSubject();
                List<String> roles = extractRoles(claims);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    // 4. Map Roles thành SimpleGrantedAuthority (chuẩn ROLE_xxx để hasRole() hoạt động)
                    List<SimpleGrantedAuthority> authorities = roles.stream()
                            .map(this::normalizeRole)
                            .map(SimpleGrantedAuthority::new)
                            .toList();

                    // 5. Nạp Authentication vào SecurityContextHolder
                    UsernamePasswordAuthenticationToken authentication =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            } catch (Exception ex) {
                // Token sai/hết hạn/chữ ký không hợp lệ -> không set Authentication,
                // để Security chain trả 401/403. Không throw để filter chain tiếp tục.
                SecurityContextHolder.clearContext();
            }
        }

        filterChain.doFilter(request, response);
    }

    @SuppressWarnings("unchecked")
    private List<String> extractRoles(Claims claims) {
        Object rolesObj = claims.get("roles");
        if (rolesObj == null) {
            rolesObj = claims.get("role");
        }
        List<String> roles = new ArrayList<>();
        if (rolesObj instanceof String s) {
            roles.add(s);
        } else if (rolesObj instanceof Collection<?> c) {
            for (Object o : c) {
                if (o != null) {
                    roles.add(o.toString());
                }
            }
        }
        return roles;
    }

    private String normalizeRole(String role) {
        if (role.startsWith("ROLE_")) {
            return role;
        }
        return "ROLE_" + role;
    }
}
