package com.example.api_gateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtTokenProvider {

    @Value("${JWT_SECRET}")
    private String jwtSecret; // Store securely in properties
    private final long jwtExpirationMs = 3600000; // 1 hour validity
    private final long refreshTokenExpirationMs = 604800000; // 7 days validity for refresh token

    public String getEmailFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
        return claims.getSubject();
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith(getKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return !claims.getExpiration().before(new Date()); // Check if the token is expired
        } catch (JwtException | IllegalArgumentException e) {
            throw new RuntimeException("Invalid JWT token");
        }
    }

    public List<GrantedAuthority> getAuthoritiesFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(getKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();

        // Assuming roles are stored in the "role" claim
        String roles = claims.get("role", String.class);
        return Stream.of(roles.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    private SecretKey getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
