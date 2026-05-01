package com.soayjony.springjwt.config;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import javax.crypto.SecretKey;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {

    private static final String ROLES = "roles";

    private final SecretKey key;
    private final long expirationSeconds;

    public JwtTokenProvider(JwtProperties jwtProperties) {
        this.key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
        this.expirationSeconds = jwtProperties.getExpiration();
    }

    public String createToken(String subject, List<String> roles) {
        Instant now = Instant.now();
        Date issuedAt = Date.from(now);
        Date expiredAt = Date.from(now.plusSeconds(expirationSeconds));

        return Jwts.builder()
                .subject(subject)
                .claim(ROLES, roles)
                .issuedAt(issuedAt)
                .expiration(expiredAt)
                .signWith(key)
                .compact();
    }

    public Optional<Claims> getClaimsFromToken(String token) {
        try {
            return Optional.of(Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload());
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public List<String> getRolesFromToken(Claims claims) {
        if (claims == null) {
            return List.of();
        }
        List<?> roles = claims.get(ROLES, List.class);
        if (roles == null) {
            return List.of();
        }
        return roles.stream().map(Object::toString).toList();
    }

    public boolean isValid(Claims claims) {
        Instant now = Instant.now();
        return claims != null
                && claims.getExpiration() != null
                && claims.getExpiration().after(Date.from(now));
    }
}
