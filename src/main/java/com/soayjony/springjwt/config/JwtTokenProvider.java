package com.soayjony.springjwt.config;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

public class JwtTokenProvider {

    private static final String ROLES = "roles";

    private static final SecretKey key = Jwts.SIG.HS256.key().build();

    private JwtTokenProvider() {
    }

    public static String createToken(String subject, List<String> roles) {

        Instant now = Instant.now();
        Date issuedAt = Date.from(now);
        Date expiredAt = Date.from(now.plusSeconds(3600)); // 1 hour expiration, you can make it configurable through
                                                           // JwtProps

        return Jwts.builder()
                .subject(subject)
                .claim(ROLES, roles)
                .issuedAt(issuedAt)
                .expiration(expiredAt)
                .signWith(key)
                .compact();
    }

    public static Optional<Claims> getClaimsFromToken(String token) {
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

    public static List<String> getRolesFromToken(Claims claims) {
        if (claims == null) {
            return List.of();
        }
        List<?> roles = claims.get(ROLES, List.class);
        if (roles == null) {
            return List.of();
        }
        return roles.stream().map(Object::toString).toList();
    }

    public static boolean isValid(Claims claims) {
        Instant now = Instant.now();
        return claims != null
                && claims.getExpiration() != null
                && claims.getExpiration().after(Date.from(now));
    }
}
