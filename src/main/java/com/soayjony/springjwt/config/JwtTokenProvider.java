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
    private static final String LAST_ACTIVITY = "lastActivity";
    private static final String SESSION_START = "sessionStart";

    private final SecretKey key;
    private final long expirationSeconds;
    private final long maxSessionDurationSeconds;

    public JwtTokenProvider(JwtProperties jwtProperties) {
        this.key = Keys.hmacShaKeyFor(jwtProperties.getSecret().getBytes());
        this.expirationSeconds = jwtProperties.getExpiration();
        this.maxSessionDurationSeconds = jwtProperties.getMaxSessionDuration();
    }

    public String createToken(String subject, List<String> roles) {
        return createToken(subject, roles, System.currentTimeMillis());
    }

    public String createToken(String subject, List<String> roles, long sessionStartTime) {
        Instant now = Instant.now();
        Date issuedAt = Date.from(now);
        Date expiredAt = Date.from(now.plusSeconds(expirationSeconds));
        Date sessionExpiry = new Date(sessionStartTime + (maxSessionDurationSeconds * 1000));

        return Jwts.builder()
                .subject(subject)
                .claim(ROLES, roles)
                .claim(LAST_ACTIVITY, now.getEpochSecond())
                .claim(SESSION_START, sessionStartTime / 1000) // Store as seconds
                .issuedAt(issuedAt)
                .expiration(expiredAt)
                .signWith(key)
                .compact();
    }

    /**
     * Refresh token by updating the expiration time and last activity timestamp.
     * This extends the access token if the user is active.
     */
    public String refreshToken(Claims claims) {
        String subject = claims.getSubject();
        List<String> roles = getRolesFromToken(claims);
        long sessionStart = getSessionStartTime(claims);

        Instant now = Instant.now();
        Date expiredAt = Date.from(now.plusSeconds(expirationSeconds));
        Date sessionExpiry = new Date(sessionStart * 1000 + (maxSessionDurationSeconds * 1000));

        return Jwts.builder()
                .subject(subject)
                .claim(ROLES, roles)
                .claim(LAST_ACTIVITY, now.getEpochSecond())
                .claim(SESSION_START, sessionStart)
                .issuedAt(new Date())
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
                && claims.getExpiration().after(Date.from(now))
                && !isSessionExpired(claims);
    }

    /**
     * Check if the maximum session duration has been exceeded
     */
    public boolean isSessionExpired(Claims claims) {
        if (claims == null) {
            return true;
        }
        long sessionStartSeconds = getSessionStartTime(claims);
        long now = System.currentTimeMillis() / 1000;
        long sessionDuration = now - sessionStartSeconds;

        return sessionDuration > maxSessionDurationSeconds;
    }

    /**
     * Check if token needs refresh based on inactivity.
     * Returns true if the token is still valid but should be refreshed soon.
     */
    public boolean shouldRefreshToken(Claims claims, long inactivityTimeoutSeconds) {
        if (claims == null) {
            return false;
        }

        long lastActivity = getLastActivityTime(claims);
        long now = System.currentTimeMillis() / 1000;
        long inactivityDuration = now - lastActivity;

        // Refresh if user has been active within the inactivity timeout window
        return inactivityDuration < inactivityTimeoutSeconds && isValid(claims);
    }

    /**
     * Get the last activity timestamp from the token
     */
    public long getLastActivityTime(Claims claims) {
        if (claims == null) {
            return 0;
        }
        Object lastActivity = claims.get(LAST_ACTIVITY);
        if (lastActivity instanceof Number) {
            return ((Number) lastActivity).longValue();
        }
        return 0;
    }

    /**
     * Get the session start time from the token
     */
    public long getSessionStartTime(Claims claims) {
        if (claims == null) {
            return 0;
        }
        Object sessionStart = claims.get(SESSION_START);
        if (sessionStart instanceof Number) {
            return ((Number) sessionStart).longValue();
        }
        return 0;
    }
}
