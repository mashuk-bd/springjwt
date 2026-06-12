package com.soayjony.springjwt.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    private String secret;
    // Short-lived access token expiration (default 15 minutes)
    private long expiration = 900;
    // Inactivity timeout - refresh token if used within this window (default 10
    // minutes)
    private long inactivityTimeout = 600;
    // Maximum session duration regardless of activity (default 24 hours)
    private long maxSessionDuration = 86400;

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    public long getExpiration() {
        return expiration;
    }

    public void setExpiration(long expiration) {
        this.expiration = expiration;
    }

    public long getInactivityTimeout() {
        return inactivityTimeout;
    }

    public void setInactivityTimeout(long inactivityTimeout) {
        this.inactivityTimeout = inactivityTimeout;
    }

    public long getMaxSessionDuration() {
        return maxSessionDuration;
    }

    public void setMaxSessionDuration(long maxSessionDuration) {
        this.maxSessionDuration = maxSessionDuration;
    }
}
