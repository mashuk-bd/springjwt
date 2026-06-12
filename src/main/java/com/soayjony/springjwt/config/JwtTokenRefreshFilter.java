package com.soayjony.springjwt.config;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Filter to automatically refresh JWT tokens based on user activity.
 * 
 * How it works:
 * 1. On each request, extracts the JWT token from the cookie
 * 2. Checks if the token needs to be refreshed (user is active within inactivity window)
 * 3. If refresh needed, creates a new token and updates the cookie
 * 4. Returns the refreshed token so the client can use it for subsequent requests
 */
@Component
public class JwtTokenRefreshFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtProperties jwtProperties;

    public JwtTokenRefreshFilter(JwtTokenProvider jwtTokenProvider, JwtProperties jwtProperties) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtProperties = jwtProperties;
    }

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request, @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            // Extract token from request
            String token = JwtCookie.readToken(request).orElse(null);

            if (token != null && !token.isBlank()) {
                jwtTokenProvider.getClaimsFromToken(token).ifPresent(claims -> {
                    // Check if token is still valid and should be refreshed
                    if (jwtTokenProvider.shouldRefreshToken(claims, jwtProperties.getInactivityTimeout())) {
                        // Refresh the token
                        String newToken = jwtTokenProvider.refreshToken(claims);
                        
                        // Update the cookie in response
                        Cookie newCookie = JwtCookie.createJwtCookie(
                            newToken, 
                            request.isSecure(), 
                            (int) jwtProperties.getExpiration()
                        );
                        response.addCookie(newCookie);
                    } else if (jwtTokenProvider.isSessionExpired(claims)) {
                        // Session has exceeded max duration - expire the token
                        Cookie expiredCookie = JwtCookie.createJwtCookie("", request.isSecure(), 0);
                        response.addCookie(expiredCookie);
                    }
                });
            }
        } catch (Exception e) {
            // Log and continue - don't break the filter chain
            logger.debug("Error processing JWT token refresh: " + e.getMessage());
        }

        filterChain.doFilter(request, response);
    }
}
