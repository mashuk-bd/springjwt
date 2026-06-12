package com.soayjony.springjwt.config;

import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import io.jsonwebtoken.Claims;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtDeferredSecurityContext implements DeferredSecurityContext {
    private static final Log logger = LogFactory.getLog(JwtDeferredSecurityContext.class);
    private final Supplier<SecurityContext> supplier;
    private final SecurityContextHolderStrategy strategy;
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtProperties jwtProperties;

    private SecurityContext securityContext;
    private boolean missingContext;

    JwtDeferredSecurityContext(Supplier<SecurityContext> supplier, SecurityContextHolderStrategy strategy,
            JwtTokenProvider jwtTokenProvider, JwtProperties jwtProperties) {
        this.supplier = supplier;
        this.strategy = strategy;
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtProperties = jwtProperties;
    }

    @Override
    public SecurityContext get() {
        init();
        return this.securityContext;
    }

    @Override
    public boolean isGenerated() {
        init();
        return this.missingContext;
    }

    private void init() {
        if (this.securityContext != null) {
            return;
        }

        this.securityContext = this.supplier.get();
        this.missingContext = (this.securityContext == null);
        if (this.missingContext) {
            this.securityContext = this.strategy.createEmptyContext();
            if (logger.isTraceEnabled()) {
                logger.trace(LogMessage.format("Created %s", this.securityContext));
            }
        } else {
            // Handle token refresh after context is loaded
            handleTokenRefreshIfNeeded();
        }
    }

    /**
     * Handles token refresh logic within the deferred security context.
     * This ensures refresh happens during the request processing when response is
     * available.
     */
    private void handleTokenRefreshIfNeeded() {
        try {
            // Get current request/response from RequestContextHolder
            ServletRequestAttributes attrs = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            if (attrs == null) {
                return;
            }

            HttpServletRequest request = attrs.getRequest();
            HttpServletResponse response = attrs.getResponse();

            if (request == null || response == null) {
                return;
            }

            // Extract token and check if refresh is needed
            JwtCookie.readToken(request)
                    .flatMap(jwtTokenProvider::getClaimsFromToken)
                    .ifPresent(claims -> {
                        if (jwtTokenProvider.isValid(claims)) {
                            if (jwtTokenProvider.shouldRefreshToken(claims, jwtProperties.getInactivityTimeout())) {
                                // User is active - refresh the token
                                String newToken = jwtTokenProvider.refreshToken(claims);
                                Cookie newCookie = JwtCookie.createJwtCookie(
                                        newToken,
                                        request.isSecure(),
                                        (int) jwtProperties.getExpiration());
                                response.addCookie(newCookie);
                            }
                        } else {
                            // Token is invalid (expired, inactive, or max duration exceeded) - clear the cookie
                            Cookie expiredCookie = JwtCookie.createJwtCookie("", request.isSecure(), 0);
                            response.addCookie(expiredCookie);
                        }
                    });
        } catch (Exception e) {
            // Log and continue - don't break the security context loading
            logger.debug("Error processing JWT token refresh: " + e.getMessage());
        }
    }
}
