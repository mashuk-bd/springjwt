package com.soayjony.springjwt.config;

import java.util.List;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Component;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class JwtSecurityContextRepository implements SecurityContextRepository {

    private final SecurityContextHolderStrategy securityContextHolderStrategy;
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtProperties jwtProperties;

    public JwtSecurityContextRepository(JwtTokenProvider jwtTokenProvider, JwtProperties jwtProperties) {
        this.securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtProperties = jwtProperties;
    }

    @Override
    public boolean containsContext(HttpServletRequest request) {
        String token = JwtCookie.readToken(request).orElse(null);
        return token != null && !token.isBlank();
    }

    /**
     * @deprecated Use {@link #loadDeferredContext(HttpServletRequest)} instead.
     *             This method will be removed in a future version of Spring
     *             Security.
     */
    @Override
    @Deprecated(since = "6.0", forRemoval = true)
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        HttpServletResponse response = requestResponseHolder.getResponse();
        return getContext(request, response);
    }

    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        Supplier<SecurityContext> supplier = () -> getContext(request, null);
        return new JwtDeferredSecurityContext(supplier, this.securityContextHolderStrategy,
                this.jwtTokenProvider, this.jwtProperties);
    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request,
            HttpServletResponse response) {

        Authentication authentication = context.getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return;
        }

        // Don't recreate token if already present
        if (hasValidToken(request, authentication)) {
            return;
        }

        List<String> roles = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        // Create token with current time as session start
        long sessionStartTime = System.currentTimeMillis();
        String jwtToken = jwtTokenProvider.createToken(authentication.getName(), roles, sessionStartTime);
        Cookie cookie = JwtCookie.createJwtCookie(jwtToken, request.isSecure(), (int) jwtProperties.getExpiration());

        response.addCookie(cookie);
    }

    private boolean hasValidToken(HttpServletRequest request, Authentication authentication) {
        return JwtCookie.readToken(request)
                .flatMap(jwtTokenProvider::getClaimsFromToken)
                .filter(jwtTokenProvider::isValid)
                .map(claims -> {
                    String username = claims.getSubject();
                    List<String> roles = jwtTokenProvider.getRolesFromToken(claims);
                    Authentication existingAuth = getAuthentication(username, roles);
                    // If the existing authentication is the same as the current one, skip token
                    // regeneration
                    return existingAuth.equals(authentication);
                })
                .orElse(false);
    }

    private SecurityContext getContext(HttpServletRequest request, HttpServletResponse response) {
        SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();

        JwtCookie.readToken(request)
                .flatMap(jwtTokenProvider::getClaimsFromToken)
                .filter(jwtTokenProvider::isValid)
                .ifPresent(claims -> {
                    String username = claims.getSubject();
                    List<String> roles = jwtTokenProvider.getRolesFromToken(claims);
                    context.setAuthentication(getAuthentication(username, roles));
                });

        return context;
    }

    private Authentication getAuthentication(String username, List<String> roles) {
        List<GrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }

}
