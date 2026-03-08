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

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class JwtSecurityContextRepository implements SecurityContextRepository {

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
            .getContextHolderStrategy();

    @Override
    public boolean containsContext(HttpServletRequest request) {
        String token = readJWTFromCookie(request);
        return token != null && !token.isBlank();
    }

    /**
     * @deprecated Use {@link #loadDeferredContext(HttpServletRequest)} instead.
     *             This method will be removed in a future version of Spring Security.
     */
    @Override
    @Deprecated(since = "6.0", forRemoval = true)
    public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
        HttpServletRequest request = requestResponseHolder.getRequest();
        return getContext(request);
    }

    @Override
    public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
        Supplier<SecurityContext> supplier = () -> getContext(request);
        return new JwtDeferredSecurityContext(supplier, this.securityContextHolderStrategy);

    }

    @Override
    public void saveContext(SecurityContext context, HttpServletRequest request,
            HttpServletResponse response) {

        Authentication authentication = context.getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            return;
        }

        // Don't recreate token if already present
        String existingToken = readJWTFromCookie(request);

        if (existingToken != null) {
            return;
        }

        List<String> roles = authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        String jwtToken = JwtTokenProvider.createToken(authentication.getName(), roles);
        Cookie cookie = JwtCookie.createJwtCookie(jwtToken, request.isSecure(), 3600);

        response.addCookie(cookie);
    }

    private SecurityContext getContext(HttpServletRequest request) {
        String token = readJWTFromCookie(request);
        SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
        JwtTokenProvider.getClaimsFromToken(token)
                .filter(JwtTokenProvider::isValid)
                .ifPresent(claims -> {
                    String username = claims.getSubject();
                    List<String> roles = JwtTokenProvider.getRolesFromToken(claims);
                    context.setAuthentication(getAuthentication(username, roles));
                });

        return context;
    }

    private String readJWTFromCookie(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (JwtCookie.JWT_COOKIE_NAME.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null; // Return null if no JWT cookie is found
    }

    private Authentication getAuthentication(String username, List<String> roles) {
        List<GrantedAuthority> authorities = roles.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(username, null, authorities);
    }

}
