package com.soayjony.springjwt.config;

import java.util.Optional;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

public class JwtCookie {
    public static final String JWT_COOKIE_NAME = "JSESSIONTOKEN";

    public static Cookie createJwtCookie(String token, boolean secure, int maxAge) {
        Cookie cookie = new Cookie(JWT_COOKIE_NAME, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(secure);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setAttribute("SameSite", "Lax");
        return cookie;
    }

    public static Optional<String> readToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (JwtCookie.JWT_COOKIE_NAME.equals(cookie.getName())) {
                    return Optional.of(cookie.getValue());
                }
            }
        }
        return Optional.empty(); // Return empty Optional if no JWT cookie is found
    }

    private JwtCookie() {
        // Private constructor to prevent instantiation
    }
}
