package com.soayjony.springjwt.config;

import jakarta.servlet.http.Cookie;

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

    private JwtCookie() {
        // Private constructor to prevent instantiation
    }
}
