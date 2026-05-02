package com.soayjony.springjwt.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.web.savedrequest.CookieRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import jakarta.servlet.DispatcherType;

public final class RequestCacheBuilder {

    private final List<RequestMatcher> matchers = new ArrayList<>();

    private RequestCacheBuilder() {
        // default: only GET
        matchers.add(new AntPathRequestMatcher("/**", "GET"));

        // exclude favicon (Spring-style pattern)
        matchers.add(new NegatedRequestMatcher(new AntPathRequestMatcher("/**/favicon.*")));

        // exclude /error (your fix)
        matchers.add(new NegatedRequestMatcher(new AntPathRequestMatcher("/error")));

        // exclude AJAX
        matchers.add(new NegatedRequestMatcher(new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest")));

        // exclude forward dispatch
        matchers.add(request -> request.getDispatcherType() == DispatcherType.REQUEST);
    }

    public static RequestCacheBuilder create() {
        return new RequestCacheBuilder();
    }

    // Add custom exclusion paths
    public RequestCacheBuilder exclude(String pattern) {
        matchers.add(new NegatedRequestMatcher(
                new AntPathRequestMatcher(pattern)));
        return this;
    }

    // Add custom matcher
    public RequestCacheBuilder add(RequestMatcher matcher) {
        matchers.add(matcher);
        return this;
    }

    public RequestCache buildCookieCache() {
        CookieRequestCache cache = new CookieRequestCache();
        cache.setRequestMatcher(new AndRequestMatcher(matchers));
        return cache;
    }
}
