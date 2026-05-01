package com.soayjony.springjwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import jakarta.servlet.http.Cookie;

@Configuration
public class SecurityConfig {

        private final JwtSecurityContextRepository jwtSecurityContextRepository;

        public SecurityConfig(JwtSecurityContextRepository jwtSecurityContextRepository) {
                this.jwtSecurityContextRepository = jwtSecurityContextRepository;
        }

        @Bean
        public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
                return http.csrf(csrf -> csrf.disable())
                                .authorizeHttpRequests(auth -> auth
                                                .requestMatchers("/login", "/login/**", "/logout").permitAll()
                                                .anyRequest().authenticated())
                                .securityContext(securityContext -> securityContext
                                                .securityContextRepository(jwtSecurityContextRepository))
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                                .requestCache(cache -> cache.disable())
                                .formLogin(Customizer.withDefaults())
                                .logout(logout -> logout
                                                .logoutUrl("/logout")
                                                .addLogoutHandler(jwtLogoutHandler())
                                                .logoutSuccessUrl("/login"))
                                .build();
        }

        @Bean
        public LogoutHandler jwtLogoutHandler() {
                return (request, response, authentication) -> {
                        Cookie cookie = JwtCookie.createJwtCookie("", request.isSecure(), 0);
                        response.addCookie(cookie);
                };
        }
}
