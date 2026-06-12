package com.soayjony.springjwt;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;
import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.soayjony.springjwt.config.JwtCookie;
import com.soayjony.springjwt.config.JwtProperties;
import com.soayjony.springjwt.config.JwtTokenProvider;

import jakarta.servlet.http.Cookie;

@SpringBootTest
@AutoConfigureMockMvc
public class JwtSessionIntegrationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private JwtProperties jwtProperties;

    private AtomicReference<Instant> mockNow;

    @BeforeEach
    void setUp() {
        mockNow = new AtomicReference<>(Instant.now());
        jwtTokenProvider.setTimeSource(mockNow::get);
    }

    @AfterEach
    void tearDown() {
        jwtTokenProvider.setTimeSource(Instant::now);
    }

    private Cookie getJwtCookie(MvcResult result) {
        if (result.getResponse().getCookies() != null) {
            for (Cookie cookie : result.getResponse().getCookies()) {
                if (JwtCookie.JWT_COOKIE_NAME.equals(cookie.getName())) {
                    return cookie;
                }
            }
        }
        return null;
    }

    private String loginAndGetToken() throws Exception {
        MvcResult result = mockMvc.perform(post("/login")
                .param("username", "abc")
                .param("password", "abc123"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
        Cookie cookie = getJwtCookie(result);
        assertNotNull(cookie, "JWT cookie should be set after successful login");
        return cookie.getValue();
    }

    /**
     * Test Case 1: Successful Login and Access Protected Endpoint.
     * Verifies that submitting valid credentials sets a valid JWT cookie,
     * and that using this cookie allows access to protected endpoints.
     */
    @Test
    void test01_SuccessfulLoginAndAccessProtectedEndpoint() throws Exception {
        String token = loginAndGetToken();

        // Access protected endpoint
        mockMvc.perform(get("/")
                .cookie(new Cookie(JwtCookie.JWT_COOKIE_NAME, token)))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, Spring Boot!"));
    }

    /**
     * Test Case 2: Debounce - No Token Refresh When Active Shortly.
     * Verifies that requests made within the first half of the inactivity window
     * (e.g. 2 minutes) do not regenerate or write back a new JWT cookie.
     */
    @Test
    void test02_DebounceNoTokenRefreshWhenActiveShortly() throws Exception {
        String originalToken = loginAndGetToken();

        // Advance time by 2 minutes (less than half of the 10-minute inactivity-timeout)
        mockNow.set(mockNow.get().plusSeconds(120));

        MvcResult result = mockMvc.perform(get("/")
                .cookie(new Cookie(JwtCookie.JWT_COOKIE_NAME, originalToken)))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, Spring Boot!"))
                .andReturn();

        // No new token cookie should be set in response (due to debounce)
        Cookie responseCookie = getJwtCookie(result);
        assertTrue(responseCookie == null || responseCookie.getValue().isEmpty() || responseCookie.getValue().equals(originalToken),
                "Cookie should not be refreshed shortly after initial issue");
    }

    /**
     * Test Case 3: Token Refresh When Debounce Threshold Exceeded.
     * Verifies that requests made after at least half of the inactivity window has passed
     * (e.g. 6 minutes) trigger a successful JWT refresh and write back a new cookie.
     */
    @Test
    void test03_TokenRefreshWhenDebounceThresholdExceeded() throws Exception {
        String originalToken = loginAndGetToken();

        // Advance time by 6 minutes (more than half of the 10-minute inactivity-timeout, but less than full timeout)
        mockNow.set(mockNow.get().plusSeconds(360));

        MvcResult result = mockMvc.perform(get("/")
                .cookie(new Cookie(JwtCookie.JWT_COOKIE_NAME, originalToken)))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, Spring Boot!"))
                .andReturn();

        // A new refreshed cookie should be returned
        Cookie responseCookie = getJwtCookie(result);
        assertNotNull(responseCookie, "Refreshed JWT cookie should be returned");
        assertNotEquals(originalToken, responseCookie.getValue(), "Returned JWT token should be newly refreshed");
        assertTrue(responseCookie.getMaxAge() > 0, "Cookie maxAge should be positive");
    }

    /**
     * Test Case 4: Inactivity Timeout Redirection and Cookie Clearance.
     * Verifies that requests made after the inactivity timeout window has been exceeded
     * (e.g. 11 minutes) are redirected to the login page and the expired JWT cookie is cleared.
     */
    @Test
    void test04_InactivityTimeoutRedirectionAndCookieClearance() throws Exception {
        String token = loginAndGetToken();

        // Advance time by 11 minutes (exceeds the 10-minute inactivity-timeout)
        mockNow.set(mockNow.get().plusSeconds(660));

        MvcResult result = mockMvc.perform(get("/")
                .cookie(new Cookie(JwtCookie.JWT_COOKIE_NAME, token)))
                // Spring Security's formLogin will redirect unauthorized requests to /login
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // Verify the response contains a cookie-clearing instruction (maxAge = 0)
        Cookie responseCookie = getJwtCookie(result);
        assertNotNull(responseCookie, "Response should set a cookie to clear the expired session");
        assertEquals(0, responseCookie.getMaxAge(), "Cleared cookie should have maxAge equal to 0");
    }

    /**
     * Test Case 5: Max Session Duration Redirection and Cookie Clearance.
     * Verifies that requests made after the maximum session duration limit has passed
     * (e.g. 25 hours) are redirected to the login page and the JWT cookie is cleared.
     */
    @Test
    void test05_MaxSessionDurationRedirectionAndCookieClearance() throws Exception {
        String token = loginAndGetToken();

        // Advance time by 25 hours (exceeds the 24-hour max session duration)
        mockNow.set(mockNow.get().plusSeconds(25 * 3600));

        MvcResult result = mockMvc.perform(get("/")
                .cookie(new Cookie(JwtCookie.JWT_COOKIE_NAME, token)))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // Verify the response clears the cookie (maxAge = 0)
        Cookie responseCookie = getJwtCookie(result);
        assertNotNull(responseCookie, "Response should set a cookie to clear the max duration expired session");
        assertEquals(0, responseCookie.getMaxAge(), "Cleared cookie should have maxAge equal to 0");
    }

    /**
     * Test Case 6: Malformed or Tampered JWT Cookie.
     * Verifies that sending a tampered or malformed token results in authentication failure
     * (redirection to login) and that the invalid cookie is cleared from the browser (maxAge = 0).
     */
    @Test
    void test06_MalformedOrTamperedJwtCookie() throws Exception {
        String invalidToken = "not.a.valid.jwt.token";

        MvcResult result = mockMvc.perform(get("/")
                .cookie(new Cookie(JwtCookie.JWT_COOKIE_NAME, invalidToken)))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // Verify that the cookie is cleared
        Cookie responseCookie = getJwtCookie(result);
        assertNotNull(responseCookie, "Response should clear the invalid cookie");
        assertEquals(0, responseCookie.getMaxAge(), "Cleared cookie should have maxAge equal to 0");
    }

    /**
     * Test Case 7: Logout Behavior.
     * Verifies that requesting /logout removes the JWT cookie (maxAge = 0)
     * and clears the user's security context.
     */
    @Test
    void test07_LogoutCookieClearance() throws Exception {
        String token = loginAndGetToken();

        MvcResult result = mockMvc.perform(post("/logout")
                .cookie(new Cookie(JwtCookie.JWT_COOKIE_NAME, token)))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        Cookie responseCookie = getJwtCookie(result);
        assertNotNull(responseCookie, "Response should set a cookie to clear the logout session");
        assertEquals(0, responseCookie.getMaxAge(), "Cleared cookie should have maxAge equal to 0");
    }

    /**
     * Test Case 8: Continuous Multi-step Rolling Refresh.
     * Verifies that a user who remains continuously active receives multiple rolling updates
     * over time and remains authenticated beyond the initial expiration duration.
     */
    @Test
    void test08_MultiStepRollingRefresh() throws Exception {
        String tokenA = loginAndGetToken();

        // Step 1: Advance time by 6 minutes (first refresh threshold)
        mockNow.set(mockNow.get().plusSeconds(360));
        MvcResult resultA = mockMvc.perform(get("/")
                .cookie(new Cookie(JwtCookie.JWT_COOKIE_NAME, tokenA)))
                .andExpect(status().isOk())
                .andReturn();

        Cookie cookieB = getJwtCookie(resultA);
        assertNotNull(cookieB, "Token should be refreshed at step 1");
        String tokenB = cookieB.getValue();
        assertNotEquals(tokenA, tokenB, "Token B should be different from token A");

        // Step 2: Advance time by another 6 minutes (total 12 minutes since start, but only 6 since tokenB was generated)
        mockNow.set(mockNow.get().plusSeconds(360));
        MvcResult resultB = mockMvc.perform(get("/")
                .cookie(new Cookie(JwtCookie.JWT_COOKIE_NAME, tokenB)))
                .andExpect(status().isOk())
                .andReturn();

        Cookie cookieC = getJwtCookie(resultB);
        assertNotNull(cookieC, "Token should be refreshed at step 2");
        String tokenC = cookieC.getValue();
        assertNotEquals(tokenB, tokenC, "Token C should be different from token B");

        // Step 3: Access endpoint with latest token and confirm it works
        mockMvc.perform(get("/")
                .cookie(new Cookie(JwtCookie.JWT_COOKIE_NAME, tokenC)))
                .andExpect(status().isOk())
                .andExpect(content().string("Hello, Spring Boot!"));
    }

    /**
     * Test Case 9: Role Reconstruction and Preservation.
     * Verifies that user roles (e.g. ROLE_USER, ROLE_ADMIN) are successfully serialized
     * into the JWT claims and correctly deserialized back into Spring Security's
     * Authentication authorities context upon subsequent requests.
     */
    @Test
    void test09_RolesReconstructionAndPreservation() throws Exception {
        // Create a custom token directly with roles
        String token = jwtTokenProvider.createToken("abc", List.of("ROLE_USER", "ROLE_ADMIN"));

        mockMvc.perform(get("/")
                .cookie(new Cookie(JwtCookie.JWT_COOKIE_NAME, token)))
                .andExpect(status().isOk())
                .andExpect(authenticated().withUsername("abc").withAuthorities(List.of(
                        new SimpleGrantedAuthority("ROLE_USER"),
                        new SimpleGrantedAuthority("ROLE_ADMIN")
                )));
    }
}
