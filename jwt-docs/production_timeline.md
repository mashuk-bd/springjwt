# Production Launch Timeline & Issues Tracker

This document tracks security, configuration, and architectural issues that must be addressed prior to deploying the stateless JWT session timeout solution to a production environment.

## 📋 Pre-Production Issues Checklist

### Phase 1: Security & Secrets
- [ ] **1. Externalize JWT Secret Key**
  - **Issue:** The JWT signing key is currently hardcoded in `application.properties`.
  - **Solution:** Inject the secret key dynamically via environment variables (`jwt.secret=${JWT_SECRET_KEY}`).
  - **Target Date:** _TBD_
  - **Status:** Not Started

- [ ] **2. Mitigation of CSRF Vulnerability**
  - **Issue:** CSRF protection is currently disabled. Since JWTs are stored in cookies, browser requests are vulnerable to Cross-Site Request Forgery.
  - **Solution:** Enable Spring Security CSRF protection or implement same-site cookie validation/custom headers to protect state-changing requests.
  - **Target Date:** _TBD_
  - **Status:** Not Started

---

### Phase 2: Deployment & Reliability
- [ ] **3. Reverse Proxy Forwarded Headers Configuration**
  - **Issue:** `request.isSecure()` determines cookie encryption. In reverse proxy environments (e.g. AWS ALB, Cloudflare, Nginx), requests will appear insecure on the application server if forward headers are ignored.
  - **Solution:** Add `server.forward-headers-strategy=FRAMEWORK` to configuration or configure Nginx/ALB to propagate `X-Forwarded-Proto`.
  - **Target Date:** _TBD_
  - **Status:** Not Started

- [ ] **4. Clock Skew Tolerance**
  - **Issue:** Distributed application nodes can experience time drift, causing valid cookies to be rejected as expired or not yet valid on different servers.
  - **Solution:** Configure a clock skew tolerance of 60 seconds in the `JwtTokenProvider` parser settings.
  - **Target Date:** _TBD_
  - **Status:** Not Started

---

### Phase 3: Advanced Features (Optional)
- [ ] **5. Immediate Force-Logout (Token Blacklisting)**
  - **Issue:** Fully stateless JWT validation cannot invalidate a user mid-session once issued.
  - **Solution:** Introduce a lightweight Redis-based cache to store blacklisted token signatures with a TTL equal to token expiration.
  - **Target Date:** _TBD_
  - **Status:** Not Started
