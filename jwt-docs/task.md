# Task List: JWT Integration Testing

- `[x]` Update `JwtTokenProvider.java` to enforce inactivity timeout and debounce refreshing
- `[x]` Update `JwtDeferredSecurityContext.java` to handle invalid tokens and clear cookies
- `[x]` Delete `JwtTokenRefreshFilter.java`
- `[x]` Refactor `JwtTokenProvider.java` to use a dynamic time source
- `[x]` Create integration test class `JwtSessionIntegrationTests.java`
- `[x]` Compile and run tests using JDK 21 (with integration tests included)
