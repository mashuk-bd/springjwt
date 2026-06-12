# JWT Session Timeout Implementation

## Overview

This implementation provides automatic session timeout with an "activity-based refresh" mechanism. Users remain logged in while active, and the session automatically expires after inactivity or a maximum duration.

## How It Works

### Key Components

1. **JwtTokenProvider** - Enhanced to track session timing
   - `lastActivity`: Timestamp of when the token was last used
   - `sessionStart`: When the session began
   - Supports token refresh while maintaining session history

2. **JwtTokenRefreshFilter** - Automatically refreshes tokens
   - Runs on every request before authentication
   - Checks if token should be refreshed based on user activity
   - Refreshes the token by updating the cookie

3. **JwtProperties** - Configurable timeout parameters
   - `expiration`: Short-lived access token duration (default: 15 minutes)
   - `inactivityTimeout`: How long before session expires due to inactivity (default: 10 minutes)
   - `maxSessionDuration`: Maximum session life regardless of activity (default: 24 hours)

### Session Lifecycle

```
Login Request
    ↓
Session Starts (sessionStart timestamp recorded)
    ↓
Token Created with expiration = now + 15 minutes
    ↓
User Makes Request (within 10 minute inactivity window)
    ↓
JwtTokenRefreshFilter Detects Activity
    ↓
Token Refreshed: expiration = now + 15 minutes
    ↓
Response includes updated cookie
    ↓
Repeat until: 
  - 10 minutes of NO activity → Session expires
  - OR 24 hours elapsed → Max session duration reached
    ↓
User Logged Out
```

### Configuration

Add to `application.properties`:

```properties
# Access token lifetime (seconds)
jwt.expiration=900                    # 15 minutes

# Inactivity timeout (seconds)  
jwt.inactivity-timeout=600           # 10 minutes

# Maximum session duration (seconds)
jwt.max-session-duration=86400       # 24 hours
```

### What Each Setting Does

| Setting | Default | Purpose |
|---------|---------|---------|
| `jwt.expiration` | 900s (15min) | How long each access token is valid. Short duration requires frequent refresh |
| `jwt.inactivity-timeout` | 600s (10min) | If user inactive for this long, session expires. Must be < expiration |
| `jwt.max-session-duration` | 86400s (24h) | Even if always active, session expires after this time for security |

## Implementation Details

### Token Claims

Each JWT now contains:

```json
{
  "sub": "username",
  "roles": ["ROLE_USER"],
  "lastActivity": 1621234567,      // Unix timestamp of last activity
  "sessionStart": 1621234567,       // Unix timestamp of session start
  "iat": 1621234567,                // Issued at
  "exp": 1621235467                 // Expiration (iat + 15 minutes)
}
```

### Refresh Logic

The filter executes on every request:

```java
if (token.isValid()) {
    if (lastActivity < (now - inactivityTimeout)) {
        // Session expired from inactivity
        logout();
    } else if ((now - sessionStart) > maxSessionDuration) {
        // Maximum session time exceeded
        logout();
    } else if (lastActivity < (now - inactivityTimeout/2)) {
        // User is active - refresh token
        newToken = refreshToken(oldToken);
        setCookie(newToken);
    }
}
```

## Client Behavior

From the client's perspective:

1. **Initial Login**: Cookie set with JWT token
2. **Active Session**: Each request automatically refreshes the cookie
3. **Inactivity**: After 10 minutes of no requests, next request returns 401 Unauthorized
4. **Long Sessions**: Even with activity, session expires after 24 hours
5. **Logout**: User must re-login for new session

### Example Flow

```
10:00 - User logs in
10:05 - User makes request → Token refreshed (10:20 expiry)
10:06 - User makes request → Token refreshed (10:21 expiry)
10:20 - User stops using app
10:30 - User makes request → Session expired (10+ min inactive)
        Response: 401 Unauthorized → Redirect to login
```

## Advantages

✅ **Automatic Activity Tracking**: No need for separate session tracking database
✅ **Stateless**: Pure JWT-based, scales horizontally  
✅ **Security**: Sessions expire after inactivity OR max duration
✅ **Transparent**: Users don't need to manually refresh tokens
✅ **Configurable**: All timeouts adjustable without code changes
✅ **No Server State**: Works with distributed systems/load balancers

## Disadvantages & Tradeoffs

⚠️ **Refresh Overhead**: Every request causes token refresh (network overhead)
⚠️ **Cannot Revoke Mid-Session**: Token valid until expiration (mitigate with short expiration)
⚠️ **Distributed Clock Issues**: If servers have clock skew, affects token validation
⚠️ **Client Must Support Cookies**: Requires HttpOnly cookie support

## Common Configurations

### Aggressive Security (Banks/Finance)

```properties
jwt.expiration=300                 # 5 minutes
jwt.inactivity-timeout=300         # 5 minutes
jwt.max-session-duration=3600      # 1 hour
```

### Balanced (Most Apps)

```properties
jwt.expiration=900                 # 15 minutes
jwt.inactivity-timeout=600         # 10 minutes
jwt.max-session-duration=86400     # 24 hours
```

### User Convenience (Long Sessions)

```properties
jwt.expiration=1800                # 30 minutes
jwt.inactivity-timeout=1800        # 30 minutes
jwt.max-session-duration=604800    # 7 days
```

## Testing the Implementation

### Test 1: Token Refresh on Activity

```bash
# 1. Login
curl -X POST http://localhost:8080/login -d "username=abc&password=abc123"
# Check Set-Cookie header for JWT

# 2. Make request immediately
curl -H "Cookie: JSESSIONTOKEN=<token>" http://localhost:8080/api/data
# Check new Set-Cookie header - should be different token

# 3. Token should be refreshed with new expiration time
```

### Test 2: Session Timeout After Inactivity

```bash
# 1. Login and save token
TOKEN=$(curl -X POST ... | extract-token)

# 2. Wait 10+ minutes without making requests
sleep 605

# 3. Make request with old token
curl -H "Cookie: JSESSIONTOKEN=$TOKEN" http://localhost:8080/api/data
# Should return 401 Unauthorized
```

### Test 3: Maximum Session Duration

```bash
# 1. Login
# 2. Make requests every 5 minutes for 24+ hours
# After 24 hours, even with activity, should be logged out
```

## Troubleshooting

### Issue: Sessions timing out too quickly
**Solution**: Check `jwt.inactivity-timeout` is reasonable for your use case. Consider increasing it.

### Issue: Sessions never timeout
**Solution**: Verify `JwtTokenRefreshFilter` is registered in `SecurityConfig`. Check logs for refresh filter execution.

### Issue: Tokens failing validation
**Solution**: Check server clocks are synchronized. JWT expiration is based on server time. Also verify `jwt.secret` is the same across all instances.

### Issue: CORS cookies not working
**Solution**: Verify `SameSite=Lax` attribute on cookie. May need `SameSite=None; Secure` for cross-origin requests.

## Related Files

- `JwtTokenProvider.java` - Token creation/validation/refresh logic
- `JwtTokenRefreshFilter.java` - Automatic refresh filter
- `JwtSecurityContextRepository.java` - Integration with Spring Security
- `JwtProperties.java` - Configuration properties
- `SecurityConfig.java` - Filter registration
- `application.properties` - Runtime configuration
