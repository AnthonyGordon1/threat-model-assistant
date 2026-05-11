# API Security — OWASP API Top 10 and Attack Patterns

## API1: Broken Object Level Authorization (BOLA/IDOR)
**Description:** APIs expose endpoints that handle object identifiers. Attackers manipulate these IDs to access other users' objects.
**Real World Example:** Venmo 2018 — public API exposed all transaction data. Researcher scraped 207 million transactions in 3 days revealing personal spending habits.
**STRIDE Category:** Information Disclosure, Elevation of Privilege
**MITRE ATT&CK:** T1078 Valid Accounts, T1548 Abuse Elevation Control Mechanism
**Attack Mechanism:** Attacker calls GET /api/invoices/1001 then changes to GET /api/invoices/1002 to access another user's invoice.
**Vulnerable Code:**
```javascript
app.get('/api/invoices/:id', authenticate, async (req, res) => {
    const invoice = await Invoice.findById(req.params.id);
    res.json(invoice); // No ownership verification
});
```
**Secure Code:**
```javascript
app.get('/api/invoices/:id', authenticate, async (req, res) => {
    const invoice = await Invoice.findOne({
        _id: req.params.id,
        userId: req.user.id // Scoped to authenticated user
    });
    if (!invoice) return res.status(404).json({ error: 'Not found' });
    res.json(invoice);
});
```
**Mitigation:** Always scope database queries to the authenticated user. Use random UUIDs instead of sequential IDs. Implement object-level authorization checks.

---

## API2: Broken Authentication
**Description:** Authentication mechanisms are implemented incorrectly allowing attackers to compromise authentication tokens or exploit implementation flaws.
**Real World Example:** Peloton 2021 — unauthenticated API endpoint exposed private user data including age, gender, city, and workout statistics of all users.
**STRIDE Category:** Spoofing, Information Disclosure
**MITRE ATT&CK:** T1110 Brute Force, T1539 Steal Web Session Cookie
**Attack Mechanism:** Attacker accesses API endpoints that should require authentication but do not enforce it.
**Vulnerable Code:**
```javascript
// Authentication middleware not applied to all routes
app.get('/api/users/:id/profile', async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user); // No auth required
});
```
**Secure Code:**
```javascript
// Apply authentication globally then exclude public routes
app.use(authenticate); // Applied to all routes
app.get('/api/users/:id/profile', async (req, res) => {
    const user = await User.findById(req.params.id);
    res.json(user);
});
```
**Mitigation:** Apply authentication middleware globally. Audit all endpoints regularly. Use API gateways to enforce auth at the infrastructure level.

---

## API3: Broken Object Property Level Authorization (Excessive Data Exposure)
**Description:** APIs expose more object properties than required, relying on clients to filter sensitive fields.
**Real World Example:** Twitter 2022 — API bug exposed email addresses and phone numbers of 5.4 million accounts by leaking them in API responses.
**STRIDE Category:** Information Disclosure
**MITRE ATT&CK:** T1530 Data from Cloud Storage, T1213 Data from Information Repositories
**Attack Mechanism:** Attacker calls a user profile endpoint and receives sensitive fields like password hash, internal flags, or admin status that the UI does not display but are present in the response.
**Vulnerable Code:**
```javascript
app.get('/api/profile', authenticate, async (req, res) => {
    const user = await User.findById(req.user.id);
    res.json(user); // Returns entire database object including sensitive fields
});
```
**Secure Code:**
```javascript
app.get('/api/profile', authenticate, async (req, res) => {
    const user = await User.findById(req.user.id)
        .select('name email createdAt'); // Explicitly select only safe fields
    res.json(user);
});
```
**Mitigation:** Never return raw database objects. Use DTOs or response serializers. Explicitly select only the fields needed for the response.

---

## API4: Unrestricted Resource Consumption (Rate Limiting)
**Description:** APIs without rate limiting allow attackers to perform brute force attacks, DoS, or automated scraping.
**Real World Example:** Instagram 2016 — no rate limiting on login endpoint allowed brute force of any account using username enumeration.
**STRIDE Category:** Denial of Service, Information Disclosure
**MITRE ATT&CK:** T1110 Brute Force, T1499 Endpoint Denial of Service
**Attack Mechanism:** Attacker sends thousands of login attempts per minute. Without rate limiting the server processes all of them.
**Vulnerable Code:**
```javascript
app.post('/api/login', async (req, res) => {
    const user = await authenticate(req.body);
    // No rate limiting — open to brute force
});
```
**Secure Code:**
```javascript
const rateLimit = require('express-rate-limit');
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,                   // 10 attempts per window
    message: 'Too many login attempts'
});
app.post('/api/login', loginLimiter, async (req, res) => {
    const user = await authenticate(req.body);
});
```
**Mitigation:** Implement rate limiting on all endpoints. Use exponential backoff. Implement CAPTCHA on sensitive flows. Monitor for unusual request patterns.

---

## API5: Broken Function Level Authorization
**Description:** Complex access control policies with different hierarchies lead to authorization flaws. Admins functions exposed to regular users.
**Real World Example:** Bumble 2020 — unauthorized users could access admin API endpoints by simply changing the endpoint path, allowing mass user data access.
**STRIDE Category:** Elevation of Privilege
**MITRE ATT&CK:** T1548 Abuse Elevation Control Mechanism, T1078 Valid Accounts
**Attack Mechanism:** Attacker discovers admin endpoints through API documentation, error messages, or enumeration and accesses them without admin privileges.
**Vulnerable Code:**
```javascript
app.delete('/api/admin/users/:id', authenticate, async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
    // No admin role check — any authenticated user can delete users
});
```
**Secure Code:**
```javascript
app.delete('/api/admin/users/:id', authenticate, requireRole('admin'), async (req, res) => {
    await User.findByIdAndDelete(req.params.id);
});

function requireRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'Forbidden' });
        }
        next();
    };
}
```
**Mitigation:** Implement RBAC. Apply role checks at the function level. Never rely on hiding endpoints as security. Audit privileged endpoints regularly.

---

## API6: Unrestricted Access to Sensitive Business Flows
**Description:** Some business flows can be abused if accessed in excessive volume, such as mass purchasing of limited items or mass account creation.
**Real World Example:** Ticketmaster bot abuse — automated bots purchase high-demand concert tickets within seconds of release, reselling at inflated prices.
**STRIDE Category:** Denial of Service, Tampering
**MITRE ATT&CK:** T1499 Endpoint Denial of Service, T1190 Exploit Public-Facing Application
**Attack Mechanism:** Attacker automates purchasing flow to buy all available limited inventory before human users can respond.
**Mitigation:** Implement CAPTCHA on business-critical flows. Add device fingerprinting. Detect and block automated behavior patterns. Implement purchase limits per account.

---

## API7: Server-Side Request Forgery (SSRF)
**Description:** API fetches a remote resource using a user-supplied URL without validation, allowing attackers to reach internal services.
**STRIDE Category:** Information Disclosure, Elevation of Privilege
**MITRE ATT&CK:** T1552 Unsecured Credentials, T1078 Valid Accounts
**Attack Example:**
```
POST /api/fetch-webhook
{"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/"}
# Returns AWS IAM credentials
```
**Secure Code:**
```javascript
const { URL } = require('url');
const BLOCKED_RANGES = ['169.254.', '10.', '172.16.', '192.168.'];
function isSafeUrl(urlString) {
    const url = new URL(urlString);
    return !BLOCKED_RANGES.some(range => url.hostname.startsWith(range));
}
```
**Mitigation:** Validate all user-supplied URLs. Block requests to private IP ranges. Use DNS rebinding protection. Enforce IMDSv2 on cloud instances.

---

## API Security Best Practices
- Use API gateways to enforce auth and rate limiting centrally
- Implement request signing for sensitive operations
- Use short-lived tokens with automatic rotation
- Log all API calls with user context for audit trails
- Return generic error messages — never expose stack traces
- Implement API versioning to deprecate insecure endpoints safely
- Use TLS 1.2+ for all API communication
- Validate Content-Type headers to prevent MIME sniffing attacks
