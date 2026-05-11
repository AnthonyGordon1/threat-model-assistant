# OWASP Top 10 2021 — Application Security Risks

## A01: Broken Access Control
**Description:** Access control enforces policy such that users cannot act outside their intended permissions. Failures lead to unauthorized information disclosure, modification, or destruction.
**Real World Example:** In 2019, Facebook had a bug where attackers could view private posts of any user by manipulating API parameters — a classic IDOR vulnerability.
**Attack Mechanism:** Attacker modifies URL parameters, API requests, or tokens to access other users data.
**STRIDE Category:** Elevation of Privilege, Information Disclosure
**MITRE ATT&CK:** T1548 Abuse Elevation Control Mechanism, T1078 Valid Accounts
**Vulnerable Code:**
```javascript
app.get('/api/orders/:id', authenticate, async (req, res) => {
    const order = await Order.findById(req.params.id);
    res.json(order); // No ownership check
});
```
**Secure Code:**
```javascript
app.get('/api/orders/:id', authenticate, async (req, res) => {
    const order = await Order.findById(req.params.id);
    if (order.userId !== req.user.id) {
        return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(order);
});
```
**Mitigation:** Enforce least privilege, deny by default, implement RBAC, log access control failures, rate limit API endpoints.

---

## A02: Cryptographic Failures
**Description:** Failures related to cryptography that lead to exposure of sensitive data including passwords, credit cards, and health records.
**Real World Example:** Adobe 2013 — 153 million user records stolen with passwords encrypted using 3DES with no salt. Attackers cracked millions of passwords using rainbow tables.
**Attack Mechanism:** Attacker intercepts unencrypted traffic, cracks weak password hashes offline, or reads plaintext sensitive data from storage.
**STRIDE Category:** Information Disclosure
**MITRE ATT&CK:** T1552 Unsecured Credentials, T1040 Network Sniffing
**Vulnerable Code:**
```javascript
const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
```
**Secure Code:**
```javascript
const hashedPassword = await bcrypt.hash(password, 12);
```
**Mitigation:** Use TLS 1.2+, bcrypt or Argon2 for passwords, AES-256 for data at rest, never store sensitive data you don't need.

---

## A03: Injection
**Description:** Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query.
**Real World Example:** Heartland Payment Systems 2008 — SQL injection exposed 130 million credit card numbers costing $140 million in settlements.
**Attack Mechanism:** Attacker injects malicious SQL into input fields that gets executed by the database.
**STRIDE Category:** Tampering, Information Disclosure, Elevation of Privilege
**MITRE ATT&CK:** T1190 Exploit Public-Facing Application
**Vulnerable Code:**
```javascript
const query = "SELECT * FROM users WHERE email = '" + email + "'";
// Attack input: ' OR '1'='1
```
**Secure Code:**
```javascript
const query = "SELECT * FROM users WHERE email = ?";
db.execute(query, [email]);
```
**Mitigation:** Use parameterized queries, ORMs, input validation, WAF rules, least privilege database accounts.

---

## A04: Insecure Design
**Description:** Missing or ineffective security controls at the design phase. Design flaws that cannot be fixed by correct implementation.
**Real World Example:** Instagram 2019 — password reset flow allowed brute-forcing the 6-digit code without rate limiting, enabling account takeover of any account.
**Attack Mechanism:** Attacker exploits missing rate limiting, lack of account lockout, or absence of multi-factor verification.
**STRIDE Category:** Elevation of Privilege, Spoofing
**MITRE ATT&CK:** T1110 Brute Force, T1078 Valid Accounts
**Vulnerable Code:**
```python
def verify_reset_code(user_id, code):
    stored_code = get_reset_code(user_id)
    return code == stored_code  # Attacker can try all 1,000,000 combinations
```
**Secure Code:**
```python
def verify_reset_code(user_id, code):
    if get_attempts(user_id) > 5:
        raise RateLimitError("Too many attempts")
    if is_expired(user_id):
        raise ExpiredError("Code expired")
    increment_attempts(user_id)
    return constant_time_compare(code, get_reset_code(user_id))
```
**Mitigation:** Threat model during design, enforce rate limiting, implement account lockout, use proven authentication libraries.

---

## A05: Security Misconfiguration
**Description:** Insecure default configurations, incomplete configurations, open cloud storage, unnecessary features enabled.
**Real World Example:** Capital One 2019 — misconfigured AWS WAF allowed SSRF. 100 million records exposed.
**Attack Mechanism:** Attacker finds exposed admin panels, default credentials, open S3 buckets, or verbose error messages revealing stack traces.
**STRIDE Category:** Information Disclosure, Elevation of Privilege
**MITRE ATT&CK:** T1592 Gather Victim Host Information, T1083 File and Directory Discovery
**Vulnerable Code:**
```javascript
app.use((err, req, res, next) => {
    res.status(500).json({ error: err.stack }); // Never expose stack traces
});
```
**Secure Code:**
```javascript
app.use((err, req, res, next) => {
    logger.error(err.stack);
    res.status(500).json({ error: 'Internal server error' });
});
```
**Mitigation:** Automated configuration scanning, remove default credentials, disable unnecessary features, implement security headers.

---

## A06: Vulnerable and Outdated Components
**Description:** Using components with known vulnerabilities. Libraries and frameworks run with the same privileges as the application.
**Real World Example:** Equifax 2017 — unpatched Apache Struts (CVE-2017-5638) led to 147 million records exposed. Patch was available 2 months before the breach.
**Attack Mechanism:** Attacker scans for known CVEs in publicly accessible component versions then uses public exploit code.
**STRIDE Category:** Tampering, Elevation of Privilege
**MITRE ATT&CK:** T1190 Exploit Public-Facing Application, T1195 Supply Chain Compromise
**Secure Pipeline:**
```yaml
- name: Run Snyk security scan
  uses: snyk/actions/node@master
  env:
    SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
  with:
    args: --severity-threshold=high
```
**Mitigation:** Maintain SBOM, automate dependency scanning with Snyk or Dependabot, patch critical CVEs within 24 hours.

---

## A07: Identification and Authentication Failures
**Description:** Weaknesses in authentication and session management that allow attackers to compromise passwords, keys, or session tokens.
**Real World Example:** Uber 2022 — MFA fatigue attack bypassed authentication. Attacker spammed push notifications until employee approved.
**Attack Mechanism:** Credential stuffing using leaked passwords, brute force, MFA fatigue, weak session tokens.
**STRIDE Category:** Spoofing, Elevation of Privilege
**MITRE ATT&CK:** T1110 Brute Force, T1539 Steal Web Session Cookie, T1621 MFA Request Generation
**Vulnerable Code:**
```javascript
const sessionId = Math.random().toString(36).substr(2, 9); // Predictable
```
**Secure Code:**
```javascript
const sessionId = crypto.randomBytes(32).toString('hex'); // Cryptographically secure
```
**Mitigation:** Implement MFA with number matching, rate limit login attempts, use secure session management, check passwords against breach databases.

---

## A08: Software and Data Integrity Failures
**Description:** Code and infrastructure that does not protect against integrity violations including insecure deserialization and CI/CD pipeline attacks.
**Real World Example:** SolarWinds 2020 — malicious code injected into build pipeline distributed to 18,000 organizations via trusted software update.
**Attack Mechanism:** Attacker compromises CI/CD pipeline or exploits insecure deserialization to achieve RCE.
**STRIDE Category:** Tampering, Elevation of Privilege
**MITRE ATT&CK:** T1195 Supply Chain Compromise, T1553 Subvert Trust Controls
**Vulnerable Code:**
```python
import pickle
data = pickle.loads(user_input)  # Never deserialize untrusted data — RCE risk
```
**Secure Code:**
```python
import json
data = json.loads(user_input)  # Safe format for untrusted input
```
**Mitigation:** Verify digital signatures on updates, implement CI/CD integrity checks, avoid pickle/Java serialization for untrusted data.

---

## A09: Security Logging and Monitoring Failures
**Description:** Without logging and monitoring, breaches cannot be detected. Average time to detect a breach is 207 days without proper monitoring.
**Real World Example:** Yahoo 2014 — 500 million accounts compromised but not discovered until 2016. Two years of undetected access.
**Attack Mechanism:** Attacker operates undetected because no alerts fire on suspicious activity like mass data access or credential stuffing.
**STRIDE Category:** Repudiation
**MITRE ATT&CK:** T1070 Indicator Removal, T1562 Impair Defenses
**Vulnerable Code:**
```javascript
app.post('/login', async (req, res) => {
    const user = await authenticate(req.body);
    if (!user) return res.status(401).json({ error: 'Invalid credentials' });
    // No logging — attacker can credential stuff undetected
});
```
**Secure Code:**
```javascript
app.post('/login', async (req, res) => {
    const user = await authenticate(req.body);
    if (!user) {
        logger.warn('Failed login attempt', {
            ip: req.ip,
            email: req.body.email,
            timestamp: new Date().toISOString()
        });
        return res.status(401).json({ error: 'Invalid credentials' });
    }
});
```
**Mitigation:** Log all auth events, implement SIEM alerts, monitor for anomalous data access patterns, establish incident response playbooks.

---

## A10: Server-Side Request Forgery (SSRF)
**Description:** SSRF flaws allow attackers to coerce the application to send requests to unintended locations including internal services and cloud metadata endpoints.
**Real World Example:** Capital One 2019 — SSRF via misconfigured WAF allowed attacker to reach AWS metadata service and steal IAM credentials exposing 100 million records.
**Attack Mechanism:** Attacker supplies a malicious URL pointing to internal services, cloud metadata endpoints, or localhost to bypass firewall rules.
**STRIDE Category:** Information Disclosure, Elevation of Privilege
**MITRE ATT&CK:** T1552 Unsecured Credentials, T1078 Valid Accounts
**Vulnerable Code:**
```javascript
app.post('/fetch', async (req, res) => {
    const response = await fetch(req.body.url); // SSRF — no validation
    res.json(await response.json());
});
```
**Secure Code:**
```javascript
const ALLOWED_DOMAINS = ['api.trusted.com', 'cdn.trusted.com'];
app.post('/fetch', async (req, res) => {
    const url = new URL(req.body.url);
    if (!ALLOWED_DOMAINS.includes(url.hostname)) {
        return res.status(400).json({ error: 'Domain not allowed' });
    }
    const response = await fetch(req.body.url);
    res.json(await response.json());
});
```
**Mitigation:** Validate and sanitize URLs, use allowlists for external requests, enforce IMDSv2 on AWS, segment internal networks.
