# Comprehensive Security Review Guide

This guide consolidates security best practices across multiple domains for code review purposes. Use this to identify security vulnerabilities in code. 

---

## 1. Cryptography & Encryption

### Core Cryptographic Algorithms

**Banned (Insecure) Algorithms - STRICTLY FORBIDDEN:**
- **Hash Functions:** MD2, MD4, MD5, SHA-0, SHA-1 (deprecated)
- **Symmetric Ciphers:** RC2, RC4, Blowfish, DES, 3DES, AES-ECB
- **Key Exchange:** Static RSA, Anonymous Diffie-Hellman, DHE with weak/common primes
- **Signature Algorithms:** RSA with PKCS#1 v1.5 padding

**Recommended Secure Algorithms:**
- **Symmetric Encryption:** AES-GCM or ChaCha20-Poly1305 (preferred). Avoid ECB. CBC/CTR only with encrypt-then-MAC.
- **Asymmetric Encryption:** RSA ≥2048 bits or modern ECC (Curve25519/Ed25519). Use OAEP for RSA encryption.
- **Hashing:** SHA-256 or higher for integrity
- **Random Number Generation:** Use CSPRNG appropriate to platform (e.g., SecureRandom, crypto.randomBytes, secrets module). Never use non-crypto RNGs.

**Deprecated SSL/Crypto APIs - FORBIDDEN:**

Symmetric Encryption:
- Deprecated: `AES_encrypt()`, `AES_decrypt()`
- Use: `EVP_EncryptInit_ex()`, `EVP_EncryptUpdate()`, `EVP_EncryptFinal_ex()`

RSA Operations:
- Deprecated: `RSA_new()`, `RSA_up_ref()`, `RSA_free()`
- Use: `EVP_PKEY_new()`, `EVP_PKEY_up_ref()`, `EVP_PKEY_free()`

Hash Functions:
- Deprecated: `SHA1_Init()`, `SHA1_Update()`, `SHA1_Final()`
- Use: `EVP_DigestInit_ex()`, `EVP_DigestUpdate()`, `EVP_DigestFinal_ex()`, `EVP_Q_digest()`

MAC Operations:
- Deprecated: `CMAC_Init()`, `HMAC()` with SHA1
- Use: `EVP_Q_MAC()` with SHA-256 or stronger

Key Wrapping:
- Deprecated: `AES_wrap_key()`, `AES_unwrap_key()`
- Use: EVP key wrapping APIs

**Secure Implementation Pattern:**
```c
EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
if (!ctx) handle_error();

if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv) != 1)
    handle_error();

int len, ciphertext_len;
if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
    handle_error();
ciphertext_len = len;

if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
    handle_error();
ciphertext_len += len;

EVP_CIPHER_CTX_free(ctx);
```

### Key Management

- **Generation:** Generate keys within validated modules (HSM/KMS), never from passwords or predictable inputs
- **Separation:** Separate keys by purpose (encryption, signing, wrapping)
- **Rotation:** Rotate on compromise, cryptoperiod expiry, or policy requirements
- **Storage:** Store keys in KMS/HSM or vault; never hardcode; avoid plain environment variables
- **Key Wrapping:** Use KEK to wrap DEKs; store separately
- **Access Control:** Control access to trust stores; validate updates; audit all key access and operations

### Data at Rest

- Encrypt sensitive data; minimize stored secrets; tokenize where possible
- Use authenticated encryption (AEAD)
- Manage nonces/IVs properly; keep salts unique per item
- **Backups:** Encrypt, restrict access, test restores, manage retention

### TLS Configuration

**Protocols:**
- Prefer TLS 1.3; allow TLS 1.2 only for legacy compatibility
- Disable TLS 1.0/1.1 and all SSL versions
- Enable TLS_FALLBACK_SCSV

**Ciphers:**
- Prefer AEAD suites
- Disable NULL/EXPORT/anonymous ciphers
- Keep libraries updated; disable compression

**Key Exchange:**
- Prefer x25519/secp256r1
- Configure secure FFDHE groups if needed

**Certificates:**
- 2048-bit+ keys, SHA-256 signatures
- Correct CN/SAN configuration
- Manage lifecycle and revocation (OCSP stapling)

**Application Layer:**
- HTTPS site-wide
- Redirect HTTP→HTTPS
- Prevent mixed content
- Set cookies with `Secure` flag

### HSTS (HTTP Strict Transport Security)

- Send `Strict-Transport-Security` header only over HTTPS
- **Phased Rollout:**
  - Test: short max-age (e.g., 86400) with includeSubDomains
  - Production: ≥1 year max-age; includeSubDomains when safe
  - Optional preload once mature (understand permanence and subdomain impact)

### Certificate Pinning

- Avoid browser HPKP
- Consider pinning only for controlled clients (mobile apps) when you own both ends
- Prefer SPKI pinning with backup pins
- Plan secure update channels
- Never allow user bypass
- Thoroughly test rotation and failure handling

---

## 2. Authentication & Multi-Factor Authentication

### Account Identifiers and UX

- Use non-public, random, unique internal user identifiers
- Allow login via verified email or username
- Return generic error messages ("Invalid username or password")
- Keep timing consistent to prevent account enumeration
- Support password managers: proper input types, allow paste, no JavaScript blocks

### Password Policy

- Accept passphrases and full Unicode
- Minimum 8 characters; avoid composition rules
- Reasonable maximum length (64+ characters)
- Check against breach corpora (k-anonymity APIs)
- Reject breached/common passwords

### Password Storage (Hashing)

**Hash, do not encrypt.** Use slow, memory-hard algorithms with unique per-user salts and constant-time comparison.

**Preferred order and parameters (tune to hardware; target <1s):**
1. **Argon2id:** m=19–46 MiB, t=2–1, p=1
2. **scrypt:** N=2^17, r=8, p=1
3. **bcrypt (legacy only):** cost ≥10 (be aware of 72-byte input limit)
4. **PBKDF2 (FIPS):** PBKDF2-HMAC-SHA-256 ≥600k iterations, or SHA-1 ≥1.3M iterations

**Optional pepper:** Store outside DB (KMS/HSM); apply via HMAC or pre-hashing; plan for user resets if pepper rotates.

### Authentication Flow Hardening

- Enforce TLS for all auth endpoints; enable HSTS
- Implement rate limits per IP, account, and globally
- Add proof-of-work or CAPTCHA only as last resort
- Progressive backoff for lockouts/throttling
- Uniform responses and code paths to reduce oracle/timing signals

### Multi-Factor Authentication (MFA)

**Phishing-Resistant Factors (Preferred):**
- Passkeys/WebAuthn (FIDO2)
- Hardware U2F tokens

**Acceptable Factors:**
- TOTP (app-based)
- Smart cards with PIN

**Avoid for Sensitive Use:**
- SMS/voice codes
- Email codes
- Security questions

**MFA Requirements:**
- Require for: login, password/email changes, disabling MFA, privilege elevation, high-value transactions, new devices/locations
- **Risk-based signals:** new device, geo-velocity, IP reputation, unusual time, breached credentials
- **Recovery:** single-use backup codes, encourage multiple factors, strong identity verification for resets
- **Failed MFA:** offer alternative enrolled methods, notify users, log context (no secrets)

### Federation and Protocols

**OAuth 2.0 / OIDC:**
- Prefer Authorization Code with PKCE for public/native apps
- Avoid Implicit and ROPC flows
- Validate state and nonce
- Use exact redirect URI matching; prevent open redirects
- Constrain tokens to audience/scope
- Use DPoP or mTLS for sender-constraining when possible
- Rotate refresh tokens; revoke on logout or risk signals

**SAML:**
- TLS 1.2+
- Sign responses/assertions; encrypt sensitive assertions
- Validate issuers, InResponseTo, timestamps, Recipient
- Verify against trusted keys
- Prevent XML signature wrapping with strict schema validation
- Keep response lifetimes short
- Prefer SP-initiated flows
- Validate RelayState; implement replay detection

### Tokens (JWT and Opaque)

- Prefer opaque server-managed tokens for simplicity and revocation
- **If using JWTs:**
  - Explicitly pin algorithms; reject "none"
  - Validate iss/aud/exp/iat/nbf
  - Use short lifetimes and rotation
  - Store secrets/keys securely (KMS/HSM)
  - Use strong HMAC secrets or asymmetric keys; never hardcode
  - Consider binding tokens to client context
  - Implement denylist/allowlist for revocation

### Recovery and Reset

- Return same response for existing and non-existing accounts (no enumeration)
- Normalize timing
- Generate 32+ byte CSPRNG tokens; single-use; store as hashes; short expiry
- Use HTTPS reset links to pinned, trusted domains
- Add referrer policy (no-referrer) on UI
- After reset: require re-authentication, rotate sessions, do not auto-login
- Never lock accounts due to reset attempts; rate-limit and monitor

### Administrative Accounts

- Separate admin login from public forms
- Enforce stronger MFA, device posture checks, IP allowlists, step-up auth
- Use distinct session contexts and stricter timeouts

### Monitoring

- Log auth events: failures/successes, MFA enroll/verify, resets, lockouts
- Use stable fields and correlation IDs
- Never log secrets or raw tokens
- Detect credential stuffing: high failure rates, many IPs/agents, impossible travel
- Notify users of new device logins

---

## 3. Authorization & Access Control

### Core Principles

1. **Deny by Default:** Default to 'deny'; explicitly grant permissions
2. **Least Privilege:** Grant minimum required access
3. **Validate on Every Request:** Check authorization for all requests
4. **Prefer ABAC/ReBAC over RBAC:** Use Attribute-Based or Relationship-Based Access Control for fine-grained permissions

### Systemic Controls

- Centralize authorization at service boundaries via middleware/policies/filters
- Model permissions at resource level (ownership/tenancy)
- Enforce scoping in data queries
- Return generic 403/404 to avoid leaking resource existence
- Log all denials with user, action, resource identifier (non-PII), rationale code

### Preventing IDOR (Insecure Direct Object Reference)

- Never trust user-supplied identifiers alone
- Always verify access to each object instance
- Resolve resources through user-scoped queries
- Example: `currentUser.projects.find(id)` instead of `Project.find(id)`
- Use non-enumerable identifiers (UUIDs/random) as defense-in-depth

### Preventing Mass Assignment

- Do not bind request bodies directly to domain objects
- Expose only safe, editable fields via DTOs
- Maintain explicit allow-lists for patch/update operations
- Use framework features to block-list sensitive fields if allow-listing is infeasible

### Transaction Authorization (Step-Up)

- Require second factor for sensitive actions (wire transfers, privilege elevation, data export)
- Apply What-You-See-Is-What-You-Sign: show critical fields for user confirmation
- Use unique, time-limited authorization credentials per transaction
- Reject on data changes mid-flow
- Enforce authorization method server-side; prevent client-side downgrades
- Protect against brute-force with throttling and flow restarts after failures

### Testing and Automation

- Maintain authorization matrix (YAML/JSON): endpoints/resources, roles/attributes, expected outcomes
- Automate integration tests that iterate matrix, mint role tokens, assert allow/deny results
- Exercise negative tests: swapped IDs, downgraded roles, missing scopes, bypass attempts

---

## 4. Input Validation & Injection Defense

### Core Strategy

- Validate early at trust boundaries with positive (allow-list) validation
- Treat all untrusted input as data, never as code
- Use safe APIs that separate code from data
- Parameterize queries/commands; escape only as last resort

### Validation Playbook

- **Syntactic validation:** enforce format, type, ranges, lengths
- **Semantic validation:** enforce business rules
- **Normalization:** canonicalize encodings before validation; validate complete strings (regex anchors ^$); beware ReDoS
- **Free-form text:** define character class allow-lists; normalize Unicode; set length bounds
- **Files:** validate by content type (magic), size caps, safe extensions; server-generate filenames; scan; store outside web root

### SQL Injection Prevention

- **Use prepared statements and parameterized queries for 100% of data access**
- Use bind variables for any dynamic SQL construction
- Never concatenate user input into SQL
- Prefer least-privilege DB users and views
- Never grant admin to app accounts
- Escaping is fragile and discouraged; parameterization is primary defense

**Example (Java PreparedStatement):**
```java
String custname = request.getParameter("customerName");
String query = "SELECT account_balance FROM user_data WHERE user_name = ? ";
PreparedStatement pstmt = connection.prepareStatement(query);
pstmt.setString(1, custname);
ResultSet results = pstmt.executeQuery();
```

### LDAP Injection Prevention

- Always apply context-appropriate escaping:
  - DN escaping for `\ # + < > , ; " =` and leading/trailing spaces
  - Filter escaping for `* ( ) \ NUL`
- Validate inputs with allow-lists before constructing queries
- Use libraries with DN/filter encoders
- Use least-privilege LDAP connections with bind authentication

### OS Command Injection Defense

- **Prefer built-in APIs instead of shelling out**
- If unavoidable, use structured execution that separates command and arguments (e.g., ProcessBuilder)
- Do not invoke shells
- Strictly allow-list commands and validate arguments
- Exclude metacharacters: `& | ; $ > < ` \ ! ' " ( )` and whitespace
- Use `--` to delimit arguments where supported

**Example (Java ProcessBuilder):**
```java
ProcessBuilder pb = new ProcessBuilder("TrustedCmd", "Arg1", "Arg2");
Map<String,String> env = pb.environment();
pb.directory(new File("TrustedDir"));
Process p = pb.start();
```

### Prototype Pollution (JavaScript)

- Use `new Set()` or `new Map()` instead of object literals
- When objects required, create with `Object.create(null)` or `{ __proto__: null }`
- Freeze or seal objects that should be immutable
- Consider Node `--disable-proto=delete`
- Avoid unsafe deep merge utilities
- Validate keys against allow-lists and block `__proto__`, `constructor`, `prototype`

---

## 5. Client-Side Web Security

### XSS Prevention (Context-Aware)

**HTML Context:**
- Prefer `textContent`
- If HTML required, sanitize with vetted library (e.g., DOMPurify) and strict allow-lists

**Attribute Context:**
- Always quote attributes and encode values

**JavaScript Context:**
- Do not build JS from untrusted strings
- Avoid inline event handlers
- Use `addEventListener`

**URL Context:**
- Validate protocol/domain and encode
- Block `javascript:` and data URLs where inappropriate

**Redirects/Forwards:**
- Never use user input directly for destinations
- Use server-side mapping (ID→URL) or validate against trusted domain allowlists

**Example sanitization:**
```javascript
const clean = DOMPurify.sanitize(userHtml, {
  ALLOWED_TAGS: ['b','i','p','a','ul','li'],
  ALLOWED_ATTR: ['href','target','rel'],
  ALLOW_DATA_ATTR: false
});
```

### DOM-Based XSS and Dangerous Sinks

- **Prohibit:** `innerHTML`, `outerHTML`, `document.write` with untrusted data
- **Prohibit:** `eval`, `new Function`, string-based `setTimeout/Interval`
- Validate and encode before assigning to `location` or event handler properties
- Use strict mode and explicit variable declarations
- Adopt Trusted Types and enforce strict CSP

**Trusted Types + CSP:**
```http
Content-Security-Policy: script-src 'self' 'nonce-{random}'; object-src 'none'; base-uri 'self'; require-trusted-types-for 'script'
```

### Content Security Policy (CSP)

- Prefer nonce-based or hash-based CSP over domain allow-lists
- Start with Report-Only mode; collect violations; then enforce
- **Baseline:** `default-src 'self'; style-src 'self' 'unsafe-inline'; frame-ancestors 'self'; form-action 'self'; object-src 'none'; base-uri 'none'; upgrade-insecure-requests`

### CSRF Defense

- Fix XSS first; then layer CSRF defenses
- Use framework-native CSRF protections and synchronizer tokens
- **Cookie settings:** `SameSite=Lax` or `Strict`; sessions `Secure` and `HttpOnly`; use `__Host-` prefix when possible
- Validate Origin/Referer
- Require custom headers for API mutations
- Never use GET for state changes
- Validate tokens on POST/PUT/DELETE/PATCH
- Enforce HTTPS for all token transmission

### Clickjacking Defense

- **Primary:** `Content-Security-Policy: frame-ancestors 'none'` or specific allow-list
- **Fallback:** `X-Frame-Options: DENY` or `SAMEORIGIN`
- Consider UX confirmations for sensitive actions when framing required

### Cross-Site Leaks (XS-Leaks) Controls

- Use `SameSite` cookies appropriately; prefer `Strict` for sensitive actions
- Adopt Fetch Metadata protections to block suspicious cross-site requests
- Isolate browsing contexts: COOP/COEP and CORP where applicable
- Disable caching and add user-unique tokens for sensitive responses

### Third-Party JavaScript

- Minimize and isolate: prefer sandboxed iframes with `sandbox` and postMessage origin checks
- Use Subresource Integrity (SRI) for external scripts
- Provide first-party, sanitized data layer
- Govern via tag manager controls and vendor contracts
- Keep libraries updated

**SRI example:**
```html
<script src="https://cdn.vendor.com/app.js"
  integrity="sha384-..." crossorigin="anonymous"></script>
```

### HTML5, CORS, WebSockets, Storage

**postMessage:**
- Always specify exact target origin
- Verify `event.origin` on receive

**CORS:**
- Avoid `*`
- Allow-list origins
- Validate preflights
- Do not rely on CORS for authorization

**WebSockets:**
- Require `wss://`
- Origin checks, auth, message size limits
- Safe JSON parsing

**Client Storage:**
- Never store secrets in `localStorage`/`sessionStorage`
- Prefer HttpOnly cookies
- If unavoidable, isolate via Web Workers

**Links:**
- Add `rel="noopener noreferrer"` to external `target=_blank` links

### HTTP Security Headers

- **HSTS:** Enforce HTTPS everywhere
- **X-Content-Type-Options:** `nosniff`
- **Referrer-Policy** and **Permissions-Policy:** Restrict sensitive signals and capabilities

---

## 6. API & Web Services Security

### Transport and TLS

- HTTPS only
- Consider mTLS for high-value/internal services
- Validate certs (CN/SAN, revocation)
- Prevent mixed content

### Authentication and Tokens

- Use standard flows (OAuth2/OIDC) for clients
- Avoid custom schemes
- For services, use mTLS or signed service tokens
- **JWTs:** pin algorithms; validate iss/aud/exp/nbf; short lifetimes; rotation; denylist on logout/revoke
- Prefer opaque tokens when revocation required and central store available
- **API keys:** scope narrowly; rate limit; monitor usage; do not use alone for sensitive operations

### Authorization

- Enforce per-endpoint, per-resource checks server-side
- Deny by default
- For microservices, authorize at gateway (coarse) and service (fine) layers
- Propagate signed internal identity, not external tokens

### Input and Content Handling

- Validate inputs via contracts: OpenAPI/JSON Schema, GraphQL SDL, XSD
- Reject unknown fields and oversize payloads; set limits
- Enforce explicit Content-Type/Accept; reject unsupported combinations
- Harden XML parsers against XXE/expansion

### SQL/Injection Safety

- Use parameterized queries/ORM bind parameters
- Never concatenate user input into queries or commands

### GraphQL-Specific Controls

- Limit query depth and overall complexity
- Enforce pagination
- Timeouts on execution
- Disable introspection and IDEs in production
- Implement field/object-level authorization to prevent IDOR/BOLA
- Validate batching and rate limit per object type

### SSRF Prevention

- Do not accept raw URLs
- Validate domains/IPs using libraries
- Restrict to HTTP/HTTPS only (block file://, gopher://, ftp://)
- **Case 1 (fixed partners):** strict allow-lists; disable redirects; network egress allow-lists
- **Case 2 (arbitrary):** block private/link-local/localhost ranges; resolve and verify all IPs are public; require signed tokens from target where feasible

### SOAP/WS and XML Safety

- Validate SOAP payloads with XSD
- Limit message sizes
- Enable XML signatures/encryption where required
- Configure parsers against XXE, entity expansion, recursive payloads
- Scan attachments

### Rate Limiting and DoS

- Apply per-IP/user/client limits, circuit breakers, timeouts
- Use server-side batching and caching to reduce load

### Management Endpoints

- Do not expose over the Internet
- Require strong auth (MFA), network restrictions, separate ports/hosts

---

## 7. Session Management & Cookies

### Session ID Generation

- Generate with CSPRNG; ≥64 bits entropy (prefer 128+)
- Opaque, unguessable, free of meaning
- Use generic cookie names (e.g., `id`)
- Reject any incoming ID not created by server
- Store all session data server-side
- Never embed PII or privileges in token

### Cookie Security Configuration

- Set `Secure`, `HttpOnly`, `SameSite=Strict` (or `Lax` if necessary)
- Scope cookies narrowly with `Path` and `Domain`
- Avoid cross-subdomain exposure
- Prefer non-persistent session cookies
- Require full HTTPS; enable HSTS

**Example header:**
```
Set-Cookie: id=<opaque>; Secure; HttpOnly; SameSite=Strict; Path=/
```

### Session Lifecycle and Rotation

- Create sessions only server-side
- Treat provided IDs as untrusted input
- **Regenerate session ID on:**
  - Authentication
  - Password changes
  - Privilege elevation
- Invalidate prior ID

### Expiration and Logout

- **Idle timeout:** 2–5 minutes (high-value), 15–30 minutes (lower risk)
- **Absolute timeout:** 4–8 hours
- Enforce timeouts server-side
- Provide visible logout button that fully invalidates server session and clears cookie

### Cookie Theft Detection

- Fingerprint session context server-side at establishment (IP, User-Agent, Accept-Language, sec-ch-ua)
- Compare incoming requests to stored fingerprint
- **Risk-based responses:**
  - High risk: require re-authentication; rotate session ID
  - Medium risk: step-up verification; rotate session ID
  - Low risk: log suspicious activity
- Always regenerate session ID when potential hijacking detected

### Client-Side Storage

- Do not store session tokens in `localStorage`/`sessionStorage` (XSS risk)
- Prefer HttpOnly cookies
- If unavoidable, isolate via Web Workers

---

## 8. Data Storage & Database Security

### Backend Database Protection

- Isolate database servers from other systems
- Limit host connections
- Disable network (TCP) access when possible; use local socket files or named pipes
- Configure database to bind only on localhost when appropriate
- Restrict network port access with firewall rules
- Place database server in separate DMZ
- Never allow direct connections from thick clients

### Transport Layer Security

- Configure database to only allow encrypted connections
- Install trusted digital certificates
- Use TLSv1.2+ with modern ciphers (AES-GCM, ChaCha20)
- Verify digital certificate validity in client applications
- Ensure all database traffic is encrypted

### Secure Authentication

- Always require authentication, including from local connections
- Protect accounts with strong, unique passwords
- Use dedicated accounts per application or service
- Configure minimum required permissions only
- Regularly review accounts and permissions
- Remove accounts when applications decommissioned
- Change passwords when staff leave or compromise suspected

### Database Credential Storage

- Never store credentials in application source code
- Store credentials in configuration files outside web root
- Set appropriate file permissions
- Never check credential files into repositories
- Encrypt credential storage when available
- Use environment variables or secrets management solutions

### Secure Permission Management

- Apply principle of least privilege
- Do not use built-in root, sa, or SYS accounts
- Do not grant administrative rights to application accounts
- Restrict account connections to allowed hosts only
- Use separate databases and accounts for Dev, UAT, Production
- Grant only required permissions (SELECT, UPDATE, DELETE as needed)
- Avoid making accounts database owners
- Implement table-level, column-level, and row-level permissions when needed

### Database Hardening

- Install security updates and patches regularly
- Run database services under low-privileged user accounts
- Remove default accounts and sample databases
- Store transaction logs on separate disk
- Configure regular encrypted database backups with proper permissions
- Disable unnecessary stored procedures and dangerous features
- Implement database activity monitoring and alerting

### Platform-Specific Hardening

- **SQL Server:** Disable xp_cmdshell, CLR execution, SQL Browser service, Mixed Mode Authentication (unless required)
- **MySQL/MariaDB:** Run mysql_secure_installation, disable FILE privilege
- **PostgreSQL:** Follow PostgreSQL security documentation
- **MongoDB:** Implement MongoDB security checklist
- **Redis:** Follow Redis security guide

---

## 9. File Handling & Uploads

### Extension Validation

- List allowed extensions only for business-critical functionality
- Apply input validation before validating extensions
- Avoid double extensions (`.jpg.php`) and null byte injection (`.php%00.jpg`)
- Use allowlist approach rather than denylist
- Validate extensions after decoding filename

### Content Type and File Signature Validation

- Never trust client-supplied Content-Type headers
- Validate file signatures (magic numbers) in conjunction with Content-Type
- Implement allowlist approach for MIME types
- Use file signature validation but not as standalone measure

### Filename Security

- Generate random filenames (UUID/GUID) instead of using user-supplied names
- If user filenames required, implement maximum length limits
- Restrict characters to alphanumeric, hyphens, spaces, periods only
- Prevent leading periods (hidden files) and sequential periods (directory traversal)
- Avoid leading hyphens or spaces

### File Content Validation

- For images, apply image rewriting to destroy malicious content
- For Microsoft documents, use Apache POI for validation
- Avoid ZIP files due to numerous attack vectors
- Implement manual file review in sandboxed environments
- Integrate antivirus scanning and Content Disarm & Reconstruct (CDR)

### Storage Security

- Store files on different servers for complete segregation when possible
- Store files outside webroot with administrative access only
- If storing in webroot, set write-only permissions
- Use application handlers that map IDs to filenames for public access
- Consider database storage for specific use cases with DBA expertise

### Access Control and Authentication

- Require user authentication before allowing file uploads
- Implement proper authorization levels for file access and modification
- Set filesystem permissions on principle of least privilege
- Scan files before execution if execution permission required

### Upload and Download Limits

- Set proper file size limits
- Consider post-decompression size limits for compressed files
- Implement request limits for download services to prevent DoS
- Use secure methods to calculate ZIP file sizes

### Additional Security Measures

- Protect file upload endpoints from CSRF attacks
- Keep all file processing libraries updated
- Implement logging and monitoring for upload activities
- Provide user reporting mechanisms for illegal content
- Use secure extraction methods for compressed files

---

## 10. XML & Serialization Hardening

### XML Parser Hardening

- **Disable DTDs and external entities by default**
- Reject DOCTYPE declarations
- Validate strictly against local, trusted XSDs
- Set explicit limits (size, depth, element counts)
- Sandbox or block resolver access
- No network fetches during parsing
- Monitor for unexpected DNS activity

### Java XML Security

**General principle:**
```java
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

**DocumentBuilderFactory/SAXParserFactory/DOM4J:**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
String FEATURE = null;
try {
    // PRIMARY defense - disallow DTDs completely
    FEATURE = "http://apache.org/xml/features/disallow-doctype-decl";
    dbf.setFeature(FEATURE, true);
    dbf.setXIncludeAware(false);
} catch (ParserConfigurationException e) {
    logger.info("ParserConfigurationException was thrown. The feature '" + FEATURE
    + "' is not supported by your XML processor.");
}
```

**If DTDs cannot be completely disabled:**
```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
String[] featuresToDisable = {
    "http://xml.org/sax/features/external-general-entities",
    "http://xml.org/sax/features/external-parameter-entities",
    "http://apache.org/xml/features/nonvalidating/load-external-dtd"
};

for (String feature : featuresToDisable) {
    try {
        dbf.setFeature(feature, false);
    } catch (ParserConfigurationException e) {
        logger.info("ParserConfigurationException was thrown. The feature '" + feature
        + "' is probably not supported by your XML processor.");
    }
}
dbf.setXIncludeAware(false);
dbf.setExpandEntityReferences(false);
dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
```

### .NET XML Security

```csharp
var settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
var reader = XmlReader.Create(stream, settings);
```

### Python XML Security

```python
from defusedxml import ElementTree as ET
ET.parse('file.xml')
# or lxml
from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.parse('filename.xml', parser)
```

### Secure XSLT/Transformer Usage

- Set `ACCESS_EXTERNAL_DTD` and `ACCESS_EXTERNAL_STYLESHEET` to empty
- Avoid loading remote resources

### Deserialization Safety

- **Never deserialize untrusted native objects**
- Prefer JSON with schema validation
- Enforce size/structure limits before parsing
- Reject polymorphic types unless strictly allow-listed
- **Language specifics:**
  - PHP: avoid `unserialize()`; use `json_decode()`
  - Python: avoid `pickle` and unsafe YAML (`yaml.safe_load` only)
  - Java: override `ObjectInputStream#resolveClass` to allow-list; avoid enabling default typing in Jackson; use XStream allow-lists
  - .NET: avoid `BinaryFormatter`; prefer `DataContractSerializer` or `System.Text.Json` with `TypeNameHandling=None`
- Sign and verify serialized payloads
- Log and alert on deserialization failures and anomalies

---

## 11. Logging & Monitoring

### What to Log

- Authn/authz events
- Admin actions
- Config changes
- Sensitive data access
- Input validation failures
- Security errors
- Include: correlation/request IDs, user/session IDs (non-PII), source IP, user agent, timestamps (UTC, RFC3339)

### How to Log

- **Structured logs (JSON)** with stable field names
- Sanitize all log inputs to prevent log injection (strip CR/LF/delimiters)
- Validate data from other trust zones
- Redact/tokenize secrets and sensitive fields
- Never log credentials, tokens, recovery codes, or raw session IDs
- Ensure integrity: append-only or WORM storage; tamper detection; centralized aggregation

### Detection & Alerting

- Build alerts for:
  - Auth anomalies (credential stuffing patterns, impossible travel)
  - Privilege changes
  - Excessive failures
  - SSRF indicators
  - Data exfil patterns
- Tune thresholds
- Provide runbooks
- Ensure on-call coverage
- Test alert flows

### Storage & Protection

- Isolate log storage (separate partition/database)
- Strict file/directory permissions
- Store outside web-accessible locations
- Synchronize time across systems
- Use secure protocols for transmission
- Implement tamper detection and monitoring

### Privacy & Compliance

- Maintain data inventory and classification
- Minimize personal data in logs
- Honor retention and deletion policies
- Provide mechanisms to trace and delete user-linked log data where required

---

## 12. Framework & Language-Specific Guides

### Django

- Disable DEBUG in production
- Keep Django and dependencies updated
- Enable `SecurityMiddleware`, clickjacking middleware, MIME sniffing protection
- Force HTTPS (`SECURE_SSL_REDIRECT`); configure HSTS
- Set secure cookie flags (`SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`)
- **CSRF:** ensure `CsrfViewMiddleware` and `{% csrf_token %}` in forms
- **XSS:** rely on template auto-escaping; avoid `mark_safe` unless trusted; use `json_script` for JS
- **Auth:** use `django.contrib.auth`; validators in `AUTH_PASSWORD_VALIDATORS`
- **Secrets:** generate via `get_random_secret_key`; store in env/secrets manager

### Django REST Framework (DRF)

- Set `DEFAULT_AUTHENTICATION_CLASSES` and restrictive `DEFAULT_PERMISSION_CLASSES`
- Never leave `AllowAny` for protected endpoints
- Always call `self.check_object_permissions(request, obj)` for object-level authz
- **Serializers:** explicit `fields=[...]`; avoid `exclude` and `"__all__"`
- Enable throttling/rate limits
- Disable unsafe HTTP methods where not needed
- Avoid raw SQL; use ORM/parameters

### Laravel

- Production: `APP_DEBUG=false`; generate app key; secure file permissions
- Cookies/sessions: enable encryption middleware; set `http_only`, `same_site`, `secure`, short lifetimes
- **Mass assignment:** use `$request->only()` / `$request->validated()`; avoid `$request->all()`
- **SQLi:** use Eloquent parameterization; validate dynamic identifiers
- **XSS:** rely on Blade escaping; avoid `{!! ... !!}` for untrusted data
- **File uploads:** validate `file`, size, `mimes`; sanitize filenames with `basename`
- **CSRF:** ensure middleware and form tokens enabled

### Symfony

- **XSS:** Twig auto-escaping; avoid `|raw` unless trusted
- **CSRF:** use `csrf_token()` and `isCsrfTokenValid()` for manual flows
- **SQLi:** Doctrine parameterized queries; never concatenate inputs
- **Command execution:** avoid `exec/shell_exec`; use Filesystem component
- **Uploads:** validate with `#[File(...)]`; store outside public; unique names
- **Directory traversal:** validate `realpath`/`basename` and enforce allowed roots
- Configure secure cookies and authentication providers/firewalls

### Ruby on Rails

**Avoid dangerous functions:**
```ruby
eval("ruby code here")
system("os command here")
`ls -al /`  # backticks
exec("os command here")
spawn("os command here")
open("| os command here")
Process.exec("os command here")
Process.spawn("os command here")
IO.binread("| os command here")
IO.binwrite("| os command here", "foo")
IO.foreach("| os command here") {}
IO.popen("os command here")
IO.read("| os command here")
IO.readlines("| os command here")
IO.write("| os command here", "foo")
```

- **SQLi:** always parameterize; use `sanitize_sql_like` for LIKE patterns
- **XSS:** default auto-escape; avoid `raw`, `html_safe` on untrusted data; use `sanitize` allow-lists
- **Sessions:** database-backed store for sensitive apps; force HTTPS (`config.force_ssl = true`)
- **Auth:** use Devise or proven libraries
- **CSRF:** `protect_from_forgery` for state-changing actions
- Secure redirects: validate/allow-list targets
- Headers/CORS: set secure defaults; configure `rack-cors` carefully

### .NET (ASP.NET Core)

- Keep runtime and NuGet packages updated; enable SCA in CI
- **Authz:** use `[Authorize]` attributes; perform server-side checks; prevent IDOR
- **Authn/sessions:** ASP.NET Identity; lockouts; cookies `HttpOnly`/`Secure`; short timeouts
- **Crypto:** use PBKDF2 for passwords, AES-GCM for encryption; DPAPI for local secrets; TLS 1.2+
- **Injection:** parameterize SQL/LDAP; validate with allow-lists
- **Config:** enforce HTTPS redirects; remove version headers; set CSP/HSTS/X-Content-Type-Options
- **CSRF:** anti-forgery tokens on state-changing actions; validate on server

### Java and JAAS

- **SQL/JPA:** use `PreparedStatement`/named parameters; never concatenate input
- **XSS:** allow-list validation; sanitize output with reputable libs; encode for context
- **Logging:** parameterized logging to prevent log injection
- **Crypto:** AES-GCM; secure random nonces; never hardcode keys; use KMS/HSM
- **JAAS:** configure `LoginModule` stanzas; implement `initialize/login/commit/abort/logout`; avoid exposing credentials; segregate public/private credentials

### Node.js

- Limit request sizes
- Validate and sanitize input; escape output
- Avoid `eval`, `child_process.exec` with user input
- Use `helmet` for headers; `hpp` for parameter pollution
- Rate limit auth endpoints
- Monitor event loop health
- Handle uncaught exceptions cleanly
- **Cookies:** set `secure`, `httpOnly`, `sameSite`
- Set `NODE_ENV=production`
- Keep packages updated; run `npm audit`
- Use security linters and ReDoS testing

### PHP Configuration

**Production php.ini:**
- `expose_php=Off`
- Log errors not display
- Restrict `allow_url_fopen/include`
- Set `open_basedir`
- Disable dangerous functions
- Set session cookie flags (`Secure`, `HttpOnly`, `SameSite=Strict`)
- Enable strict session mode
- Constrain upload size/number
- Set resource limits (memory, post size, execution time)
- Use Snuffleupagus or similar for additional hardening

---

## 13. DevOps, CI/CD, and Containers

### CI/CD Pipeline Security

- **Repos:** protected branches; mandatory reviews; signed commits
- **Secrets:** never hardcode; fetch at runtime from vault/KMS; mask in logs
- **Least privilege:** ephemeral, isolated runners with minimal permissions
- **Security gates:** SAST, SCA, DAST, IaC scanning; block on criticals
- **Dependencies:** pin via lockfiles; verify integrity; use private registries
- **Sign everything:** commits and artifacts (containers/jars); verify prior to deploy; adopt SLSA provenance

### Docker and Container Hardening

- **User:** run as non-root; set `USER` in Dockerfile
- Use `--security-opt=no-new-privileges`
- **Capabilities:** `--cap-drop all` and add only what needed; never `--privileged`
- **Daemon socket:** never mount `/var/run/docker.sock`
- DO NOT enable TCP Docker daemon socket (`-H tcp://0.0.0.0:XXX`) without TLS
- Avoid `- "/var/run/docker.sock:/var/run/docker.sock"` in docker-compose
- **Filesystems:** read-only root, tmpfs for temp write; resource limits (CPU/mem)
- **Networks:** avoid host network; define custom networks; limit exposed ports
- **Images:** minimal base (distroless/alpine), pin tags and digests; remove package managers from final image; add `HEALTHCHECK`
- **Secrets:** Docker/Kubernetes secrets; never in layers/env; mount via runtime secrets
- **Scanning:** scan images on build and admission; block high-severity vulns

### Node.js in Containers

- **Deterministic builds:** `npm ci --omit=dev`; pin base image with digest
- **Production env:** `ENV NODE_ENV=production`
- **Non-root:** copy with correct ownership and drop to `USER node`
- **Signals:** use init (e.g., `dumb-init`) and implement graceful shutdown handlers
- **Multi-stage builds:** separate build and runtime; mount secrets via BuildKit; use `.dockerignore`

### Virtual Patching (Temporary Mitigation)

- Use WAF/IPS/ModSecurity for immediate protection when code fixes not yet possible
- Prefer positive security rules (allow-list) for accuracy
- **Process:** prepare tooling in advance; analyze CVEs; implement patches in log-only first, then enforce; track and retire after code fix

### C/C++ Toolchain Hardening

**Compiler:**
- `-Wall -Wextra -Wconversion`
- `-fstack-protector-all`
- PIE (`-fPIE`/`-pie`)
- `_FORTIFY_SOURCE=2`
- CFI (`-fsanitize=cfi` with LTO)

**Linker:**
- RELRO/now
- noexecstack
- NX/DEP and ASLR

**Debug vs Release:**
- Enable sanitizers in debug
- Enable hardening flags in release
- Assert in debug only

**CI checks:**
- Verify flags (`checksec`)
- Fail builds if protections missing

---

## 14. Cloud & Orchestration (Kubernetes)

### Identity & RBAC

- Least privilege for users and service accounts
- Separate namespaces
- Bind only needed roles

### Policy

- Admission controls (OPA/Gatekeeper/Kyverno)
- Enforce: image sources, capabilities, root, network policies, required labels/annotations

### Networking

- Default-deny with network policies
- Explicit egress allow-lists
- Service identity/mTLS within mesh where applicable

### Secrets

- Use KMS providers
- Avoid plaintext in manifests
- Rotate regularly
- Restrict secret mount paths

### Nodes

- Hardened OS, auto-updates, minimal attack surface
- Isolate sensitive workloads with taints/tolerations and dedicated nodes

### Supply Chain

- Verify image signatures
- Enforce provenance (SLSA/Sigstore) in admission

### Verification

- Cluster conformance and CIS benchmark scans
- Policy tests in CI for manifests (OPA unit tests)
- Periodic admission dry-run

### Incident Readiness

- Enable audit logs and centralize
- Restrict access to etcd
- Backup/restore tested
- Define break-glass roles with MFA and time-bound approvals

---

## 15. Infrastructure as Code (IaC) Security

### Network Security

- **ALWAYS** restrict access to remote administrative services, databases, LDAP, TACACS+, or other sensitive services
- Security Group and ACL inbound rules should **NEVER** allow `0.0.0.0/0` to:
  - Remote administration ports (SSH 22, RDP 3389)
  - Database ports (3306, 5432, 1433, 1521, 27017)
- Kubernetes API endpoints should **NEVER** allow `0.0.0.0/0`
- **NEVER** expose cloud platform database services to all IP addresses
- Generally prefer private networking (VPC, VNET, VPN)
- **ALWAYS** enable VPC/VNET flow logs
- **ALWAYS** implement default deny rules and explicit allow rules
- Generally prefer blocking egress traffic by default

### Data Protection

- **ALWAYS** configure data encryption at rest for all storage services
  - Cloud storage (S3, Azure Blob, GCS buckets)
  - Database encryption (RDS, Azure SQL, Cloud SQL, DocumentDB)
  - EBS/disk encryption for virtual machine storage
- **ALWAYS** configure encryption in transit
  - TLS 1.2 or higher for all HTTPS/API communications
  - SSL/TLS for database connections with certificate validation
  - Encryption for inter-service communication
  - Encrypted protocols for remote access
- **ALWAYS** implement data classification and protection controls
- **ALWAYS** configure secure data retention and disposal policies
- **ALWAYS** enable comprehensive data access monitoring and auditing
- **ALWAYS** encrypt data backups

### Access Control

- **NEVER** leave critical services with anonymous access unless public
- **NEVER** use wildcard permissions in IAM policies (`"Action": "*"`, `"Resource": "*"`)
- **NEVER** overprivilege service accounts with Owner/Admin roles
- **NEVER** use service API Keys and client secrets; use workload identity with RBAC
- **NEVER** enable or use legacy Instance Metadata Service version 1 (IMDSv1) in AWS
- **NEVER** use legacy authentication methods when more secure alternatives exist

### Container and VM Images

- **NEVER** use non-hardened VM and container images
- **ALWAYS** choose distroless or minimal container images
- **RECOMMEND** using secure baseline virtual machine images from trusted sources

### Logging and Administrative Access

- **NEVER** disable administrative activity logging for sensitive services
- **ALWAYS** enable audit logging for privileged operations

### Secrets Management

- **NEVER** hardcode secrets, passwords, API keys, or certificates in IaC source code
- **ALWAYS** in Terraform mark secrets with "sensitive = true"

### Backup and Data Recovery

- **NEVER** create backups without encryption at rest and in transit
- **ALWAYS** configure multi-region data storage for backups with cross-region replication
- **NEVER** configure backups without retention policies and lifecycle management

---

## 16. Supply Chain Security

### Policy and Governance

- Maintain allow-listed registries and scopes
- Disallow direct installs from untrusted sources
- Require lockfiles and version pinning
- Prefer digest pinning for images and vendored assets
- Generate SBOMs for apps/images; store with artifacts
- Attest provenance (SLSA, Sigstore)

### Package Hygiene (npm focus, applicable to others)

- Regularly audit (`npm audit`, ecosystem SCA) and patch
- Enforce SLAs by severity
- Use deterministic builds: `npm ci` (not `npm install`) in CI/CD
- Maintain lockfile consistency
- Avoid install scripts that execute on install when possible; review for risk
- Use `.npmrc` to scope private registries
- Avoid wildcard registries
- Enable integrity verification
- Enable account 2FA for publishing

### Development Practices

- Minimize dependency footprint
- Remove unused packages
- Prefer stdlib/first-party for trivial tasks
- Protect against typosquatting and protestware: pin maintainers, monitor releases, use provenance checks
- Hermetic builds: no network in compile/packaging stages unless required; cache with authenticity checks

### CI/CD Integration

- SCA, SAST, IaC scans in gates
- Fail on criticals
- Require approvals for overrides with compensating controls
- Sign artifacts; verify signatures at deploy
- Enforce policy in admission

### Vulnerability Management

**For patched vulnerabilities:**
- Test and deploy updates
- Document any API breaking changes

**For unpatched vulnerabilities:**
- Implement compensating controls (input validation, wrappers) based on CVE type
- Prefer direct dependency fixes over transitive workarounds
- Document risk decisions
- Escalate acceptance to appropriate authority with business justification

### Incident Response

- Maintain rapid rollback
- Isolate compromised packages
- Throttle rollouts
- Notify stakeholders
- Monitor threat intel feeds (e.g., npm advisories)
- Auto-open tickets for critical CVEs

---

## 17. Mobile Application Security

### Architecture and Design

- Follow least privilege and defense in depth
- Use standard secure authentication protocols (OAuth2, JWT)
- Perform all authentication and authorization checks server-side
- Request only necessary permissions
- Establish security controls for app updates, patches, releases
- Use only trusted and validated third-party libraries

### Authentication and Authorization

- Perform authentication/authorization server-side only
- Do not store user passwords on device; use revocable access tokens
- Avoid hardcoding credentials
- Encrypt credentials in transmission
- Use platform-specific secure storage (iOS Keychain, Android Keystore)
- Require password complexity; avoid short PINs
- Implement session timeouts and remote logout
- Require re-authentication for sensitive operations
- Use platform-supported biometric authentication with secure fallbacks

### Data Storage and Privacy

- Encrypt sensitive data using platform APIs; avoid custom encryption
- Leverage hardware-based security features (Secure Enclave, Strongbox)
- Store private data on device's internal storage only
- Minimize PII collection to necessity; implement automatic expiration
- Avoid caching, logging, or background snapshots of sensitive data
- Always use HTTPS for network communications

### Network Communication

- Use HTTPS for all network communication
- Do not override SSL certificate validation for self-signed certificates
- Use strong, industry standard cipher suites with appropriate key lengths
- Use certificates signed by trusted CA providers
- Consider certificate pinning
- Encrypt data even if sent over SSL
- Avoid sending sensitive data via SMS

### Code Quality and Integrity

- Use static analysis tools
- Make security focal point during code reviews
- Keep all libraries up to date
- Disable debugging in production builds
- Include code to validate integrity of application code
- Obfuscate the app binary
- **Implement runtime anti-tampering controls:**
  - Check for debugging, hooking, or code injection
  - Detect emulator or rooted/jailbroken devices
  - Verify app signatures at runtime

### Android Security

- Use Android's ProGuard for code obfuscation
- Avoid storing sensitive data in SharedPreferences
- Disable backup mode to prevent sensitive data in backups
- Use Android Keystore with hardware backing (TEE or StrongBox)
- Implement Google's Play Integrity API

### iOS Security

- Configure Shortcuts permissions to require device unlock for sensitive actions
- Set Siri intent `requiresUserAuthentication` to true for sensitive functionality
- Implement authentication checks on deep link endpoints
- Use conditional logic to mask sensitive widget content on lock screen
- Store sensitive data in iOS Keychain, not plist files
- Use Secure Enclave for cryptographic key storage
- Implement App Attest API for app integrity validation
- Use DeviceCheck API for persistent device state tracking

### Testing and Monitoring

- Perform penetration testing including cryptographic vulnerability assessment
- Leverage automated tests to ensure security features work
- Ensure security features do not harm usability
- Use real-time monitoring to detect and respond to threats
- Have clear incident response plan
- Plan for regular updates; implement forced update mechanisms when necessary

---

## 18. Privacy & Data Protection

- Implement strong cryptography
- Enforce HTTPS with HSTS
- Enable certificate pinning
- Provide user privacy features to protect data and anonymity
- Use strong, up-to-date cryptographic algorithms for data in transit and at rest
- Securely hash passwords with established libraries
- Enforce HTTPS exclusively; implement HSTS
- Implement certificate pinning to prevent man-in-the-middle attacks
- Minimize IP address leakage by blocking third-party external content loading where feasible
- Maintain transparency: inform users about privacy limitations and data handling policies
- Implement privacy-focused audit trails and access logging
- Return "Invalid username or password" to prevent account enumeration
- Use Argon2 or bcrypt with unique salts per user
- Store sessions server-side with cryptographically random IDs

---

## 19. Hardcoded Credentials Detection

### NEVER hardcode:

**Passwords and Authentication:**
- Database passwords, user passwords, admin passwords
- API keys, secret keys, access tokens, refresh tokens
- Private keys, certificates, signing keys
- Connection strings containing credentials
- OAuth client secrets, webhook secrets
- Any credentials for accessing external services

### Recognition Patterns

**Common Secret Formats:**
- **AWS Keys:** Start with `AKIA`, `AGPA`, `AIDA`, `AROA`, `AIPA`, `ANPA`, `ANVA`, `ASIA`
- **Stripe Keys:** Start with `sk_live_`, `pk_live_`, `sk_test_`, `pk_test_`
- **Google API:** Start with `AIza` followed by 35 characters
- **GitHub Tokens:** Start with `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`
- **JWT Tokens:** Three base64 sections separated by dots, starts with `eyJ`
- **Private Key Blocks:** Text between `-----BEGIN` and `-----END PRIVATE KEY-----`
- **Connection Strings:** URLs with credentials like `mongodb://user:pass@host`

**Warning Signs:**
- Variable names containing: `password`, `secret`, `key`, `token`, `auth`
- Long random-looking strings
- Base64 encoded strings near authentication code
- Any string that grants access to external services

---

## 20. Digital Certificate Security

### How to Identify Certificate Data

- **PEM-Encoded Strings:** Begin with `-----BEGIN CERTIFICATE-----` and end with `-----END CERTIFICATE-----`
- **File Operations:** Files with extensions `.pem`, `.crt`, `.cer`, `.der`
- **Library Function Calls:** OpenSSL's `PEM_read_X509`, Python's `cryptography.x509.load_pem_x509_certificate`, Java's `CertificateFactory`

### Mandatory Sanity Checks

**Check 1: Expiration Status**
- **CRITICAL:** Certificate's `notAfter` date is before current date
- **Report:** Certificate expired on [YYYY-MM-DD]. Must be renewed and replaced immediately.
- **Warning:** Certificate's `notBefore` date is after current date
- **Report:** Certificate not yet valid. Validity period begins on [YYYY-MM-DD].

**Check 2: Public Key Strength**
- **Weak Keys:**
  - RSA keys with modulus < 2048 bits
  - EC keys using curves < 256-bit prime (e.g., secp192r1, P-192, P-224)
- **Report:** Certificate's public key is cryptographically weak. Should be re-issued using at least RSA 2048-bit or ECDSA P-256+.

**Check 3: Signature Algorithm**
- **Insecure Algorithms:** Any signature using MD5 or SHA-1
- **Report:** Certificate signed with insecure algorithm. Vulnerable to collision attacks. Must be re-issued using SHA-2 family (e.g., sha256WithRSAEncryption).

**Check 4: Issuer Type (Self-Signed)**
- **Condition:** Certificate's `Issuer` and `Subject` fields are identical
- **Report:** This is a self-signed certificate. Ensure intentional and only used for development, testing, or internal services. Never for public-facing production systems.

---

## 21. Safe C/C++ Functions

### Insecure Functions to Avoid & Secure Alternatives

**NEVER use `gets()`**
- **Critical security risk:** No bounds checking
- **Replace with:** `fgets(char *str, int n, FILE *stream)`

**Avoid `strcpy()`**
- **High risk:** No bounds checking
- **Replace with:** `snprintf()`, `strncpy()` (with careful handling), or `strcpy_s()` (C11 Annex K)

**Don't use `strcat()`**
- **High risk:** No bounds checking
- **Replace with:** `snprintf()`, `strncat()` (with careful handling), or `strcat_s()` (C11 Annex K)

**Replace `sprintf()` and `vsprintf()`**
- **High risk:** No bounds checking on output buffer
- **Replace with:** `snprintf()`, `snwprintf()`, or `vsprintf_s()` (C11 Annex K)

**Be careful with `scanf()` family**
- **Medium risk:** `%s` without width limit can cause buffer overflows
- **Use:** Width specifiers like `scanf("%127s", buffer)` or better: `fgets()` then `sscanf()`

**Avoid `strtok()`**
- **Medium risk:** Not reentrant or thread-safe
- **Replace with:** `strtok_r()` (POSIX) or `strtok_s()` (C11 Annex K)

**Use `memcpy()` and `memmove()` carefully**
- Not inherently insecure, but common source of bugs
- Double-check size calculations
- Prefer `memcpy_s()` (C11 Annex K) when available
- Use `memmove()` if buffers might overlap

### Banned Memory Functions

**Use safe variants:**
- `memcpy()` → Use `memcpy_s()`
- `memset()` → Use `memset_s()`
- `memmove()` → Use `memmove_s()`
- `memcmp()` → Use `memcmp_s()`
- `bzero()` → Use `memset_s()`
- `memzero()` → Use `memset_s()`

**Safe Memory Function Pattern:**
```c
// Instead of: memcpy(dest, src, count);
errno_t result = memcpy_s(dest, dest_size, src, count);
if (result != 0) {
    // Handle error
}
```

### Banned String Functions

**Use safe variants:**
- `strstr()` → Use `strstr_s()`
- `strtok()` → Use `strtok_s()`
- `strcpy()` → Use `strcpy_s()`
- `strcmp()` → Use `strcmp_s()`
- `strlen()` → Use `strnlen_s()`
- `strcat()` → Use `strcat_s()`
- `sprintf()` → Use `snprintf()`

**Safe String Copy Pattern:**
```c
// Bad - unsafe
char dest[256];
strcpy(dest, src); // Buffer overflow risk!

// Good - safe
char dest[256];
errno_t result = strcpy_s(dest, sizeof(dest), src);
if (result != 0) {
    EWLC_LOG_ERROR("String copy failed: %d", result);
    return ERROR;
}
```

### Compiler Flags for Protection

Enable these protective compiler flags:
- **Stack Protection:** `-fstack-protector-all` or `-fstack-protector-strong`
- **Address Sanitizer:** `-fsanitize=address` during development
- **Object Size Checking:** `-D_FORTIFY_SOURCE=2`
- **Format String Protection:** `-Wformat -Wformat-security`

### Common Pitfalls

**Pitfall 1: Wrong Size Parameter**
```c
// Wrong
strcpy_s(dest, strlen(src), src); // WRONG!

// Correct
strcpy_s(dest, sizeof(dest), src); // CORRECT
```

**Pitfall 2: Ignoring Return Values**
```c
// Wrong
strcpy_s(dest, sizeof(dest), src); // Error not checked

// Correct
if (strcpy_s(dest, sizeof(dest), src) != 0) {
    // Handle error appropriately
}
```

**Pitfall 3: Using sizeof() on Pointers**
```c
// Wrong
void func(char *buffer) {
    strcpy_s(buffer, sizeof(buffer), src); // sizeof(char*) = 8!
}

// Correct
void func(char *buffer, size_t buffer_size) {
    strcpy_s(buffer, buffer_size, src);
}
```

---

## Code Review Checklist Summary

### Cryptography
- [ ] No banned algorithms (MD5, DES, RC4, SHA-1, etc.)
- [ ] No deprecated SSL/crypto APIs used
- [ ] HMAC uses SHA-256 or stronger
- [ ] All crypto operations use EVP high-level APIs
- [ ] Proper error handling for all crypto operations
- [ ] Key material properly zeroed after use

### Authentication & Authorization
- [ ] Passwords hashed with Argon2id/scrypt/bcrypt (not encrypted)
- [ ] MFA implemented for sensitive operations
- [ ] Authorization checked on every request
- [ ] No IDOR vulnerabilities
- [ ] No mass assignment vulnerabilities
- [ ] Session IDs generated with CSPRNG

### Input Validation
- [ ] 100% parameterization coverage for SQL
- [ ] No string concatenation in queries/commands
- [ ] LDAP DN/filter escaping in use
- [ ] No shell invocation with untrusted input
- [ ] Prototype pollution protections (JavaScript)
- [ ] File uploads validated by content, size, extension

### Client-Side Security
- [ ] Context-aware XSS prevention
- [ ] Strict CSP with nonces/Trusted Types
- [ ] CSRF tokens on all state-changing requests
- [ ] Frame protections set
- [ ] XS-Leak mitigations enabled
- [ ] Third-party JS isolated with SRI

### API & Web Services
- [ ] HTTPS/mTLS configured
- [ ] Contract validation at edge and service
- [ ] Strong authn/z per endpoint
- [ ] SSRF protections in place
- [ ] Rate limiting and circuit breakers active
- [ ] Management endpoints isolated

### Infrastructure & Containers
- [ ] No `0.0.0.0/0` access to sensitive services
- [ ] Encryption at rest and in transit
- [ ] No hardcoded secrets in IaC
- [ ] Containers run as non-root
- [ ] No Docker daemon socket mounts
- [ ] Images scanned and signed

### Dependencies & Supply Chain
- [ ] Lockfiles present and used
- [ ] SBOM + provenance stored
- [ ] Automated dependency updates
- [ ] High-sev vulns remediated within SLA
- [ ] Signatures verified pre-deploy

### Mobile Apps
- [ ] Server-side authentication/authorization only
- [ ] Sensitive data encrypted using platform APIs
- [ ] HTTPS for all network communication
- [ ] No hardcoded credentials
- [ ] Runtime integrity checks implemented
- [ ] Platform-specific secure storage used

### C/C++ Safety
- [ ] No unsafe memory functions (memcpy, memset, etc.)
- [ ] No unsafe string functions (strcpy, strcat, sprintf, etc.)
- [ ] All operations use `*_s()` variants
- [ ] Buffer sizes correctly calculated
- [ ] Hardening compiler flags enabled

### Certificates
- [ ] No expired certificates
- [ ] No weak public keys (< 2048-bit RSA, < 256-bit EC)
- [ ] No insecure signature algorithms (MD5, SHA-1)
- [ ] Self-signed certificates only for development/testing

### Credentials
- [ ] No hardcoded passwords, API keys, tokens
- [ ] No AWS/Stripe/GitHub/Google API keys in code
- [ ] No private keys in source
- [ ] Connection strings use secrets management

---

**This comprehensive security review guide consolidates best practices from 22 security domains. Use it during code review to identify vulnerabilities across authentication, authorization, cryptography, input validation, API security, infrastructure, and more.**
