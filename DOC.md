

# 📚 Complete Domain Reconnaissance Report - Deep Dive

I'll explain **every single field** and its cybersecurity significance.

---

# 🏷️ SECTION 1: metadata

```json
"metadata": {
  "scan_type": "domain_reconnaissance",
  "scan_timestamp": "2025-12-27T15:14:08.143126",
  "target_domain": "devergolabs.com",
  "anonymous_mode": false,
  "bruteforce_mode": false,
  "modules_executed": ["whois", "subdomain_discovery", "dns_resolution"]
}
```

| Field | Value | Cybersecurity Meaning |
|-------|-------|----------------------|
| `scan_type` | `domain_reconnaissance` | Type of scan performed - passive intel gathering |
| `scan_timestamp` | `2025-12-27T15:14:08` | When scan ran (useful for version control) |
| `target_domain` | `devergolabs.com` | The domain you analyzed |
| `anonymous_mode` | `false` | ⚠️ You scanned with YOUR REAL IP - target could detect/log you |
| `bruteforce_mode` | `false` | Didn't try to guess subdomains (safer, less aggressive) |
| `modules_executed` | `[whois, subdomain_discovery, dns_resolution]` | What tools ran |

---

# 🏢 SECTION 2: whois

WHOIS tells you **who owns the domain** and **registration details**.

```json
"whois": {
  "domain_name": "DEVERGOLABS.COM",
  "registrar": "Amazon Registrar, Inc.",
  ...
}
```

| Field | Value | Cybersecurity Meaning |
|-------|-------|----------------------|
| `domain_name` | `DEVERGOLABS.COM` | The registered domain (uppercase is normal) |
| `registrar` | `Amazon Registrar, Inc.` | Domain bought through Amazon → owner likely uses AWS |
| `registrar_url` | `registrar.amazon.com` | Where domain was purchased |
| `reseller` | `null` | No reseller involved (direct purchase) |
| `whois_server` | `whois.registrar.amazon` | Server that holds WHOIS data |
| `referral_url` | `null` | No referral URL |

### **Important Dates:**

| Field | Value | Cybersecurity Meaning |
|-------|-------|----------------------|
| `creation_date` | `2024-09-18` | Domain is ~1 year old (relatively new) |
| `updated_date` | `2025-08-14` | Last modified ~4 months ago |
| `expiration_date` | `2026-09-18` | Domain valid for another ~2 years |

⚠️ **Security Note**: Attackers often target domains near expiration to hijack them when they lapse.

### **Name Servers:**

```json
"name_servers": [
  "NS-1479.AWSDNS-56.ORG",
  "NS-1830.AWSDNS-36.CO.UK",
  "NS-449.AWSDNS-56.COM",
  "NS-963.AWSDNS-56.NET"
]
```

| What This Means |
|-----------------|
| **All 4 name servers are AWS Route 53** |
| Using 4 different TLDs (.org, .co.uk, .com, .net) for redundancy |
| This is professional, enterprise-grade DNS setup |

### **Domain Status:**

| Field | Value | Cybersecurity Meaning |
|-------|-------|----------------------|
| `status` | `ok` | Domain is active and healthy (no locks/pending transfers) |
| `dnssec` | `unsigned` | ⚠️ DNSSEC not enabled - vulnerable to DNS spoofing attacks |

### **Privacy Protection (All null):**

```json
"name": null,
"org": null,
"address": null,
"city": null,
...
```

| What This Means |
|-----------------|
| ✅ Owner uses **WHOIS privacy protection** |
| Can't see real owner name, address, phone |
| `emails: trustandsafety@support.aws.com` is AWS's generic contact |
| This is good security practice (prevents social engineering) |

---

# 🌐 SECTION 3: subdomains

```json
"subdomains": ["www.devergolabs.com"],
"subdomain_count": 1
```

| Field | Value | Cybersecurity Meaning |
|-------|-------|----------------------|
| `subdomains` | `["www.devergolabs.com"]` | Only 1 subdomain found (very clean attack surface) |
| `subdomain_count` | `1` | Minimal exposure |

⚠️ **Security Note**: More subdomains = bigger attack surface. Some companies have 100s of forgotten subdomains with outdated software. Having only 1 is excellent.

---

# 📡 SECTION 4: dns

DNS records tell you **where traffic goes** and **what services exist**.

## 4.1 Root Domain DNS (devergolabs.com)

### **A Records (IPv4 Addresses):**

```json
"A": ["18.102.191.166", "15.160.30.163", "15.161.171.153"]
```

| What This Means |
|-----------------|
| Domain points to **3 different IP addresses** |
| This is a **load balancer** setup - traffic distributed across 3 servers |
| All IPs are AWS (15.x.x.x and 18.x.x.x are AWS Milan region) |

### **AAAA Records (IPv6):**

```json
"AAAA": null
```

| What This Means |
|-----------------|
| No IPv6 addresses configured |
| ⚠️ Minor security note: Some attack vectors only work on one protocol |

### **MX Records (Email):**

```json
"MX": null
```

| What This Means |
|-----------------|
| **No email server configured for this domain** |
| Can't send/receive email @devergolabs.com (or using external service not in DNS) |
| ✅ Reduces attack surface (no email = no phishing target for this domain) |

### **NS Records (Name Servers):**

```json
"NS": [
  "ns-1830.awsdns-36.co.uk.",
  "ns-1479.awsdns-56.org.",
  "ns-963.awsdns-56.net.",
  "ns-449.awsdns-56.com."
]
```

| What This Means |
|-----------------|
| AWS Route 53 manages DNS |
| 4 name servers across different TLDs for redundancy |
| If one fails, others take over |

### **TXT Records:**

```json
"TXT": null
```

| What This Means |
|-----------------|
| No TXT records (no SPF, DKIM, DMARC for email) |
| Since there's no MX record, this is expected |
| If they HAD email, missing TXT = ⚠️ vulnerable to email spoofing |

### **SOA Record (Start of Authority):**

```json
"SOA": ["ns-1479.awsdns-56.org. awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400"]
```

Breaking this down:
| Part | Value | Meaning |
|------|-------|---------|
| Primary NS | `ns-1479.awsdns-56.org` | Master name server |
| Admin Email | `awsdns-hostmaster.amazon.com` | Admin contact (@ replaced with .) |
| Serial | `1` | Version number of zone file |
| Refresh | `7200` | Slaves refresh every 2 hours |
| Retry | `900` | Retry every 15 min if refresh fails |
| Expire | `1209600` | Zone expires after 14 days |
| Min TTL | `86400` | Cache negative results for 1 day |

### **CNAME Record:**

```json
"CNAME": null
```

| What This Means |
|-----------------|
| Root domain doesn't alias to another name |
| Uses direct A records (normal for root domains) |

---

# 🔍 SECTION 5: nmap (Port Scanning)

## 5.1 Scan Metadata

```json
"scan_type": "thorough",
"scanner_version": [7, 94],
"ip_arguments": "-T3 -A --top-ports 1000 -sV ..."
```

| Field | Value | Meaning |
|-------|-------|---------|
| `scan_type` | `thorough` | Deep scan with OS detection |
| `scanner_version` | `7.94` | Nmap version used |
| `total_ips` | `3` | Scanned 3 IP addresses |
| `total_hostnames` | `1` | Scanned 1 hostname |

### **Arguments Breakdown:**

| Argument | Purpose |
|----------|---------|
| `-T3` | Normal timing (not too aggressive) |
| `-A` | Enable OS detection + scripts |
| `--top-ports 1000` | Scan 1000 most common ports |
| `-sV` | Detect service versions |
| `-O` | OS fingerprinting |
| `--script=default,banner,http-title,ssl-cert` | Run these detection scripts |
| `-Pn` | Skip ping, assume host is up |
| `--open` | Only show open ports |

---

## 5.2 IP Scan Results: 15.160.30.163

### **Host Identification:**

| Field | Value | Meaning |
|-------|-------|---------|
| `status` | `up` | Server is responding |
| `hostnames.name` | `ec2-15-160-30-163.eu-south-1.compute.amazonaws.com` | AWS EC2 in Milan |
| `hostnames.type` | `PTR` | Reverse DNS lookup result |

### **OS Detection:**

```json
"os_detection": [{
  "name": "Linux 2.6.32 - 3.13",
  "accuracy": "87",
  "os_family": "Linux"
}]
```

| Field | Meaning |
|-------|---------|
| `name` | OS guess: Linux kernel 2.6-3.13 (likely inaccurate due to firewall) |
| `accuracy` | 87% confident - not 100% certain |
| `os_family` | Definitely Linux-based |

⚠️ **Note**: Load balancers often mask the real OS, making detection unreliable.

---

### **Port 80 (HTTP):**

```json
{
  "port": 80,
  "state": "open",
  "service": "http",
  "product": "",  // Empty - hidden by load balancer
  "scripts": {
    "http-title": "Did not follow redirect to https://...",
    "fingerprint-strings": "...301 Moved Permanently...Server: awselb/2.0..."
  }
}
```

| Field | Value | Cybersecurity Meaning |
|-------|-------|----------------------|
| `port` | `80` | Standard HTTP port |
| `state` | `open` | Port is accessible from internet |
| `service` | `http` | Web server |
| `product` | `""` | Product hidden (security through obscurity) |

**Scripts Analysis:**

| Script | Finding | Security Implication |
|--------|---------|---------------------|
| `http-title` | Redirects to HTTPS | ✅ Good - forces encryption |
| `fingerprint-strings` | `Server: awselb/2.0` | AWS Elastic Load Balancer detected |
| `301 Moved Permanently` | Permanent redirect to HTTPS | ✅ Good - proper redirect |

---

### **Port 443 (HTTPS):**

```json
{
  "port": 443,
  "state": "open",
  "service": "http",
  "product": "nginx",
  "version": "1.18.0",
  "extrainfo": "Ubuntu",
  "cpe": "cpe:/o:linux:linux_kernel",
  "scripts": {
    "ssl-cert": "Subject: commonName=www.devergolabs.com\n...Not valid after: 2026-09-17",
    "ssl-date": "TLS randomness does not represent time",
    "http-title": "Devergo labs"
  }
}
```

| Field | Value | Cybersecurity Meaning |
|-------|-------|----------------------|
| `product` | `nginx` | Web server software |
| `version` | `1.18.0` | ⚠️ Version exposed - attackers can search for CVEs |
| `extrainfo` | `Ubuntu` | Operating system leaked |
| `cpe` | `cpe:/o:linux:linux_kernel` | Standard identifier for vulnerability databases |

**SSL Certificate Analysis:**

| Detail | Value | Meaning |
|--------|-------|---------|
| `commonName` | `www.devergolabs.com` | Certificate is for this domain |
| `Not valid after` | `2026-09-17` | ✅ Valid for ~2 more years |
| `ssl-date` | "TLS randomness does not represent time" | ✅ Good - server doesn't leak time in TLS |

---

## 5.3 Special Finding: "tcpwrapped"

```json
{
  "port": 80,
  "service": "tcpwrapped",
  ...
}
```

| What `tcpwrapped` Means |
|-------------------------|
| Server accepted connection but **immediately closed it** |
| This happens when: load balancer blocks the probe, OR firewall resets connection |
| Nmap couldn't determine what service is running |
| ✅ This is actually **good security** - server is hiding information |

---

## 5.4 Summary Stats

```json
"summary": {
  "ips_scanned": 3,
  "ips_up": 3,
  "hostnames_scanned": 1,
  "hostnames_up": 1,
  "total_tcp_ports": 6,
  "total_udp_ports": 0
}
```

| Field | Value | Meaning |
|-------|-------|---------|
| `ips_scanned` | 3 | Scanned all 3 IPs |
| `ips_up` | 3 | All 3 are online |
| `total_tcp_ports` | 6 | Found 6 open TCP ports (80+443 on 3 servers) |
| `total_udp_ports` | 0 | No open UDP ports found |

---

# 🏆 OVERALL SECURITY ASSESSMENT

| Category | Finding | Rating |
|----------|---------|--------|
| **Infrastructure** | AWS Load Balancer + 3 EC2 instances | ✅ Professional |
| **HTTPS** | Forces HTTPS, valid cert until 2026 | ✅ Excellent |
| **Attack Surface** | Only 1 subdomain, 2 ports open | ✅ Minimal |
| **WHOIS Privacy** | Owner info hidden | ✅ Good |
| **Version Exposure** | nginx/1.18.0 visible | ⚠️ Minor risk |
| **DNSSEC** | Not enabled | ⚠️ DNS spoofing possible |
| **Email Security** | No MX records | ✅ (N/A - no email) |

**Overall: This is a well-secured, professionally-hosted website on AWS.**