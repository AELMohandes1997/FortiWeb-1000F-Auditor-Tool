# FortiWeb 1000F — Configuration Review Benchmark
# Based on: Fortinet FortiWeb 6.x/7.x Official Hardening Guide + CIS Framework Principles
# Version: 1.0 | Scope: Full Configuration Audit

---

## SECTION 1 — SYSTEM HARDENING

### 1.1 Admin & Authentication
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 1.1.1  | Default admin account renamed                | No account named 'admin' should exist               | CRITICAL  | config system admin |
| 1.1.2  | Admin password complexity enforced           | min-length >= 8, must include upper/lower/num/special | HIGH    | config system password-policy |
| 1.1.3  | Password minimum length                      | >= 8 characters                                     | HIGH      | config system password-policy |
| 1.1.4  | Password expiry configured                   | expire-day <= 90                                    | MEDIUM    | config system password-policy |
| 1.1.5  | Account lockout after failed attempts        | lockout-threshold <= 5                              | HIGH      | config system password-policy |
| 1.1.6  | Lockout duration configured                  | lockout-duration >= 300 (5 min)                     | MEDIUM    | config system password-policy |
| 1.1.7  | Two-factor authentication enabled            | two-factor = enable (for all admin accounts)        | HIGH      | config system admin |
| 1.1.8  | Idle session timeout configured              | idle-timeout <= 300 (5 min)                         | MEDIUM    | config system global |
| 1.1.9  | Admin access restricted to trusted hosts     | trusthost1/trusthost2/trusthost3 defined            | CRITICAL  | config system admin |
| 1.1.10 | No wildcard trusted host (0.0.0.0/0)        | No admin with trusthost = 0.0.0.0 0.0.0.0          | CRITICAL  | config system admin |
| 1.1.11 | Admin profile least privilege enforced       | No non-super-admin with accprofile = super_admin    | HIGH      | config system admin |
| 1.1.12 | Guest/maintenance accounts disabled          | No unused/default accounts present                  | HIGH      | config system admin |

### 1.2 Management Access
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 1.2.1  | HTTPS only for admin access                  | admin-https = enable, admin-http = disable          | CRITICAL  | config system global |
| 1.2.2  | HTTP management access disabled              | admin-http = disable                                | CRITICAL  | config system global |
| 1.2.3  | SSH admin access restricted or disabled      | admin-ssh = disable OR restricted to mgmt VLAN      | HIGH      | config system global |
| 1.2.4  | Telnet management disabled                   | admin-telnet = disable                              | CRITICAL  | config system global |
| 1.2.5  | SNMP v1/v2 disabled                          | No snmp community with version v1 or v2             | HIGH      | config system snmp community |
| 1.2.6  | SNMP v3 used with auth+privacy               | version = v3, auth-pwd set, priv-pwd set            | HIGH      | config system snmp user |
| 1.2.7  | SNMP community string not default            | Not 'public' or 'private'                          | CRITICAL  | config system snmp community |
| 1.2.8  | Management port changed from default         | admin-port != 443 (default) and admin-sport != 80   | MEDIUM    | config system global |
| 1.2.9  | Management interface isolated                | Management on dedicated interface/VLAN              | HIGH      | config system interface |
| 1.2.10 | SSH strong ciphers only                      | No weak ciphers (3DES, RC4, arcfour)               | HIGH      | config system global |

### 1.3 System & Time
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 1.3.1  | NTP server configured                        | ntpsync = enable, server defined                    | HIGH      | config system ntp |
| 1.3.2  | NTP authentication enabled                   | ntpauth = enable where supported                    | MEDIUM    | config system ntp |
| 1.3.3  | Correct timezone set                         | timezone = correct for deployment region            | MEDIUM    | config system global |
| 1.3.4  | Hostname configured (not default)            | hostname != FortiWeb                                | LOW       | config system global |
| 1.3.5  | Firmware up to date                          | Version >= latest stable release for 1000F          | HIGH      | get system status |
| 1.3.6  | FortiGuard license active                    | All FortiGuard services licensed and updated        | HIGH      | get system fortiguard-service status |

---

## SECTION 2 — NETWORK & INTERFACE HARDENING

### 2.1 Interface Configuration
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 2.1.1  | Unused interfaces administratively disabled  | type = physical, status = down for unused ports     | MEDIUM    | config system interface |
| 2.1.2  | Management interface separate from data      | Dedicated mgmt port or VLAN                         | HIGH      | config system interface |
| 2.1.3  | Interface IP not in routable public space unnecessarily | RFC1918 for internal interfaces             | MEDIUM    | config system interface |
| 2.1.4  | No interfaces configured with /32 default route unnecessarily | Route table reviewed                   | LOW       | config router static |
| 2.1.5  | VLAN tagging configured where required       | vlanid set correctly per network design             | MEDIUM    | config system interface |

### 2.2 Routing
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 2.2.1  | Default route defined and correct            | Single default route to correct gateway             | HIGH      | config router static |
| 2.2.2  | No unnecessary static routes                 | Only required routes present                        | MEDIUM    | config router static |
| 2.2.3  | Route leaking between security zones absent  | Internal/external routing not mixed without policy  | HIGH      | config router static |

---

## SECTION 3 — LOGGING & ALERTING

### 3.1 Logging Configuration
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 3.1.1  | Syslog server configured                     | At least one syslog server defined                  | CRITICAL  | config log syslogd setting |
| 3.1.2  | Syslog logging enabled                       | status = enable                                     | CRITICAL  | config log syslogd setting |
| 3.1.3  | Syslog level set appropriately               | severity <= information (capture all events)        | HIGH      | config log syslogd setting |
| 3.1.4  | Log all attack events                        | attack-log = enable in server policies              | CRITICAL  | config waf http-protocol-parameter-restriction |
| 3.1.5  | Traffic logging enabled                      | traffic-log = enable                                | HIGH      | config log traffic |
| 3.1.6  | Event logging enabled                        | event-log = enable                                  | HIGH      | config log eventfilter |
| 3.1.7  | Log disk usage alert configured              | disk-full = overwrite or alert threshold set        | MEDIUM    | config system global |
| 3.1.8  | Log timestamp in UTC or consistent timezone  | Matches NTP timezone setting                        | MEDIUM    | config system global |
| 3.1.9  | FortiAnalyzer integration configured (if applicable) | server IP, status = enable               | MEDIUM    | config log fortianalyzer setting |
| 3.1.10 | Log reliable transmission (TCP syslog)       | mode = reliable (not UDP) for critical logs         | MEDIUM    | config log syslogd setting |

### 3.2 Alerting
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 3.2.1  | Email alerting configured                    | SMTP server defined, alert-email set                | HIGH      | config system alertemail |
| 3.2.2  | Alert on critical severity events            | Threshold = alert or emergency                      | HIGH      | config system alertemail |
| 3.2.3  | SNMP traps configured for critical events    | trap-receivers defined, events mapped               | MEDIUM    | config system snmp sysinfo |

---

## SECTION 4 — WAF POLICY CONFIGURATION

### 4.1 Server Policy
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 4.1.1  | All server policies have WAF profile applied | waf-profile set in every server policy              | CRITICAL  | config server-policy policy |
| 4.1.2  | Server policy in enforcement mode (not monitor) | action = alert_deny or block (not alert-only)    | CRITICAL  | config server-policy policy |
| 4.1.3  | Client real IP configured                    | client-real-ip = enable where X-Forwarded-For used  | HIGH      | config server-policy policy |
| 4.1.4  | HTTP/HTTPS redirect configured               | http-to-https = enable for all HTTPS policies       | HIGH      | config server-policy policy |
| 4.1.5  | Half-open connection threshold set           | half-open-threshold defined                         | MEDIUM    | config server-policy policy |
| 4.1.6  | Server policy references correct VIP         | vip defined and matches real server                 | HIGH      | config server-policy policy |
| 4.1.7  | Persistence (session affinity) configured correctly | persistence-policy set if stateful app        | MEDIUM    | config server-policy policy |
| 4.1.8  | Connection limit configured                  | max-http-conn-per-ip, max-http-request set          | HIGH      | config server-policy policy |
| 4.1.9  | Certificate verification for backend         | ssl-server-check = enable for HTTPS backends        | HIGH      | config server-policy policy |
| 4.1.10 | Intermediate certificate deployed            | Full chain present in server certificate profile    | MEDIUM    | config server-policy server-pool |

### 4.2 WAF Profile Completeness
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 4.2.1  | SQL Injection protection enabled             | sql-injection-detection = enable                    | CRITICAL  | config waf signature |
| 4.2.2  | XSS protection enabled                       | xss-detection = enable                              | CRITICAL  | config waf signature |
| 4.2.3  | Command injection protection enabled         | cmd-injection-detection = enable                    | CRITICAL  | config waf signature |
| 4.2.4  | File inclusion protection enabled            | file-inclusion-detection = enable                   | CRITICAL  | config waf signature |
| 4.2.5  | CSRF protection enabled                      | csrf = enable in inline-protection or web-protection-profile | HIGH | config waf csrf-protection |
| 4.2.6  | HTTP protocol enforcement enabled            | http-protocol-parameter-restriction applied         | HIGH      | config waf http-protocol-parameter-restriction |
| 4.2.7  | Bot detection enabled                        | bot-detection-policy applied                        | HIGH      | config waf bot-detection-policy |
| 4.2.8  | Signature auto-update enabled                | FortiGuard signature auto-update = enable           | CRITICAL  | config waf signature |
| 4.2.9  | Custom signatures defined for app-specific threats | At least one custom signature group defined   | MEDIUM    | config waf custom-signature |
| 4.2.10 | Web scraping protection configured           | web-scraping-policy applied                         | MEDIUM    | config waf web-scraping-policy |
| 4.2.11 | Signature exceptions reviewed                | exceptions list not overly permissive               | HIGH      | config waf signature-exception |
| 4.2.12 | FortiWeb in reverse proxy mode (preferred)   | operation-mode = reverse-proxy                      | HIGH      | config system global (or mode config) |

### 4.3 HTTP Protocol Parameter Restrictions
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 4.3.1  | Max HTTP header length restricted            | max-http-header-length <= 8192                      | HIGH      | config waf http-protocol-parameter-restriction |
| 4.3.2  | Max URL length restricted                    | max-url-param-length <= 2048                        | HIGH      | config waf http-protocol-parameter-restriction |
| 4.3.3  | Max body size restricted                     | max-body-length configured and reasonable           | HIGH      | config waf http-protocol-parameter-restriction |
| 4.3.4  | Illegal HTTP methods blocked                 | method-policy restricts to GET/POST/HEAD only (or as needed) | HIGH | config waf http-method-policy |
| 4.3.5  | HTTP version enforcement                     | HTTP/0.9 and HTTP/1.0 blocked if not required       | MEDIUM    | config waf http-protocol-parameter-restriction |
| 4.3.6  | Redundant HTTP headers blocked               | Duplicate headers rejected                          | MEDIUM    | config waf http-protocol-parameter-restriction |

---

## SECTION 5 — SSL/TLS CONFIGURATION

### 5.1 Certificate Management
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 5.1.1  | Valid CA-signed certificate deployed         | No self-signed certs on production listener         | HIGH      | config system certificate local |
| 5.1.2  | Certificate expiry > 30 days                 | Cert not expiring within 30 days                    | HIGH      | config system certificate local |
| 5.1.3  | Certificate key length >= 2048 bits (RSA)    | RSA key >= 2048, ECDSA >= 256                       | HIGH      | config system certificate local |
| 5.1.4  | Wildcard certificate scope reviewed          | Wildcard use documented and justified               | MEDIUM    | config system certificate local |
| 5.1.5  | Certificate CN/SAN matches server FQDN       | CN or SAN matches deployed domain                   | MEDIUM    | config system certificate local |

### 5.2 TLS Protocol & Cipher Configuration
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 5.2.1  | TLS 1.0 disabled                             | ssl-min-proto-version != TLSv1.0                    | CRITICAL  | config system global / ssl-profile |
| 5.2.2  | TLS 1.1 disabled                             | ssl-min-proto-version != TLSv1.1                    | CRITICAL  | config system global / ssl-profile |
| 5.2.3  | TLS 1.2 minimum enforced                     | ssl-min-proto-version = TLSv1-2 at minimum          | CRITICAL  | config system global |
| 5.2.4  | TLS 1.3 enabled                              | TLSv1.3 enabled where supported                     | HIGH      | config system global |
| 5.2.5  | SSLv3 disabled                               | No SSLv3 in any profile                             | CRITICAL  | config system global |
| 5.2.6  | Weak ciphers disabled (RC4, DES, 3DES, EXPORT) | Ciphersuite list excludes weak algorithms          | CRITICAL  | config system global |
| 5.2.7  | Perfect Forward Secrecy ciphers prioritized  | ECDHE/DHE ciphers listed first                      | HIGH      | config system global |
| 5.2.8  | NULL ciphers disabled                        | No NULL cipher suites in any profile                | CRITICAL  | config system global |
| 5.2.9  | HSTS header enforced                         | hsts = enable, max-age >= 31536000                  | HIGH      | config waf http-header-security |
| 5.2.10 | SSL inspection on backend (if HTTPS backend) | ssl-server-verify = enable                          | HIGH      | config server-policy server-pool |

---

## SECTION 6 — ACCESS CONTROL & IP REPUTATION

### 6.1 IP-Based Access Control
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 6.1.1  | IP reputation database enabled               | ip-reputation = enable                              | HIGH      | config waf ip-reputation |
| 6.1.2  | Tor exit node blocking enabled               | tor-exit-node = enable in IP reputation             | HIGH      | config waf ip-reputation |
| 6.1.3  | Botnet IP blocking enabled                   | botnet = enable in IP reputation                    | HIGH      | config waf ip-reputation |
| 6.1.4  | Anonymous proxy blocking configured          | anonymous-proxy = enable                            | MEDIUM    | config waf ip-reputation |
| 6.1.5  | Geo-IP blocking configured for restricted regions | geo-ip-block policy defined                    | MEDIUM    | config waf geo-ip-bypass |
| 6.1.6  | IP allowlist/whitelist documented and minimal | Trust IP group not overly broad                    | HIGH      | config waf ip-list |
| 6.1.7  | IP blacklist configured for known bad actors | blacklist-ip group defined and applied              | MEDIUM    | config waf ip-list |

### 6.2 Rate Limiting & DoS Protection
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 6.2.1  | HTTP flood protection enabled                | http-flood = enable, threshold defined              | CRITICAL  | config waf http-flood-prevention |
| 6.2.2  | TCP flood protection enabled                 | tcp-flood = enable at network level                 | HIGH      | config waf dos-protection |
| 6.2.3  | Connection rate limiting per IP configured   | max-http-conn-per-ip defined                        | HIGH      | config server-policy policy |
| 6.2.4  | Request rate limiting configured             | max-http-req-per-sec defined                        | HIGH      | config waf http-flood-prevention |
| 6.2.5  | SYN cookie protection enabled                | syn-cookie = enable                                 | HIGH      | config waf dos-protection |
| 6.2.6  | Challenge action for suspicious traffic      | action = redirect/captcha before block              | MEDIUM    | config waf http-flood-prevention |
| 6.2.7  | DoS policy applied to all server policies    | dos-protection-profile linked in server policies    | CRITICAL  | config server-policy policy |

---

## SECTION 7 — AUTHENTICATION & SESSION MANAGEMENT

### 7.1 Application Authentication
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 7.1.1  | Site publish authentication configured (if applicable) | auth-policy applied to protected apps     | HIGH      | config waf site-publish-helper |
| 7.1.2  | SSO/SAML configured securely                 | saml-server validated, assertion signed             | HIGH      | config user saml |
| 7.1.3  | LDAP server uses LDAPS (port 636)            | ldap server port = 636, secure = enable             | HIGH      | config user ldap |
| 7.1.4  | RADIUS server configured with strong secret  | secret not default, min 16 chars                    | HIGH      | config user radius |
| 7.1.5  | Session cookie security flags set            | HttpOnly, Secure flags in cookie-security config    | HIGH      | config waf cookie-security |
| 7.1.6  | Cookie signing/encryption enabled            | cookie-sign = enable or cookie-encrypt = enable     | HIGH      | config waf cookie-security |
| 7.1.7  | Cookie replay attack protection              | cookie-replay-protection = enable                   | HIGH      | config waf cookie-security |
| 7.1.8  | Session timeout enforced                     | session-timeout defined and <= 1800 seconds         | MEDIUM    | config waf web-protection-profile |

---

## SECTION 8 — SECURITY HEADERS

### 8.1 HTTP Security Headers
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 8.1.1  | X-Frame-Options header injected              | x-frame-options = DENY or SAMEORIGIN                | HIGH      | config waf http-header-security |
| 8.1.2  | X-Content-Type-Options header injected       | x-content-type-options = nosniff                    | MEDIUM    | config waf http-header-security |
| 8.1.3  | X-XSS-Protection header injected             | x-xss-protection = 1; mode=block                    | MEDIUM    | config waf http-header-security |
| 8.1.4  | Content-Security-Policy header configured    | csp header defined with strict policy               | HIGH      | config waf http-header-security |
| 8.1.5  | HSTS header configured                       | strict-transport-security with max-age >= 31536000  | HIGH      | config waf http-header-security |
| 8.1.6  | Server header removed or masked              | server-header = remove or custom value              | MEDIUM    | config waf http-header-security |
| 8.1.7  | Referrer-Policy header configured            | referrer-policy header defined                      | LOW       | config waf http-header-security |
| 8.1.8  | HTTP header security profile applied to all policies | header-security-profile linked in server policies | HIGH  | config server-policy policy |

---

## SECTION 9 — ADVANCED THREAT PROTECTION

### 9.1 Bot & Scraping Protection
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 9.1.1  | Bot detection policy applied                 | bot-detection-policy = enable in WAF profile        | HIGH      | config waf bot-detection-policy |
| 9.1.2  | Known bot signatures updated                 | FortiGuard bot DB updated within 7 days             | HIGH      | FortiGuard status |
| 9.1.3  | Malicious bot action = block                 | action = block (not alert-only)                     | HIGH      | config waf bot-detection-policy |
| 9.1.4  | Credential stuffing protection enabled       | credential-stuffing-defense = enable                | HIGH      | config waf credential-stuffing-defense |
| 9.1.5  | CAPTCHA challenge configured for bots        | captcha-action defined before block                 | MEDIUM    | config waf bot-detection-policy |

### 9.2 Data Loss Prevention
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 9.2.1  | Data loss prevention policy configured       | dlp-policy applied                                  | HIGH      | config waf dlp-data-type |
| 9.2.2  | Credit card data masking enabled             | credit-card pattern in DLP profile, action = mask   | HIGH      | config waf dlp-policy |
| 9.2.3  | PII patterns defined in DLP                  | SSN, email, national ID patterns defined            | HIGH      | config waf dlp-data-type |
| 9.2.4  | Response body inspection enabled             | response-inspection = enable                        | MEDIUM    | config waf dlp-policy |

---

## SECTION 10 — HA & RESILIENCE

### 10.1 High Availability
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 10.1.1 | HA mode configured (if applicable)           | mode = active-passive or active-active              | HIGH      | config system ha |
| 10.1.2 | HA heartbeat interface dedicated             | hbdev = dedicated non-data interface                | HIGH      | config system ha |
| 10.1.3 | HA password (group-password) set             | group-password != default/empty                     | CRITICAL  | config system ha |
| 10.1.4 | HA group-id unique in environment            | group-id != 0 and unique                            | MEDIUM    | config system ha |
| 10.1.5 | Session sync enabled                         | session-sync = enable                               | HIGH      | config system ha |
| 10.1.6 | Failover detection threshold configured      | Reasonable heartbeat interval and failover count    | MEDIUM    | config system ha |

---

## SECTION 11 — BACKUP & CHANGE MANAGEMENT

### 11.1 Configuration Backup
| ID     | Control                                      | Expected Value / Condition                          | Severity  | Config Path |
|--------|----------------------------------------------|-----------------------------------------------------|-----------|-------------|
| 11.1.1 | Automatic backup configured                  | Scheduled backup to remote server                   | HIGH      | config system auto-backup (or equivalent) |
| 11.1.2 | Backup server defined (FTP/SFTP/SCP)         | Backup destination IP and protocol configured       | HIGH      | system backup config |
| 11.1.3 | Backup encryption enabled                    | Encrypted backup preferred                          | HIGH      | backup config |
| 11.1.4 | Configuration revision history maintained    | Manual versioning or FortiManager integration       | MEDIUM    | FortiManager or manual |
