# Apache Tomcat Hardening Review: Checklist and Ansible Audit
 
| | |
|---|---|
| **Document date** | 2026-11-24 |
| **Scope** | Apache Tomcat 10.1.x / 11.0.x (primary), 9.0.x (noted where it differs) |
| **Companion files** | `tomcat_audit.yml` (read-only audit playbook), `tomcat_audit_policy.yml` (policy and feature switches) |
| **Validated on** | Apache Tomcat 10.1.61 (Debian package binaries + upstream `conf/`), OpenJDK 21.0.13, ansible-core 2.22.0, community.general 14.0.1 |
 
## How to read this document
 
* **Part A** covers controls **outside Tomcat**: OS, service account, JVM, network, proxy and process. These are often missing from a CIS-based Tomcat guide, but an attacker who gets code execution in Tomcat meets them first.
* **Part B** covers **Tomcat-specific** controls. Each one has an ID, the expected state, an "if X is not needed → disable Y / if needed → harden" rule, and the exact Ansible check from the companion playbook.
* Each `tomcat_needs_*` switch in `tomcat_audit_policy.yml` is one "is X needed?" decision. A switch should only be `true` when an owner has documented the need.
```bash
# controller needs: ansible-core, community.general, python3-lxml (targets need nothing extra)
ansible-playbook -i inventory tomcat_audit.yml -e @tomcat_audit_policy.yml          # full audit
ansible-playbook -i inventory tomcat_audit.yml -e @tomcat_audit_policy.yml --tags xml,files,version
ansible-playbook -i inventory tomcat_audit.yml -e @tomcat_audit_policy.yml --tags probe \
                 -e tomcat_probe_base_url=https://app.example.internal              # run again via the proxy
```
 
### Design rules of the audit (why the checks look the way they do)
 
1. **The audit is read-only.** It slurps files and runs `find` and `java -cp catalina.jar …ServerInfo`. The only write is the JSON report on the controller.
2. **XML is parsed, never grepped.** Tomcat ignores commented-out elements. `grep`/`lineinfile` do not, so the stock `server.xml` (commented AJP and TLS connectors) would give false results.
3. **No lxml on hardened hosts.** Files are parsed on the controller (`delegate_to: localhost`, `community.general.xml` with `xmlstring`).
4. **Comparisons are conservative.** Booleans must be exactly `true`/`false`, so `allowTrace="TRUE"` is reported. Invalid XML makes every check on that file report an XPath error instead of passing.
5. **A failed check is never a pass.** If `find` returns non-zero, or a file is missing or unreadable, that is recorded as a finding. (The `state: absent` + no verification pattern in the reviewed guide has exactly this weakness.)
6. **Apps can override global settings.** `WEB-INF/web.xml`, `WEB-INF/tomcat-web.xml`, `META-INF/context.xml` and `conf/<engine>/<host>/*.xml` are checked per application.
7. **Runtime probes confirm the effective behaviour.** Run them directly against the connector **and** through the reverse proxy.
### Lab validation summary
 
| Instance | Description | Result |
|---|---|---|
| `stock` | Upstream 10.1.x `conf/` + ROOT, manager, host-manager | **35 findings** (expected) |
| `hard` | Hardened reference configuration | **0 findings**. Tomcat starts cleanly; all probes pass. |
| `mut` | Hardened config with ~25 injected violations (XML-only) | **30 findings**: every injected violation was detected. The "needed = true" branches (AJP, Realm, users, shutdown, HTTP/2, cluster, persistence) produced 8 more targeted findings. |
| `mut2` | Running instance with runtime misconfigurations (TRACE, writable DefaultServlet, oversized headers, manager exposed) | **20 findings**, including probe failures for TC-38/39/40/42 |
 
### Corrections and new findings compared to the earlier recommendations
 
The lab and the current Tomcat documentation changed some earlier statements. Apply these to the review:
 
* **`EncryptInterceptor` is deprecated.** Tomcat 11 docs say it must not be used to secure cluster traffic. Cluster traffic must be isolated (private network, VPN/IPsec) or carried over TLS.
* **`rejectIllegalHeader` was removed from the checks.** It is not documented for Tomcat 11, and 10.1.61 accepts it silently, so it is not a verifiable control.
* **`rejectSuspiciousURIs="true"` blocks the `..;` proxy bypass on Tomcat itself.** In the lab, `/x/..;/manager/html`, `/;a=b/…`, `%2e%2e`, `%2f` and `%5c` variants returned 400 with it, and 401 (reached the manager) without it. `/manager;x=y/html` is still accepted, so proxy-side normalisation (A-11) is still required.
* **HSTS default `max-age` is 0.** `HttpHeaderSecurityFilter` sends `max-age=0` unless `hstsMaxAgeSeconds` is set, and only on requests Tomcat considers secure.
* **Session persistence defaults differ by version.** It is off by default in 10.1/11 (`pathname` default null) and on in 9.0 (`SESSIONS.ser`).
* **`deployXML="false"` stops apps with their own `META-INF/context.xml` from deploying**, e.g. manager/host-manager. They need a descriptor in `conf/<engine>/<host>/`.
* **A TRACE probe on `/` gives a false pass.** JSP/welcome paths return 405 even with `allowTrace="true"`; a static path returned 200.
* **The Java Security Manager was removed in Tomcat 11.** Tomcat's own guidance is to run each application on a dedicated instance in a container or VM (A-06).
---
 
## Part A — Platform and surrounding controls (not Tomcat-specific)
 
These are not checked by the companion playbook, except where a TC-ID is referenced. The "How to verify" column gives the command an auditor or an additional Ansible task should run.
 
| ID | Control | Expected state / rule | How to verify |
|---|---|---|---|
| A-01 | Tomcat does **not** run as root | Service runs as a dedicated unprivileged account. Backstop inside Tomcat: TC-02 `SecurityListener` refuses a root start (confirmed in the lab). | `ps -o user=,pid=,args= -C java` · `systemctl show -p User,Group tomcat` |
| A-02 | Service account cannot be used interactively | Shell `/usr/sbin/nologin`, password locked, no sudo rules, not in `wheel`/`sudo`/`adm`/`docker`. | `getent passwd tomcat` · `passwd -S tomcat` · `sudo -l -U tomcat` · `id tomcat` |
| A-03 | Restrictive umask | `UMask=0027` in the unit, so new files are not world-readable. Matches TC-02 `minimumUmask`. | `systemctl show -p UMask tomcat` |
| A-04 | systemd sandboxing | `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ReadWritePaths=` logs/temp/work only, `PrivateTmp=yes`, `ProtectHome=yes`, `CapabilityBoundingSet=` (empty), `RestrictSUIDSGID=yes`, `ProtectKernelTunables/Modules=yes`, `ProtectControlGroups=yes`, `RestrictNamespaces=yes`, `LockPersonality=yes`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`, `LimitCORE=0`. **Do not** set `MemoryDenyWriteExecute=yes`: it breaks the JVM JIT. Ports <1024: no `CAP_NET_BIND_SERVICE`; use the proxy. | `systemd-analyze security tomcat.service` (score threshold in policy) · `systemctl show -p NoNewPrivileges,ProtectSystem,ReadWritePaths tomcat` |
| A-05 | Mandatory access control | SELinux enforcing with a confined domain, or an AppArmor profile in enforce mode. | `getenforce` · `ps -eZ \| grep java` · `aa-status` |
| A-06 | One application per Tomcat instance/JVM | The Security Manager is gone, so apps in one JVM share all secrets and privileges. Split `CATALINA_HOME` (binaries) from one `CATALINA_BASE` per app. | Inventory review · count of approved apps per instance (TC-29) |
| A-07 | Container runtime (if used) | Non-root UID, read-only root FS (tmpfs for temp/work), `--cap-drop=ALL`, `no-new-privileges`, not privileged, no host socket or hostPath mounts, scanned image. | `docker inspect` / pod `securityContext` review |
| A-08 | Listening sockets | Only approved ports. Shutdown 8005, AJP 8009, cluster 4000, JMX/RMI and JDWP not on non-loopback interfaces. Complements TC-03..06. | `ss -ltnp` |
| A-09 | Inbound filtering | Connector port reachable only from the reverse proxy IPs. | `nft list ruleset` / `iptables-save` / security groups |
| A-10 | **Egress default-deny** for the runtime user | Allow only required destinations (DB, LDAP, …). Blocks reverse shells, JNDI/LDAP callbacks and exfiltration after RCE. | `nft list ruleset` (`meta skuid tomcat`) · test `curl` as tomcat user fails |
| A-11 | Reverse proxy | Deny admin paths at the proxy **and** on Tomcat. Normalise or reject `;` path parameters, `%2e`, `%2f`, `%5c` (for httpd `mod_proxy`, Tomcat docs suggest `mapping=servlet`). Strip client-supplied `X-Forwarded-*`. Strict HTTP/1.1 parsing against request smuggling. CSP, plus MFA on any admin UI. | Re-run probes TC-37..42 with `tomcat_probe_base_url` = proxy URL |
| A-12 | Proxy → Tomcat hop | TLS (or mTLS) when the hop crosses hosts, zones or untrusted segments. | Config review · `openssl s_client` from the proxy |
| A-13 | JDK | Supported release, patched in step with Tomcat (separate patch stream). | `java -version` · package inventory |
| A-14 | No debug agents | No `-agentlib:jdwp`, `-Xrunjdwp` or `catalina.sh jpda` in production. An open JDWP port means instant RCE. | `tr '\0' ' ' < /proc/<pid>/cmdline` · `setenv.sh`, unit file |
| A-15 | Remote JMX | **Not needed → no `com.sun.management.jmxremote*`.** **Needed →** bound to loopback/management network, authentication + TLS, firewall. Treat JMX access as root-equivalent (Tomcat docs). | `/proc/<pid>/cmdline` · `ss -ltnp` |
| A-16 | Java deserialization filter | `-Djdk.serialFilter=` with an allow-list and limits (JEP 290). Test with the apps first. | `/proc/<pid>/cmdline` |
| A-17 | Attach API, heap/core dumps | `-XX:+DisableAttachMechanism` (trade-off: APM attach, `jcmd`). `HeapDumpPath` in a restricted dir or dumps disabled. `LimitCORE=0`. Dumps contain secrets and session IDs. | `/proc/<pid>/cmdline` · unit file |
| A-18 | `java.io.tmpdir` | `CATALINA_BASE/temp`, owned by the runtime user, 0750. Uploads land here. | `/proc/<pid>/cmdline` · `stat` |
| A-19 | Secrets outside config | Keystore passwords via `*PasswordFile` (TC-14), DB passwords via `${…}` substitution from a protected source (TC-24), systemd `LoadCredential=` or a vault. No secrets in `setenv.sh` or `Environment=`. | `grep -i pass setenv.sh` · `systemctl show -p Environment tomcat` |
| A-20 | Logging and monitoring | Logs forwarded to SIEM, NTP-synchronised time. Alerts on: new files in `webapps/`, manager access, 401/400 bursts on admin or `..;` paths, config changes, Tomcat restarts. | SIEM use-case review |
| A-21 | File integrity monitoring | FIM/auditd watches on `CATALINA_HOME/bin`, `lib`, `CATALINA_BASE/conf`, `lib`, `webapps`. | `auditctl -l` · AIDE config |
| A-22 | Patch management | Tomcat, JDK and tcnative/OpenSSL tracked separately. Tomcat 9.0.x end of support: **31 Mar 2027** (a 9.1.x branch continues). tcnative 1.3.x end of support: 31 Mar 2027. **Not using APR/OpenSSL → remove `AprLifecycleListener` and libtcnative.** | Version inventory vs vendor security pages |
| A-23 | Application supply chain | SCA/SBOM for WARs and `lib/`, no secrets inside WARs, CSRF/CORS filters where apps need them. | CI evidence |
| A-24 | Deployment process | CI/CD only, artifacts hashed/signed, no manual copies into `webapps/`. Golden image plus this audit on a schedule (drift detection). | Pipeline review · audit reports history |
 
 
---
 
## Part B — Tomcat-specific controls
 
### B.1 Feature switches ("if X is not needed → disable Y")
 
| Switch (`tomcat_audit_policy.yml`) | Default | If **false** (not needed), the audit requires… | If **true** (needed), the audit requires… | IDs |
|---|---|---|---|---|
| `tomcat_needs_shutdown_port` | false | `<Server port="-1">` | loopback only, ≥20-char secret | TC-03 |
| `tomcat_needs_ajp` | false | no AJP connector | secret ≥32 chars, `secretRequired`, no `.*` pattern | TC-06 |
| `tomcat_needs_tls_on_tomcat` | false | no TLS connector / `SSLHostConfig` | pinned protocols, explicit ciphers, password files | TC-13, TC-14 |
| `tomcat_tls_terminated_at_proxy` | true | – | `RemoteIpValve` or `secure`/`scheme` on the connector | TC-16b |
| `tomcat_needs_http2` | false | no `Http2Protocol` | `maxConcurrentStreams` ≤ policy | TC-15 |
| `tomcat_needs_manager` | false | manager/host-manager absent | CIDR-restricted contexts + descriptors | TC-28, TC-29 |
| `tomcat_needs_container_auth` | false | no `Realm`, no users | LockOutRealm, PBKDF2 handler, clean users file | TC-20..22 |
| `tomcat_needs_cluster` | false | no `Cluster` | explicit internal `Receiver` address (+ isolated network) | TC-23 |
| `tomcat_needs_session_persistence` | false | no `pathname`/`PersistentManager`/`Store` (9.0: explicit `pathname=""`) | class filter, no `FileStore` | TC-25 |
| `tomcat_needs_write_methods` | false | DefaultServlet read-only, no WebDAV | (review case by case) | TC-30, TC-31, TC-39 |
| `tomcat_needs_cgi` | false | no `CGIServlet` | (review case by case) | TC-31 |
| `tomcat_needs_runtime_jsp` | true | `JspServlet` removed | – | TC-32 |
| `tomcat_strict_uri_checks` | true | – | `rejectSuspiciousURIs`, reject `%5C` | TC-11 |
 
 
### B.2 Tomcat-specific checks
 
| ID | Area | Expected state | Rule: if X not needed → / if needed → | Where | Lab result |
|---|---|---|---|---|---|
| [TC-01](#tc-01) | Patch level | Tomcat release ≥ the patched baseline of a **supported** branch. The real version is read from `catalina.jar`, so a ServerInfo override cannot hide it. | Always. Branch not in policy = unsupported = finding. 9.0.x end of support: 31 Mar 2027. | `lib/catalina.jar` | Detected (baseline raised) / passed |
| [TC-02](#tc-02) | Process | `SecurityListener` enabled: refuses to start as `root` and enforces a minimum umask (0007 or stricter). | Always. In-Tomcat backstop for A-01. | server.xml | Blocked a root start in the lab; detected on stock |
| [TC-03](#tc-03) | Shutdown port | `<Server port="-1">` | **Not needed → `port=-1`** (systemd stops via signal). **Needed →** loopback only + ≥20-char `shutdown` secret. | server.xml | Detected on stock; both branches |
| [TC-04](#tc-04) | Connectors | Only approved connector ports exist. Delete unused connectors (sample 8443/8009 included). | Always. | server.xml | Detected |
| [TC-05](#tc-05) | Connectors | Every connector has an explicit `address` from the allow-list. Without `address`, Tomcat listens on **all** interfaces. | Always. Behind a local proxy: `127.0.0.1`, otherwise the internal interface. | server.xml | Detected on stock |
| [TC-06](#tc-06) | AJP | No AJP connector. | **Not needed → remove.** **Needed →** `secretRequired` true, secret ≥32 chars, no `.*` attribute pattern, firewall to proxy (A-09). AJP is cleartext. | server.xml | Detected; both branches |
| [TC-07](#tc-07) | HTTP methods | `allowTrace` absent or `false`. | Always. | server.xml | Detected (XML + probe) |
| [TC-08](#tc-08) | Banner | `xpoweredBy` false; `server` attribute (if set) is generic. | Always. | server.xml | Detected |
| [TC-09](#tc-09) | Banner | `lib/org/apache/catalina/util/ServerInfo.properties` overrides `server.info`, `server.number` and `server.built`. | Always. | CATALINA_BASE/lib | Detected; override confirmed effective at runtime |
| [TC-10](#tc-10) | URI parsing | No `allowBackslash`, `encodedSolidusHandling=reject`, no `relaxedPathChars`/`relaxedQueryChars`. Non-standard parsing behind a proxy enables access-control bypasses. | Always. | server.xml | Detected |
| [TC-11](#tc-11) | URI parsing | `rejectSuspiciousURIs="true"` and `encodedReverseSolidusHandling="reject"` on HTTP connectors. **In the lab this returned 400 for `/x/..;/manager/html`, `/;a=b/…`, `%2e%2e`, `%2f` and `%5c` variants.** | Default on (`tomcat_strict_uri_checks`). Disable only with documented app incompatibility. | server.xml | Detected on stock; bypass blocked when set |
| [TC-12](#tc-12) | DoS limits | `connectionTimeout`, `maxPostSize`, `maxParameterCount`, `maxPartCount`, `maxPartHeaderSize`, `maxHttpHeaderSize`, `maxSwallowSize` explicitly set, ≤ policy, never `-1`. | Always. Explicit values protect against default changes between versions. | server.xml | Detected (each limit) |
| [TC-13](#tc-13) | TLS | TLS on Tomcat: `SSLHostConfig protocols` = policy (`TLSv1.2+TLSv1.3`) plus explicit `ciphers`. The Tomcat default `all` includes TLSv1/1.1. | **Not needed (TLS at proxy) → no TLS connector.** **Needed →** pinned protocols and ciphers. Put only TLS 1.2 suites in `ciphers` (Tomcat moves 1.3 suites and warns). | server.xml | Detected; both branches |
| [TC-14](#tc-14) | Secrets | No inline `certificateKeystorePassword`/`certificateKeyPassword`/`keystorePass`/`truststorePass`. Use `certificateKeystorePasswordFile` (root:tomcat 0640). | Always. | server.xml | Detected |
| [TC-15](#tc-15) | HTTP/2 | No `Http2Protocol`. | **Not needed → remove.** **Needed →** `maxConcurrentStreams` ≤ policy plus a current patch level (HTTP/2 DoS CVEs). | server.xml | Detected; both branches |
| [TC-16](#tc-16) | Proxy trust | `RemoteIpValve` has explicit `internalProxies` (its default trusts all RFC 1918/loopback ranges, so any internal host can spoof client IPs). If TLS ends at the proxy, Tomcat must be told: `RemoteIpValve` or `secure="true" scheme="https"`. | Always for 16a. 16b when `tomcat_tls_terminated_at_proxy`: without it HSTS is not sent and requests look insecure. | server.xml | Detected |
| [TC-17](#tc-17) | Deployment | `autoDeploy="false"` and `deployXML="false"` on every Host. | Always. Note: with `deployXML=false`, apps with their own `META-INF/context.xml` (e.g. manager) **do not deploy** until a descriptor exists in `conf/<engine>/<host>/` (seen in the lab). | server.xml | Detected |
| [TC-18](#tc-18) | Error output | Every Host has `ErrorReportValve showReport="false" showServerInfo="false"`. | Always. | server.xml | Detected (XML + probe) |
| [TC-19](#tc-19) | Logging | `AccessLogValve` on every Host (or Engine). Pattern has no session ID (`%S`), cookies (`%{..}c`) or `Authorization` header. | Always. | server.xml | Detected |
| [TC-20](#tc-20) | Authentication | No `Realm`. | **Not needed → no Realm.** **Needed →** top-level `LockOutRealm` with `failureCount` ≤ policy and `lockOutTime` ≥ policy (Realms do not lock accounts by default). | server.xml | Detected; both branches |
| [TC-21](#tc-21) | Authentication | Password realms use `SecretKeyCredentialHandler` with `PBKDF2WithHmacSHA512` and ≥ policy iterations. Without a handler, stored passwords are compared in **plaintext**. | Only when container auth is needed. | server.xml | Detected |
| [TC-22](#tc-22) | Authentication | `tomcat-users.xml`: no users if not needed; otherwise hashed passwords only, no default names, no `manager-script`/`manager-jmx`/`admin-script`. | **Not needed → no users.** **Needed →** as stated. | tomcat-users.xml | Detected; both branches |
| [TC-23](#tc-23) | Clustering | No `Cluster`. | **Not needed → remove.** **Needed →** `Receiver` bound to an explicit internal address (default `auto`), on an isolated network/IPsec/TLS. `EncryptInterceptor` is deprecated and not a security control. | server.xml | Detected; both branches |
| [TC-24](#tc-24) | Secrets | No plaintext `*password*`/`*Pass*` attributes in server.xml, conf/context.xml, app and descriptor context files. Use `${…}` property substitution from a protected source. | Always. | all XML | Detected (`${…}` correctly ignored) |
| [TC-25](#tc-25) | Sessions | No session persistence (no `pathname`, `PersistentManager` or `Store`). **Tomcat 9:** `<Manager pathname=""/>` must be explicit (persistence is on by default there; off by default in 10.1/11). | **Not needed → disabled.** **Needed →** `sessionAttributeValueClassNameFilter` and no `FileStore` (CVE-2025-24813 chain used file-based persistence). | context.xml (+apps) | Detected; Tomcat 9 branch |
| [TC-26](#tc-26) | Context | No `privileged`/`crossContext`/`allowLinking`. `useHttpOnly` not disabled. Exception: approved admin apps may be `privileged`. | Always. | context.xml (+apps) | Detected |
| [TC-27](#tc-27) | Cookies | Global `CookieProcessor sameSiteCookies="strict"` or `"lax"`. | Always. | context.xml | Detected on stock |
| [TC-28](#tc-28) | Admin apps | `RemoteCIDRValve`/`RemoteAddrValve` with a restricted `allow` (no `0.0.0.0/0`, `::/0`) in **both** the app's context.xml and its `conf/<engine>/<host>/` descriptor. | **Not needed → apps absent (TC-29).** **Needed →** as stated, plus proxy-side block and MFA (A-11). | manager contexts | Detected |
| [TC-29](#tc-29) | Deployment | Contents of `webapps/` (dirs + WARs) and `conf/<engine>/<host>/*.xml` match an allow-list. ROOT/docs/examples/manager/host-manager absent unless approved. Descriptors can deploy code from **outside** `webapps/`. | Always. | filesystem | Detected (apps + rogue descriptor) |
| [TC-30](#tc-30) | DefaultServlet | `readonly=true`, `listings=false`, `allowPartialPut=false`, `showServerInfo=false` (global). Apps must not re-enable writes or listings (`WEB-INF/web.xml`, `WEB-INF/tomcat-web.xml`). | **Writes not needed → read-only everywhere.** If needed: authenticated, separate context. | web.xml (+apps) | Detected (XML + PUT probe) |
| [TC-31](#tc-31) | Servlets | No `WebdavServlet` / `CGIServlet` (global or in apps). | **Not needed → not declared.** | web.xml (+apps) | Detected |
| [TC-32](#tc-32) | JSP | `JspServlet` removed from global web.xml: a dropped `.jsp` web shell cannot run. | **Runtime JSP not needed → remove** (precompile JSPs with JspC). Default switch is `true` because many apps need it. | web.xml | Detected |
| [TC-33](#tc-33) | Session cookie | `cookie-config` `http-only` and `secure` true, `tracking-mode` COOKIE only, `session-timeout` 1..policy. Apps must not weaken these. | Always. | web.xml (+apps) | Detected |
| [TC-34](#tc-34) | Headers | `HttpHeaderSecurityFilter` mapped to `/*`, `hstsMaxAgeSeconds` ≥ 1 year (**default is 0**), click-jacking/nosniff not disabled. HSTS is only sent on requests Tomcat sees as secure (see TC-16b). | Always (coordinate with headers set by the proxy). | web.xml | Detected (XML + probe) |
| [TC-35](#tc-35) | Error output | Global `<error-page>` for `java.lang.Throwable`. | Always. | web.xml | Detected |
| [TC-36](#tc-36) | Files | No file in CATALINA_HOME/BASE owned by the runtime user except logs/temp/work. No group/world-writable code or config. conf/ not world-readable. logs/temp/work owned by runtime user, no world access. **A check that cannot run is itself a finding.** | Always. | filesystem | Detected (owner, g+w, o+r) |
| [TC-37](#tc-37) | Probe | 404 and 400 error pages contain no product, version or stack trace. | Run against Tomcat **and** through the proxy. | HTTP | Detected on stock |
| [TC-38](#tc-38) | Probe | TRACE refused on `/` **and on a static path**. JSP/welcome paths return 405 even with `allowTrace=true`, so probing `/` alone is a false pass (seen in the lab). | Always. | HTTP | Detected |
| [TC-39](#tc-39) | Probe | PUT and partial PUT refused, and the probe file is not retrievable. | Always (when writes are not needed). | HTTP | Detected |
| [TC-40](#tc-40) | Probe | Admin paths return 400/403/404, including `..;`, `;param` and encoded variants. A 401 means **reachable**. | Run from an untrusted segment and through the proxy. | HTTP | Detected (401 on stock) |
| [TC-41](#tc-41) | Probe | No version in `Server`; `X-Content-Type-Options: nosniff`; `X-Frame-Options`; HSTS ≥ policy on HTTPS; session cookie `Secure; HttpOnly; SameSite`. | Always. | HTTP | Detected / passed |
| [TC-42](#tc-42) | Probe | An oversized request header (2× `maxHttpHeaderSize`) is rejected (400/413/431). | Always. | HTTP | Detected |
 
### B.3 How the XML checks run (shared engine)
 
All `tc_xml_checks` entries below are evaluated by this engine. A check either counts **offending** nodes (`expect: absent` → must be 0) or **required** nodes (`expect: present` → must be ≥ 1). `applies` implements the "if X not needed" switch. Per-application checks (`kind: webxml|context|admin_context`) run against every app descriptor found.
 
```yaml
- name: "COLLECT | read core config files"
  ansible.builtin.slurp:
    src: "{{ catalina_base }}/conf/{{ item }}"
  loop: [server.xml, web.xml, context.xml, tomcat-users.xml]
  register: tc_core_raw
  failed_when: false
  tags: [always]
 
- name: "COLLECT | decode core config files (missing file -> empty <missing/> document)"
  ansible.builtin.set_fact:
    tc_xml:
      server: "{{ (tc_core_raw.results[0].content | default('PG1pc3NpbmcvPg==')) | b64decode }}"
      web: "{{ (tc_core_raw.results[1].content | default('PG1pc3NpbmcvPg==')) | b64decode }}"
      context: "{{ (tc_core_raw.results[2].content | default('PG1pc3NpbmcvPg==')) | b64decode }}"
      users: "{{ (tc_core_raw.results[3].content | default('PG1pc3NpbmcvPg==')) | b64decode }}"
  tags: [always]
 
- name: "COLLECT | server.xml and web.xml must exist"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-00', 'title': 'Core config file missing or unreadable', 'detail': item.item}] }}"
  loop: "{{ tc_core_raw.results }}"
  loop_control: { label: "{{ item.item }}" }
  when: item.content is not defined and item.item in ['server.xml', 'web.xml', 'context.xml']
  tags: [always]
 
- name: "COLLECT | find per-app descriptors (WEB-INF/web.xml, WEB-INF/tomcat-web.xml, META-INF/context.xml)"
  ansible.builtin.find:
    paths: "{{ catalina_base }}/webapps"
    patterns: ["web.xml", "tomcat-web.xml", "context.xml"]
    recurse: true
    depth: 3
  register: tc_app_find
  tags: [always]
 
- name: "COLLECT | find context descriptors in conf/<engine>/<host>/"
  ansible.builtin.find:
    paths: "{{ catalina_base }}/conf/{{ tomcat_engine_name }}"
    patterns: ["*.xml"]
    recurse: true
    depth: 2
  register: tc_desc_find
  failed_when: false
  tags: [always]
 
- name: "COLLECT | read per-app descriptors"
  ansible.builtin.slurp:
    src: "{{ item }}"
  loop: >-
    {{ (tc_app_find.files | map(attribute='path')
        | select('search', '/(WEB-INF/(web|tomcat-web)|META-INF/context)\.xml$') | list)
       + (tc_desc_find.files | default([]) | map(attribute='path') | list) }}
  register: tc_app_raw
  tags: [always]
 
- name: "COLLECT | classify per-app descriptors"
  ansible.builtin.set_fact:
    tc_app_files: >-
      {{ tc_app_files | default([]) + [{
           'path': item.source,
           'content': item.content | b64decode,
           'kind': ('webxml' if item.source is search('/WEB-INF/') else 'context'),
           'app': ((item.source | regex_findall('/webapps/([^/]+)/') | first)
                   if item.source is search('/webapps/')
                   else (item.source | basename | regex_replace('[.]xml$', '')))
         }] }}
  loop: "{{ tc_app_raw.results }}"
  loop_control: { label: "{{ item.source }}" }
  tags: [always]
 
- name: "XML | core configuration checks (one loop item per check ID)"
  community.general.xml:
    xmlstring: "{{ tc_xml[item.file] }}"
    xpath: "{{ item.xpath }}"
    count: true
  delegate_to: localhost
  become: false
  loop: "{{ tc_xml_checks | selectattr('applies', 'equalto', true) | list }}"
  loop_control: { label: "{{ item.id }}" }
  register: tc_xml_results
  failed_when: false
  tags: [xml]
 
- name: "XML | record findings"
  ansible.builtin.set_fact:
    tc_findings: >-
      {{ tc_findings + [{'id': r.item.id, 'title': r.item.title,
         'detail': ('XPath error: ' ~ (r.msg | default('?'))) if r.count is not defined
                   else ('conf/' ~ {'server':'server.xml','web':'web.xml','context':'context.xml','users':'tomcat-users.xml'}[r.item.file]
                         ~ ': ' ~ r.count ~ ' offending node(s)' if r.item.expect == 'absent' else ' required element missing')}] }}
  loop: "{{ tc_xml_results.results | default([]) }}"
  loop_control: { loop_var: r, label: "{{ r.item.id }}" }
  when: >-
    r.count is not defined
    or (r.item.expect == 'absent' and (r.count | int) > 0)
    or (r.item.expect == 'present' and (r.count | int) == 0)
  tags: [xml]
 
- name: "XML-APP | per-application descriptor checks"
  community.general.xml:
    xmlstring: "{{ item.0.content }}"
    xpath: "{{ item.1.xpath }}"
    count: true
  delegate_to: localhost
  become: false
  loop: "{{ tc_app_files | default([]) | product(tc_app_checks | selectattr('applies', 'equalto', true) | list) | list }}"
  loop_control: { label: "{{ item.1.id }} {{ item.0.path }}" }
  when: >-
    (item.1.kind == item.0.kind and not (item.1.id == 'TC-26b' and item.0.app in tomcat_privileged_apps))
    or (item.1.kind == 'admin_context' and item.0.kind == 'context' and item.0.app in ['manager', 'host-manager'])
  register: tc_app_results
  failed_when: false
  tags: [xml]
 
- name: "XML-APP | record findings"
  ansible.builtin.set_fact:
    tc_findings: >-
      {{ tc_findings + [{'id': r.item.1.id, 'title': r.item.1.title,
         'detail': r.item.0.path ~ ((': XPath error ' ~ (r.msg | default('?'))) if r.count is not defined
                   else (': ' ~ r.count ~ ' offending node(s)' if r.item.1.expect == 'absent' else ': required element missing'))}] }}
  loop: "{{ tc_app_results.results | default([]) }}"
  loop_control: { loop_var: r, label: "{{ r.item.1.id }}" }
  when: >-
    r.skipped is not defined and (
    r.count is not defined
    or (r.item.1.expect == 'absent' and (r.count | int) > 0)
    or (r.item.1.expect == 'present' and (r.count | int) == 0))
  tags: [xml]
```
 
Probe tasks (TC-37..42) run inside one `block` with `delegate_to: localhost`, `become: false` and `when: tomcat_run_probes`, i.e. from the auditor's network position. Run them twice: against the connector and against the public/proxy URL.
 
### B.4 Ansible implementation per check
 
#### TC-01
 
**Patch level:** Tomcat release ≥ the patched baseline of a **supported** branch. The real version is read from `catalina.jar`, so a ServerInfo override cannot hide it.  
**Rule:** Always. Branch not in policy = unsupported = finding. 9.0.x end of support: 31 Mar 2027.
 
```yaml
- name: "TC-01 | read real Tomcat version from catalina.jar"
  ansible.builtin.command:
    argv: ["{{ tomcat_java }}", "-cp", "{{ catalina_home }}/lib/catalina.jar", "org.apache.catalina.util.ServerInfo"]
  register: tc_ver
  changed_when: false
  failed_when: false
  tags: [version]
 
- name: "TC-01 | parse version"
  ansible.builtin.set_fact:
    tc_version: "{{ tc_ver.stdout | default('') | regex_findall('Server number:[ \\t]*([0-9.]+)') | first | default('0') }}"
  tags: [version]
 
- name: "TC-01 | derive major version"
  ansible.builtin.set_fact:
    tc_major: "{{ tc_version.split('.')[0] }}"
    tc_version_cmp: "{{ tc_version.split('.')[0:3] | join('.') }}"
  tags: [version]
 
- name: "TC-01 | Tomcat version >= patched baseline for its branch"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-01', 'title': 'Tomcat older than patched baseline / unsupported branch',
                     'detail': 'running ' ~ tc_version ~ ', baseline ' ~ (tomcat_min_version[tc_major] | default('n/a (branch not in policy = unsupported)'))}] }}"
  when: >-
    tc_major not in tomcat_min_version
    or tc_version_cmp is version(tomcat_min_version[tc_major], '<')
  tags: [version]
```
 
#### TC-02
 
**Process:** `SecurityListener` enabled: refuses to start as `root` and enforces a minimum umask (0007 or stricter).  
**Rule:** Always. In-Tomcat backstop for A-01.
 
```yaml
- id: TC-02
  title: SecurityListener present (blocks start as root, enforces umask)
  file: server
  expect: present
  applies: true
  xpath: >-
    /Server/Listener[@className='org.apache.catalina.security.SecurityListener']
    [not(@checkedOsUsers) or contains(concat(',',translate(@checkedOsUsers,' ',''),','),',root,')]
    [not(@minimumUmask) or @minimumUmask='0007' or @minimumUmask='0027' or @minimumUmask='0077']
```
 
#### TC-03
 
**Shutdown port:** `<Server port="-1">`  
**Rule:** **Not needed → `port=-1`** (systemd stops via signal). **Needed →** loopback only + ≥20-char `shutdown` secret.
 
```yaml
- id: TC-03a
  title: Shutdown port disabled (port="-1")
  file: server
  expect: present
  applies: "{{ not tomcat_needs_shutdown_port | bool }}"
  xpath: /Server[@port='-1']
- id: TC-03b
  title: Shutdown port (if needed) has strong secret and listens on loopback only
  file: server
  expect: absent
  applies: "{{ tomcat_needs_shutdown_port | bool }}"
  xpath: >-
    /Server[@port!='-1'][not(@shutdown) or @shutdown='SHUTDOWN' or string-length(@shutdown) < 20
    or (@address and @address!='localhost' and @address!='127.0.0.1' and @address!='::1')]
```
 
#### TC-04
 
**Connectors:** Only approved connector ports exist. Delete unused connectors (sample 8443/8009 included).  
**Rule:** Always.
 
```yaml
- id: TC-04
  title: Only approved connector ports are defined
  file: server
  expect: absent
  applies: true
  xpath: "//Connector[not({{ tc_x_port_ok }})]"
```
 
#### TC-05
 
**Connectors:** Every connector has an explicit `address` from the allow-list. Without `address`, Tomcat listens on **all** interfaces.  
**Rule:** Always. Behind a local proxy: `127.0.0.1`, otherwise the internal interface.
 
```yaml
- id: TC-05
  title: Every connector binds to an approved address (no wildcard bind)
  file: server
  expect: absent
  applies: true
  xpath: "//Connector[not(@address) or not({{ tc_x_bind_ok }})]"
```
 
#### TC-06
 
**AJP:** No AJP connector.  
**Rule:** **Not needed → remove.** **Needed →** `secretRequired` true, secret ≥32 chars, no `.*` attribute pattern, firewall to proxy (A-09). AJP is cleartext.
 
```yaml
- id: TC-06a
  title: No AJP connector defined
  file: server
  expect: absent
  applies: "{{ not tomcat_needs_ajp | bool }}"
  xpath: "//Connector[{{ tc_x_ajp }}]"
- id: TC-06b
  title: AJP connector (if needed) requires a strong secret, explicit bind, no wildcard attribute pattern
  file: server
  expect: absent
  applies: "{{ tomcat_needs_ajp | bool }}"
  xpath: >-
    //Connector[{{ tc_x_ajp }}][@secretRequired='false' or not(@secret) or string-length(@secret) < 32
    or @allowedRequestAttributesPattern='.*']
```
 
#### TC-07
 
**HTTP methods:** `allowTrace` absent or `false`.  
**Rule:** Always.
 
```yaml
- id: TC-07
  title: TRACE not enabled on any connector
  file: server
  expect: absent
  applies: true
  xpath: "//Connector[@allowTrace and @allowTrace!='false']"
```
 
#### TC-08
 
**Banner:** `xpoweredBy` false; `server` attribute (if set) is generic.  
**Rule:** Always.
 
```yaml
- id: TC-08
  title: No X-Powered-By and no product/version in the Server header
  file: server
  expect: absent
  applies: true
  xpath: >-
    //Connector[(@xpoweredBy and @xpoweredBy!='false')
    or contains(translate(@server,'TOMCATOYE','tomcatoye'),'tomcat')
    or contains(translate(@server,'TOMCATOYE','tomcatoye'),'coyote')]
```
 
#### TC-09
 
**Banner:** `lib/org/apache/catalina/util/ServerInfo.properties` overrides `server.info`, `server.number` and `server.built`.  
**Rule:** Always.
 
```yaml
- name: "TC-09 | look for ServerInfo.properties override (base/lib first, then home/lib)"
  ansible.builtin.slurp:
    src: "{{ item }}/lib/org/apache/catalina/util/ServerInfo.properties"
  loop: "{{ [catalina_base, catalina_home] | unique }}"
  register: tc_serverinfo
  failed_when: false
  tags: [files]
 
- name: "TC-09 | override must exist and hide product name and version"
  vars:
    tc_si: "{{ (tc_serverinfo.results | selectattr('content', 'defined') | map(attribute='content') | first | default('')) | b64decode }}"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-09', 'title': 'ServerInfo.properties override missing or still reveals product/version',
                     'detail': 'override not found' if tc_si == '' else 'server.info/server.number/server.built not all neutralised'}] }}"
  when: >-
    tc_si == ''
    or not (tc_si is search('(?m)^server\.info=') and tc_si is search('(?m)^server\.number=') and tc_si is search('(?m)^server\.built='))
    or tc_si is search('(?im)^server[.](info|number|built)=.*tomcat')
    or (tc_version != '0' and tc_si is search('(?m)^server[.](info|number)=.*' ~ (tc_version | regex_escape)))
  tags: [files]
```
 
#### TC-10
 
**URI parsing:** No `allowBackslash`, `encodedSolidusHandling=reject`, no `relaxedPathChars`/`relaxedQueryChars`. Non-standard parsing behind a proxy enables access-control bypasses.  
**Rule:** Always.
 
```yaml
- id: TC-10
  title: No relaxed / non-standard URI parsing (proxy bypass risk)
  file: server
  expect: absent
  applies: true
  xpath: >-
    //Connector[(@allowBackslash and @allowBackslash!='false')
    or (@encodedSolidusHandling and @encodedSolidusHandling!='reject')
    or @relaxedPathChars or @relaxedQueryChars]
```
 
#### TC-11
 
**URI parsing:** `rejectSuspiciousURIs="true"` and `encodedReverseSolidusHandling="reject"` on HTTP connectors. **In the lab this returned 400 for `/x/..;/manager/html`, `/;a=b/…`, `%2e%2e`, `%2f` and `%5c` variants.**  
**Rule:** Default on (`tomcat_strict_uri_checks`). Disable only with documented app incompatibility.
 
```yaml
- id: TC-11
  title: Suspicious URIs and encoded backslash rejected (rejectSuspiciousURIs, encodedReverseSolidusHandling)
  file: server
  expect: absent
  applies: "{{ tomcat_strict_uri_checks | bool }}"
  xpath: >-
    //Connector[not({{ tc_x_ajp }})][not(@rejectSuspiciousURIs='true')
    or not(@encodedReverseSolidusHandling='reject')]
# TC-12 (one check per limit) -----------------------------------------
```
 
#### TC-12
 
**DoS limits:** `connectionTimeout`, `maxPostSize`, `maxParameterCount`, `maxPartCount`, `maxPartHeaderSize`, `maxHttpHeaderSize`, `maxSwallowSize` explicitly set, ≤ policy, never `-1`.  
**Rule:** Always. Explicit values protect against default changes between versions.
 
```yaml
- id: TC-12a
  title: "connectionTimeout set and <= {{ tomcat_limits.connectionTimeout }}"
  file: server
  expect: absent
  applies: true
  xpath: "//Connector[not(@connectionTimeout) or @connectionTimeout > {{ tomcat_limits.connectionTimeout }} or @connectionTimeout < 0 or string(number(@connectionTimeout))='NaN']"
- id: TC-12b
  title: "maxPostSize set and <= {{ tomcat_limits.maxPostSize }}"
  file: server
  expect: absent
  applies: true
  xpath: "//Connector[not(@maxPostSize) or @maxPostSize > {{ tomcat_limits.maxPostSize }} or @maxPostSize < 0 or string(number(@maxPostSize))='NaN']"
- id: TC-12c
  title: "maxParameterCount set and <= {{ tomcat_limits.maxParameterCount }}"
  file: server
  expect: absent
  applies: true
  xpath: "//Connector[not(@maxParameterCount) or @maxParameterCount > {{ tomcat_limits.maxParameterCount }} or @maxParameterCount < 0 or string(number(@maxParameterCount))='NaN']"
- id: TC-12d
  title: "maxPartCount set and <= {{ tomcat_limits.maxPartCount }}"
  file: server
  expect: absent
  applies: true
  xpath: "//Connector[not({{ tc_x_ajp }})][not(@maxPartCount) or @maxPartCount > {{ tomcat_limits.maxPartCount }} or @maxPartCount < 0 or string(number(@maxPartCount))='NaN']"
- id: TC-12e
  title: "maxPartHeaderSize set and <= {{ tomcat_limits.maxPartHeaderSize }}"
  file: server
  expect: absent
  applies: true
  xpath: "//Connector[not({{ tc_x_ajp }})][not(@maxPartHeaderSize) or @maxPartHeaderSize > {{ tomcat_limits.maxPartHeaderSize }} or @maxPartHeaderSize < 0 or string(number(@maxPartHeaderSize))='NaN']"
- id: TC-12f
  title: "maxHttpHeaderSize set and <= {{ tomcat_limits.maxHttpHeaderSize }}"
  file: server
  expect: absent
  applies: true
  xpath: "//Connector[not({{ tc_x_ajp }})][not(@maxHttpHeaderSize) or @maxHttpHeaderSize > {{ tomcat_limits.maxHttpHeaderSize }} or @maxHttpHeaderSize < 0 or string(number(@maxHttpHeaderSize))='NaN']"
- id: TC-12g
  title: "maxSwallowSize set and <= {{ tomcat_limits.maxSwallowSize }}"
  file: server
  expect: absent
  applies: true
  xpath: "//Connector[not({{ tc_x_ajp }})][not(@maxSwallowSize) or @maxSwallowSize > {{ tomcat_limits.maxSwallowSize }} or @maxSwallowSize < 0 or string(number(@maxSwallowSize))='NaN']"
```
 
#### TC-13
 
**TLS:** TLS on Tomcat: `SSLHostConfig protocols` = policy (`TLSv1.2+TLSv1.3`) plus explicit `ciphers`. The Tomcat default `all` includes TLSv1/1.1.  
**Rule:** **Not needed (TLS at proxy) → no TLS connector.** **Needed →** pinned protocols and ciphers. Put only TLS 1.2 suites in `ciphers` (Tomcat moves 1.3 suites and warns).
 
```yaml
- id: TC-13a
  title: "TLS connectors pin protocols to {{ tomcat_tls_protocols }} and set an explicit cipher list"
  file: server
  expect: absent
  applies: "{{ tomcat_needs_tls_on_tomcat | bool }}"
  xpath: >-
    //SSLHostConfig[not(@protocols) or @protocols!='{{ tomcat_tls_protocols }}' or not(@ciphers)]
    | //Connector[@SSLEnabled='true'][not(SSLHostConfig)]
- id: TC-13b
  title: No TLS connector defined (TLS is terminated elsewhere)
  file: server
  expect: absent
  applies: "{{ not tomcat_needs_tls_on_tomcat | bool }}"
  xpath: "//Connector[@SSLEnabled='true'] | //SSLHostConfig"
```
 
#### TC-14
 
**Secrets:** No inline `certificateKeystorePassword`/`certificateKeyPassword`/`keystorePass`/`truststorePass`. Use `certificateKeystorePasswordFile` (root:tomcat 0640).  
**Rule:** Always.
 
```yaml
- id: TC-14
  title: Keystore/key passwords not inline in server.xml (use *PasswordFile)
  file: server
  expect: absent
  applies: true
  xpath: >-
    //Certificate[@certificateKeystorePassword or @certificateKeyPassword]
    | //SSLHostConfig[@truststorePassword]
    | //Connector[@keystorePass or @keyPass or @SSLPassword or @truststorePass]
```
 
#### TC-15
 
**HTTP/2:** No `Http2Protocol`.  
**Rule:** **Not needed → remove.** **Needed →** `maxConcurrentStreams` ≤ policy plus a current patch level (HTTP/2 DoS CVEs).
 
```yaml
- id: TC-15a
  title: HTTP/2 upgrade protocol not configured
  file: server
  expect: absent
  applies: "{{ not tomcat_needs_http2 | bool }}"
  xpath: "//UpgradeProtocol[contains(@className,'Http2Protocol')]"
- id: TC-15b
  title: "HTTP/2 (if needed) limits maxConcurrentStreams <= {{ tomcat_http2_max_concurrent_streams }}"
  file: server
  expect: absent
  applies: "{{ tomcat_needs_http2 | bool }}"
  xpath: >-
    //UpgradeProtocol[contains(@className,'Http2Protocol')][not(@maxConcurrentStreams)
    or @maxConcurrentStreams > {{ tomcat_http2_max_concurrent_streams }} or string(number(@maxConcurrentStreams))='NaN']
```
 
#### TC-16
 
**Proxy trust:** `RemoteIpValve` has explicit `internalProxies` (its default trusts all RFC 1918/loopback ranges, so any internal host can spoof client IPs). If TLS ends at the proxy, Tomcat must be told: `RemoteIpValve` or `secure="true" scheme="https"`.  
**Rule:** Always for 16a. 16b when `tomcat_tls_terminated_at_proxy`: without it HSTS is not sent and requests look insecure.
 
```yaml
- id: TC-16a
  title: RemoteIpValve/Filter trusts only explicit proxy IPs (default trusts all RFC1918 ranges)
  file: server
  expect: absent
  applies: true
  xpath: >-
    //Valve[contains(@className,'RemoteIpValve')][not(@internalProxies) or @internalProxies='.*'
    or @trustedProxies='.*']
- id: TC-16b
  title: TLS terminated at proxy is signalled to Tomcat (RemoteIpValve or secure/scheme on connector)
  file: server
  expect: present
  applies: "{{ tomcat_tls_terminated_at_proxy | bool }}"
  xpath: >-
    //Valve[contains(@className,'RemoteIpValve')]
    | //Connector[@secure='true' and @scheme='https']
```
 
#### TC-17
 
**Deployment:** `autoDeploy="false"` and `deployXML="false"` on every Host.  
**Rule:** Always. Note: with `deployXML=false`, apps with their own `META-INF/context.xml` (e.g. manager) **do not deploy** until a descriptor exists in `conf/<engine>/<host>/` (seen in the lab).
 
```yaml
- id: TC-17
  title: No automatic deployment and no app-supplied context.xml (autoDeploy/deployXML false)
  file: server
  expect: absent
  applies: true
  xpath: "//Host[not(@autoDeploy='false') or not(@deployXML='false')]"
```
 
#### TC-18
 
**Error output:** Every Host has `ErrorReportValve showReport="false" showServerInfo="false"`.  
**Rule:** Always.
 
```yaml
- id: TC-18
  title: Every Host has ErrorReportValve with showReport and showServerInfo false
  file: server
  expect: absent
  applies: true
  xpath: >-
    //Host[not(Valve[@className='org.apache.catalina.valves.ErrorReportValve'
    and @showReport='false' and @showServerInfo='false'])]
```
 
#### TC-19
 
**Logging:** `AccessLogValve` on every Host (or Engine). Pattern has no session ID (`%S`), cookies (`%{..}c`) or `Authorization` header.  
**Rule:** Always.
 
```yaml
- id: TC-19a
  title: Access logging enabled for every Host (Host or Engine level)
  file: server
  expect: absent
  applies: true
  xpath: >-
    //Host[not(Valve[contains(@className,'AccessLogValve')])]
    [not(../Valve[contains(@className,'AccessLogValve')])]
- id: TC-19b
  title: Access log pattern does not record session IDs, cookies or Authorization headers
  file: server
  expect: absent
  applies: true
  xpath: >-
    //Valve[contains(@className,'AccessLogValve')][contains(@pattern,'%S') or contains(@pattern,'}c')
    or contains(translate(@pattern,'AUTHORIZATION','authorization'),'authorization')]
```
 
#### TC-20
 
**Authentication:** No `Realm`.  
**Rule:** **Not needed → no Realm.** **Needed →** top-level `LockOutRealm` with `failureCount` ≤ policy and `lockOutTime` ≥ policy (Realms do not lock accounts by default).
 
```yaml
- id: TC-20a
  title: No Realm configured (container authentication not used)
  file: server
  expect: absent
  applies: "{{ not tomcat_needs_container_auth | bool }}"
  xpath: "//Realm"
- id: TC-20b
  title: Every top-level Realm is a LockOutRealm with policy thresholds
  file: server
  expect: absent
  applies: "{{ tomcat_needs_container_auth | bool }}"
  xpath: >-
    //Realm[not(ancestor::Realm)][not(@className='org.apache.catalina.realm.LockOutRealm')
    or (@failureCount and @failureCount > {{ tomcat_lockout_failure_count_max }})
    or not(@lockOutTime) or @lockOutTime < {{ tomcat_lockout_time_min }}
    or string(number(@lockOutTime))='NaN' or (@failureCount and string(number(@failureCount))='NaN')]
```
 
#### TC-21
 
**Authentication:** Password realms use `SecretKeyCredentialHandler` with `PBKDF2WithHmacSHA512` and ≥ policy iterations. Without a handler, stored passwords are compared in **plaintext**.  
**Rule:** Only when container auth is needed.
 
```yaml
- id: TC-21
  title: "Password realms store PBKDF2 hashes ({{ tomcat_pbkdf2_algorithm }}, >= {{ tomcat_pbkdf2_min_iterations }} iterations)"
  file: server
  expect: absent
  applies: "{{ tomcat_needs_container_auth | bool }}"
  xpath: >-
    //Realm[contains(@className,'UserDatabaseRealm') or contains(@className,'DataSourceRealm')
    or contains(@className,'MemoryRealm')]
    [not(CredentialHandler[@className='org.apache.catalina.realm.SecretKeyCredentialHandler'
    and @algorithm='{{ tomcat_pbkdf2_algorithm }}' and @iterations >= {{ tomcat_pbkdf2_min_iterations }}])]
```
 
#### TC-22
 
**Authentication:** `tomcat-users.xml`: no users if not needed; otherwise hashed passwords only, no default names, no `manager-script`/`manager-jmx`/`admin-script`.  
**Rule:** **Not needed → no users.** **Needed →** as stated.
 
```yaml
- id: TC-22a
  title: tomcat-users.xml defines no users (container authentication not used)
  file: users
  expect: absent
  applies: "{{ not tomcat_needs_container_auth | bool }}"
  xpath: "//*[local-name()='user']"
- id: TC-22b
  title: tomcat-users.xml has no plaintext passwords, default user names or scripting roles
  file: users
  expect: absent
  applies: "{{ tomcat_needs_container_auth | bool }}"
  xpath: >-
    //*[local-name()='user'][(@password and not(contains(@password,'$')))
    {% for u in tomcat_forbidden_usernames %} or @username='{{ u }}'{% endfor %}
    {% for r in tomcat_forbidden_roles %} or contains(concat(',',translate(@roles,' ',''),','),',{{ r }},'){% endfor %}]
```
 
#### TC-23
 
**Clustering:** No `Cluster`.  
**Rule:** **Not needed → remove.** **Needed →** `Receiver` bound to an explicit internal address (default `auto`), on an isolated network/IPsec/TLS. `EncryptInterceptor` is deprecated and not a security control.
 
```yaml
- id: TC-23a
  title: No Cluster element (session replication not used)
  file: server
  expect: absent
  applies: "{{ not tomcat_needs_cluster | bool }}"
  xpath: "//Cluster"
- id: TC-23b
  title: Cluster (if needed) defines a Receiver bound to an explicit internal address (default is "auto")
  file: server
  expect: present
  applies: "{{ tomcat_needs_cluster | bool }}"
  xpath: "//Cluster//Receiver[@address and @address!='auto' and @address!='0.0.0.0' and @address!='::']"
```
 
#### TC-24
 
**Secrets:** No plaintext `*password*`/`*Pass*` attributes in server.xml, conf/context.xml, app and descriptor context files. Use `${…}` property substitution from a protected source.  
**Rule:** Always.
 
```yaml
- id: TC-24a
  title: No plaintext password attributes in server.xml (use ${...} property substitution)
  file: server
  expect: absent
  applies: true
  xpath: >-
    //@*[contains(translate(local-name(),'PASW','pasw'),'pass')]
    [not(substring(local-name(), string-length(local-name()) - 3) = 'File')]
    [not(starts-with(normalize-space(.),'${'))]
- id: TC-24b
  title: No plaintext password attributes in conf/context.xml
  file: context
  expect: absent
  applies: true
  xpath: >-
    //@*[contains(translate(local-name(),'PASW','pasw'),'pass')]
    [not(substring(local-name(), string-length(local-name()) - 3) = 'File')]
    [not(starts-with(normalize-space(.),'${'))]
- id: TC-24c
  title: No plaintext password attributes in app/descriptor context.xml
  kind: context
  expect: absent
  applies: true
  xpath: >-
    //@*[contains(translate(local-name(),'PASW','pasw'),'pass')]
    [not(substring(local-name(), string-length(local-name()) - 3) = 'File')]
    [not(starts-with(normalize-space(.),'${'))]
```
 
#### TC-25
 
**Sessions:** No session persistence (no `pathname`, `PersistentManager` or `Store`). **Tomcat 9:** `<Manager pathname=""/>` must be explicit (persistence is on by default there; off by default in 10.1/11).  
**Rule:** **Not needed → disabled.** **Needed →** `sessionAttributeValueClassNameFilter` and no `FileStore` (CVE-2025-24813 chain used file-based persistence).
 
```yaml
- id: TC-25a
  title: No session persistence to disk/store in conf/context.xml or server.xml
  file: context
  expect: absent
  applies: "{{ not tomcat_needs_session_persistence | bool }}"
  xpath: "//Manager[string-length(@pathname) > 0 or contains(@className,'PersistentManager')] | //Store"
- id: TC-25b
  title: "Tomcat 9: StandardManager persistence explicitly disabled (<Manager pathname=\"\"/>)"
  file: context
  expect: present
  applies: "{{ (not tomcat_needs_session_persistence | bool) and (tc_major | default('0')) == '9' }}"
  xpath: "/Context/Manager[@pathname='']"
- id: TC-25c
  title: Session persistence (if needed) restricts deserialised classes and uses no FileStore
  file: context
  expect: absent
  applies: "{{ tomcat_needs_session_persistence | bool }}"
  xpath: "//Manager[not(@sessionAttributeValueClassNameFilter)] | //Store[contains(@className,'FileStore')]"
- id: TC-25d
  title: App/descriptor context does not enable session persistence
  kind: context
  expect: absent
  applies: "{{ not tomcat_needs_session_persistence | bool }}"
  xpath: "//Manager[string-length(@pathname) > 0 or contains(@className,'PersistentManager')] | //Store"
```
 
#### TC-26
 
**Context:** No `privileged`/`crossContext`/`allowLinking`. `useHttpOnly` not disabled. Exception: approved admin apps may be `privileged`.  
**Rule:** Always.
 
```yaml
- id: TC-26
  title: Global context not privileged, no crossContext, no allowLinking, HttpOnly not disabled
  file: context
  expect: absent
  applies: true
  xpath: >-
    /Context[(@privileged and @privileged!='false') or (@crossContext and @crossContext!='false')
    or (@useHttpOnly and @useHttpOnly!='true')] | //Resources[@allowLinking and @allowLinking!='false']
- id: TC-26b
  title: App/descriptor context not privileged/crossContext/allowLinking (except approved admin apps)
  kind: context
  expect: absent
  applies: true
  xpath: >-
    /Context[(@crossContext and @crossContext!='false') or (@useHttpOnly and @useHttpOnly!='true')]
    | //Resources[@allowLinking and @allowLinking!='false']
```
 
#### TC-27
 
**Cookies:** Global `CookieProcessor sameSiteCookies="strict"` or `"lax"`.  
**Rule:** Always.
 
```yaml
- id: TC-27
  title: Global CookieProcessor sets SameSite (lax or strict)
  file: context
  expect: present
  applies: true
  xpath: "/Context/CookieProcessor[@sameSiteCookies='strict' or @sameSiteCookies='lax']"
```
 
#### TC-28
 
**Admin apps:** `RemoteCIDRValve`/`RemoteAddrValve` with a restricted `allow` (no `0.0.0.0/0`, `::/0`) in **both** the app's context.xml and its `conf/<engine>/<host>/` descriptor.  
**Rule:** **Not needed → apps absent (TC-29).** **Needed →** as stated, plus proxy-side block and MFA (A-11).
 
```yaml
- id: TC-28
  title: Admin app context restricts clients with RemoteCIDRValve (no any-address allow)
  kind: admin_context
  expect: present
  applies: "{{ tomcat_needs_manager | bool }}"
  xpath: >-
    /Context/Valve[contains(@className,'RemoteCIDRValve') or contains(@className,'RemoteAddrValve')]
    [@allow and string-length(normalize-space(@allow)) > 0]
    {% for c in tomcat_manager_allow_cidrs_forbidden %}[not(contains(@allow,'{{ c }}'))]{% endfor %}
```
 
#### TC-29
 
**Deployment:** Contents of `webapps/` (dirs + WARs) and `conf/<engine>/<host>/*.xml` match an allow-list. ROOT/docs/examples/manager/host-manager absent unless approved. Descriptors can deploy code from **outside** `webapps/`.  
**Rule:** Always.
 
```yaml
- name: "TC-29 | list webapps/ entries (directories and WARs)"
  ansible.builtin.find:
    paths: "{{ catalina_base }}/webapps"
    file_type: any
    recurse: false
    hidden: true
  register: tc_webapps
  tags: [files]
 
- name: "TC-29 | only approved apps deployed; default apps absent"
  vars:
    tc_allowed: "{{ tomcat_approved_apps + (['manager', 'host-manager'] if tomcat_needs_manager | bool else []) }}"
    tc_deployed: "{{ tc_webapps.files | map(attribute='path') | map('basename') | map('regex_replace', '[.]war$', '') | unique | list }}"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-29', 'title': 'Unapproved or default application deployed', 'detail': tc_deployed | difference(tc_allowed) | join(', ')}] }}"
  when: tc_deployed | difference(tc_allowed) | length > 0
  tags: [files]
 
- name: "TC-29 | only approved context descriptors in conf/<engine>/<host>/ (they can deploy apps from outside webapps/)"
  vars:
    tc_allowed: "{{ tomcat_approved_context_descriptors + (['manager', 'host-manager'] if tomcat_needs_manager | bool else []) }}"
    tc_desc: "{{ tc_desc_find.files | default([]) | map(attribute='path') | map('basename') | map('regex_replace', '[.]xml$', '') | list }}"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-29', 'title': 'Unapproved context descriptor', 'detail': tc_desc | difference(tc_allowed) | join(', ')}] }}"
  when: tc_desc | difference(tc_allowed) | length > 0
  tags: [files]
```
 
#### TC-30
 
**DefaultServlet:** `readonly=true`, `listings=false`, `allowPartialPut=false`, `showServerInfo=false` (global). Apps must not re-enable writes or listings (`WEB-INF/web.xml`, `WEB-INF/tomcat-web.xml`).  
**Rule:** **Writes not needed → read-only everywhere.** If needed: authenticated, separate context.
 
```yaml
- id: TC-30a
  title: Global DefaultServlet is read-only and lists no directories
  file: web
  expect: absent
  applies: "{{ not tomcat_needs_write_methods | bool }}"
  xpath: >-
    {{ tc_x_defaultservlet }}[*[local-name()='init-param'][
    (normalize-space(*[local-name()='param-name'])='readonly' and normalize-space(*[local-name()='param-value'])!='true')
    or (normalize-space(*[local-name()='param-name'])='listings' and normalize-space(*[local-name()='param-value'])!='false')]]
- id: TC-30b
  title: Global DefaultServlet explicitly disables partial PUT and server info (defence in depth)
  file: web
  expect: present
  applies: true
  xpath: >-
    {{ tc_x_defaultservlet }}
    [*[local-name()='init-param'][normalize-space(*[local-name()='param-name'])='readonly' and normalize-space(*[local-name()='param-value'])='true']]
    [*[local-name()='init-param'][normalize-space(*[local-name()='param-name'])='allowPartialPut' and normalize-space(*[local-name()='param-value'])='false']]
    [*[local-name()='init-param'][normalize-space(*[local-name()='param-name'])='showServerInfo' and normalize-space(*[local-name()='param-value'])='false']]
- id: TC-30c
  title: App does not re-enable writes or listings on DefaultServlet
  kind: webxml
  expect: absent
  applies: "{{ not tomcat_needs_write_methods | bool }}"
  xpath: >-
    {{ tc_x_defaultservlet }}[*[local-name()='init-param'][
    (normalize-space(*[local-name()='param-name'])='readonly' and normalize-space(*[local-name()='param-value'])!='true')
    or (normalize-space(*[local-name()='param-name'])='listings' and normalize-space(*[local-name()='param-value'])!='false')]]
```
 
#### TC-31
 
**Servlets:** No `WebdavServlet` / `CGIServlet` (global or in apps).  
**Rule:** **Not needed → not declared.**
 
```yaml
- id: TC-31a
  title: No WebDAV servlet in global web.xml
  file: web
  expect: absent
  applies: "{{ not tomcat_needs_write_methods | bool }}"
  xpath: "//*[local-name()='servlet-class'][contains(normalize-space(),'WebdavServlet')]"
- id: TC-31b
  title: No CGI servlet in global web.xml
  file: web
  expect: absent
  applies: "{{ not tomcat_needs_cgi | bool }}"
  xpath: "//*[local-name()='servlet-class'][contains(normalize-space(),'CGIServlet')]"
- id: TC-31c
  title: App declares no WebDAV / CGI servlet
  kind: webxml
  expect: absent
  applies: "{{ not (tomcat_needs_write_methods | bool or tomcat_needs_cgi | bool) }}"
  xpath: "//*[local-name()='servlet-class'][contains(normalize-space(),'WebdavServlet') or contains(normalize-space(),'CGIServlet')]"
```
 
#### TC-32
 
**JSP:** `JspServlet` removed from global web.xml: a dropped `.jsp` web shell cannot run.  
**Rule:** **Runtime JSP not needed → remove** (precompile JSPs with JspC). Default switch is `true` because many apps need it.
 
```yaml
- id: TC-32
  title: JspServlet removed (no runtime JSP compilation -> dropped .jsp files cannot execute)
  file: web
  expect: absent
  applies: "{{ not tomcat_needs_runtime_jsp | bool }}"
  xpath: "//*[local-name()='servlet-class'][normalize-space()='org.apache.jasper.servlet.JspServlet']"
```
 
#### TC-33
 
**Session cookie:** `cookie-config` `http-only` and `secure` true, `tracking-mode` COOKIE only, `session-timeout` 1..policy. Apps must not weaken these.  
**Rule:** Always.
 
```yaml
- id: TC-33a
  title: Session cookie is HttpOnly and Secure (global web.xml)
  file: web
  expect: present
  applies: true
  xpath: >-
    //*[local-name()='session-config']/*[local-name()='cookie-config']
    [*[local-name()='http-only'][normalize-space()='true']][*[local-name()='secure'][normalize-space()='true']]
- id: TC-33b
  title: Session tracking via cookie only (no ;jsessionid in URLs)
  file: web
  expect: present
  applies: true
  xpath: >-
    //*[local-name()='session-config'][*[local-name()='tracking-mode'][normalize-space()='COOKIE']]
    [not(*[local-name()='tracking-mode'][normalize-space()!='COOKIE'])]
- id: TC-33c
  title: "Session timeout set, > 0 and <= {{ tomcat_session_timeout_max }} minutes"
  file: web
  expect: present
  applies: true
  xpath: >-
    //*[local-name()='session-config']/*[local-name()='session-timeout']
    [number(normalize-space()) > 0 and number(normalize-space()) <= {{ tomcat_session_timeout_max }}]
- id: TC-33d
  title: App does not weaken session cookie / tracking settings
  kind: webxml
  expect: absent
  applies: true
  xpath: >-
    //*[local-name()='cookie-config']/*[(local-name()='http-only' or local-name()='secure') and normalize-space()!='true']
    | //*[local-name()='tracking-mode'][normalize-space()!='COOKIE']
```
 
#### TC-34
 
**Headers:** `HttpHeaderSecurityFilter` mapped to `/*`, `hstsMaxAgeSeconds` ≥ 1 year (**default is 0**), click-jacking/nosniff not disabled. HSTS is only sent on requests Tomcat sees as secure (see TC-16b).  
**Rule:** Always (coordinate with headers set by the proxy).
 
```yaml
- id: TC-34a
  title: "HttpHeaderSecurityFilter defined with hstsMaxAgeSeconds >= {{ tomcat_hsts_min_age }} (default is 0)"
  file: web
  expect: present
  applies: true
  xpath: >-
    //*[local-name()='filter'][*[local-name()='filter-class'][normalize-space()='org.apache.catalina.filters.HttpHeaderSecurityFilter']]
    [normalize-space(*[local-name()='filter-name'])='{{ tomcat_header_filter_name }}']
    [*[local-name()='init-param'][normalize-space(*[local-name()='param-name'])='hstsMaxAgeSeconds'
    and number(normalize-space(*[local-name()='param-value'])) >= {{ tomcat_hsts_min_age }}]]
    [not(*[local-name()='init-param'][(normalize-space(*[local-name()='param-name'])='antiClickJackingEnabled'
    or normalize-space(*[local-name()='param-name'])='blockContentTypeSniffingEnabled'
    or normalize-space(*[local-name()='param-name'])='hstsEnabled')
    and normalize-space(*[local-name()='param-value'])!='true'])]
- id: TC-34b
  title: HttpHeaderSecurityFilter is mapped to /*
  file: web
  expect: present
  applies: true
  xpath: >-
    //*[local-name()='filter-mapping'][normalize-space(*[local-name()='filter-name'])='{{ tomcat_header_filter_name }}']
    [*[local-name()='url-pattern'][normalize-space()='/*']]
```
 
#### TC-35
 
**Error output:** Global `<error-page>` for `java.lang.Throwable`.  
**Rule:** Always.
 
```yaml
- id: TC-35
  title: Global error page for java.lang.Throwable (no stack traces from the app layer)
  file: web
  expect: present
  applies: true
  xpath: >-
    //*[local-name()='error-page'][*[local-name()='exception-type'][normalize-space()='java.lang.Throwable']]
```
 
#### TC-36
 
**Files:** No file in CATALINA_HOME/BASE owned by the runtime user except logs/temp/work. No group/world-writable code or config. conf/ not world-readable. logs/temp/work owned by runtime user, no world access. **A check that cannot run is itself a finding.**  
**Rule:** Always.
 
```yaml
- name: "TC-36 | files owned by the runtime user outside logs/temp/work"
  # find HOME BASE -xdev -regextype posix-extended -regex '^BASE/(logs|temp|work)$' -prune -o -user tomcat -print
  ansible.builtin.command:
    argv: >-
      {{ ['find'] + ([catalina_home, catalina_base] | unique)
         + ['-xdev', '-regextype', 'posix-extended',
            '-regex', '^' ~ (catalina_base | regex_escape) ~ '/(' ~ (tomcat_writable_dirs | join('|')) ~ ')$',
            '-prune', '-o', '-user', tomcat_user, '-print'] }}
  register: tc_owned
  changed_when: false
  failed_when: false
  tags: [files]
 
- name: "TC-36 | group- or world-writable files/dirs in code and config locations"
  ansible.builtin.command:
    argv: >-
      {{ ['find'] + ([catalina_home ~ '/bin', catalina_home ~ '/lib', catalina_base ~ '/conf', catalina_base ~ '/lib', catalina_base ~ '/webapps'] | unique)
         + ['-xdev', '(', '-perm', '-0020', '-o', '-perm', '-0002', ')', '!', '-type', 'l', '-print'] }}
  register: tc_writable
  changed_when: false
  failed_when: false
  tags: [files]
 
- name: "TC-36 | world-readable files in conf/ (secrets, keystores, users)"
  ansible.builtin.command:
    argv: ["find", "{{ catalina_base }}/conf", "-xdev", "-type", "f", "-perm", "-0004", "-print"]
  register: tc_worldread
  changed_when: false
  failed_when: false
  tags: [files]
 
- name: "TC-36 | a check that cannot run is a finding (never a silent pass)"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-36', 'title': 'Permission check could not run completely', 'detail': (r.cmd | default([]) | join(' ')) ~ ' :: ' ~ (r.stderr | default(''))[:300]}] }}"
  loop: [tc_owned, tc_writable, tc_worldread]
  loop_control: { label: "{{ item }}" }
  vars:
    r: "{{ lookup('vars', item) }}"
  when: (r.rc | default(1)) != 0
  tags: [files]
 
- name: "TC-36 | logs/temp/work owned by runtime user and not world-accessible"
  ansible.builtin.stat:
    path: "{{ catalina_base }}/{{ item }}"
  loop: "{{ tomcat_writable_dirs }}"
  register: tc_wdirs
  tags: [files]
 
- name: "TC-36 | record ownership findings"
  ansible.builtin.set_fact:
    tc_findings: >-
      {{ tc_findings
         + ([{'id': 'TC-36', 'title': 'Code/config owned by runtime user', 'detail': tc_owned.stdout_lines[:20] | join(', ')}] if tc_owned.stdout_lines | length > 0 else [])
         + ([{'id': 'TC-36', 'title': 'Group/world-writable code or config', 'detail': tc_writable.stdout_lines[:20] | join(', ')}] if tc_writable.stdout_lines | length > 0 else [])
         + ([{'id': 'TC-36', 'title': 'World-readable files in conf/', 'detail': tc_worldread.stdout_lines[:20] | join(', ')}] if tc_worldread.stdout_lines | length > 0 else []) }}
  tags: [files]
 
- name: "TC-36 | record findings for logs/temp/work"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-36', 'title': 'Writable dir missing, not owned by runtime user, or world-accessible', 'detail': catalina_base ~ '/' ~ d.item}] }}"
  loop: "{{ tc_wdirs.results }}"
  loop_control: { loop_var: d, label: "{{ d.item }}" }
  when: >-
    not d.stat.exists
    or d.stat.pw_name != tomcat_user
    or d.stat.roth or d.stat.woth or d.stat.xoth
  tags: [files]
```
 
#### TC-37
 
**Probe:** 404 and 400 error pages contain no product, version or stack trace.  
**Rule:** Run against Tomcat **and** through the proxy.
 
```yaml
- name: "TC-37 | error pages reveal no product, version or stack trace"
  ansible.builtin.uri:
    validate_certs: "{{ tomcat_probe_validate_certs | default(true) }}"
    url: "{{ tomcat_probe_base_url }}{{ item }}"
    return_content: true
    status_code: [400, 404]
  loop: ["/tc-audit-{{ 99999999 | random }}-notfound", "/%zz"]
  register: tc_p_err
  failed_when: false
 
- name: "TC-37 | record: error page leaks product/version/stack trace"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-37', 'title': 'Error page leaks product/version/stack trace or probe failed', 'detail': r.url ~ ' HTTP ' ~ (r.status | string)}] }}"
  loop: "{{ tc_p_err.results }}"
  loop_control: { loop_var: r, label: "{{ r.url | default('') }}" }
  when: >-
    (r.status | int) not in [400, 404]
    or (r.content | default('')) is search('(?i)apache tomcat|coyote|\\b(9|10|11)\\.\\d+\\.\\d+\\b|exception|at org\\.apache')
```
 
#### TC-38
 
**Probe:** TRACE refused on `/` **and on a static path**. JSP/welcome paths return 405 even with `allowTrace=true`, so probing `/` alone is a false pass (seen in the lab).  
**Rule:** Always.
 
```yaml
- name: "TC-38 | TRACE is refused (a static path is needed: JSP/welcome paths refuse TRACE even when allowTrace=true)"
  ansible.builtin.uri:
    validate_certs: "{{ tomcat_probe_validate_certs | default(true) }}"
    url: "{{ tomcat_probe_base_url }}{{ item }}"
    method: TRACE
    status_code: [403, 405, 501]
  loop: ["/", "/tc-audit-trace-probe.txt"]
  register: tc_p_trace
  failed_when: false
 
- name: "TC-38 | record: TRACE accepted"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-38', 'title': 'TRACE not refused', 'detail': r.item ~ ' -> HTTP ' ~ (r.status | string)}] }}"
  loop: "{{ tc_p_trace.results }}"
  loop_control: { loop_var: r, label: "{{ r.item }}" }
  when: (r.status | int) not in [403, 405, 501]
```
 
#### TC-39
 
**Probe:** PUT and partial PUT refused, and the probe file is not retrievable.  
**Rule:** Always (when writes are not needed).
 
```yaml
- name: "TC-39 | PUT and partial PUT are refused"
  ansible.builtin.uri:
    validate_certs: "{{ tomcat_probe_validate_certs | default(true) }}"
    url: "{{ tomcat_probe_base_url }}/tc-audit-put-probe.txt"
    method: PUT
    body: "tc-audit"
    headers: "{{ item }}"
    status_code: [400, 401, 403, 404, 405, 501]
  loop:
    - {}
    - {"Content-Range": "bytes 0-7/16"}
  register: tc_p_put
  failed_when: false
 
- name: "TC-39 | probe file was not created"
  ansible.builtin.uri:
    validate_certs: "{{ tomcat_probe_validate_certs | default(true) }}"
    url: "{{ tomcat_probe_base_url }}/tc-audit-put-probe.txt"
    status_code: [403, 404]
  register: tc_p_put_get
  failed_when: false
 
- name: "TC-39 | record: PUT / partial PUT accepted"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-39', 'title': 'PUT / partial PUT not refused', 'detail': (r.item | to_json) ~ ' -> HTTP ' ~ (r.status | string)}] }}"
  loop: "{{ tc_p_put.results }}"
  loop_control: { loop_var: r, label: "{{ r.item | to_json }}" }
  when: (r.status | int) not in [400, 401, 403, 404, 405, 501]
 
- name: "TC-39 | record: probe file retrievable"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-39', 'title': 'PUT probe file is retrievable', 'detail': 'HTTP ' ~ (tc_p_put_get.status | string)}] }}"
  when: (tc_p_put_get.status | int) not in [403, 404]
```
 
#### TC-40
 
**Probe:** Admin paths return 400/403/404, including `..;`, `;param` and encoded variants. A 401 means **reachable**.  
**Rule:** Run from an untrusted segment and through the proxy.
 
```yaml
- name: "TC-40 | admin interfaces unreachable, incl. path-parameter/encoding bypass variants"
  ansible.builtin.uri:
    validate_certs: "{{ tomcat_probe_validate_certs | default(true) }}"
    url: "{{ tomcat_probe_base_url }}{{ item }}"
    follow_redirects: none
    status_code: [400, 403, 404]
  loop: "{{ tomcat_probe_admin_paths }}"
  register: tc_p_admin
  failed_when: false
 
- name: "TC-40 | record: admin path reachable"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-40', 'title': 'Admin path reachable (expected 400/403/404)', 'detail': r.item ~ ' -> HTTP ' ~ (r.status | string)}] }}"
  loop: "{{ tc_p_admin.results }}"
  loop_control: { loop_var: r, label: "{{ r.item }}" }
  when: (r.status | int) not in [400, 403, 404]
```
 
#### TC-41
 
**Probe:** No version in `Server`; `X-Content-Type-Options: nosniff`; `X-Frame-Options`; HSTS ≥ policy on HTTPS; session cookie `Secure; HttpOnly; SameSite`.  
**Rule:** Always.
 
```yaml
- name: "TC-41 | security headers and banner on an application URL"
  ansible.builtin.uri:
    validate_certs: "{{ tomcat_probe_validate_certs | default(true) }}"
    url: "{{ tomcat_probe_app_url | default(tomcat_probe_base_url ~ '/') }}"
    follow_redirects: none
    status_code: [200, 302, 401, 403]
  register: tc_p_hdr
  failed_when: false
 
- name: "TC-41 | session cookie flags (only if a session URL is configured)"
  ansible.builtin.uri:
    validate_certs: "{{ tomcat_probe_validate_certs | default(true) }}"
    url: "{{ tomcat_probe_session_url }}"
    follow_redirects: none
    status_code: [200, 302, 303]
  register: tc_p_cookie
  failed_when: false
  when: tomcat_probe_session_url | length > 0
 
- name: "TC-41 | record: banner and security headers"
  vars:
    tc_hdr: "{{ tc_p_hdr }}"
    tc_https: "{{ (tomcat_probe_app_url | default(tomcat_probe_base_url)) is match('https://') }}"
    tc_hsts_age: "{{ (tc_hdr.strict_transport_security | default('') | regex_findall('max-age=([0-9]+)') | first | default('0')) | int }}"
    tc_checks:
      - title: Server header reveals product/version
        bad: "{{ (tc_hdr.server | default('')) is search('(?i)tomcat|coyote|\\d+\\.\\d+') }}"
        detail: "{{ tc_hdr.server | default('') }}"
      - title: "X-Content-Type-Options: nosniff missing"
        bad: "{{ (tc_hdr.x_content_type_options | default('')) | lower != 'nosniff' }}"
        detail: "{{ tc_hdr.url | default('') }} HTTP {{ tc_hdr.status | default('') }}"
      - title: X-Frame-Options missing
        bad: "{{ (tc_hdr.x_frame_options | default('')) | length == 0 }}"
        detail: "{{ tc_hdr.url | default('') }} HTTP {{ tc_hdr.status | default('') }}"
      - title: HSTS missing or max-age below policy (HTTPS URLs only)
        bad: "{{ (tc_https | bool) and (tc_hsts_age | int) < (tomcat_hsts_min_age | int) }}"
        detail: "{{ tc_hdr.strict_transport_security | default('absent') }}"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-41', 'title': c.title, 'detail': c.detail}] }}"
  loop: "{{ tc_checks }}"
  loop_control: { loop_var: c, label: "{{ c.title }}" }
  when: c.bad | bool
 
- name: "TC-41 | record: session cookie flags"
  vars:
    tc_sc: "{{ tc_p_cookie.set_cookie | default('') }}"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-41', 'title': 'Session cookie lacks Secure/HttpOnly/SameSite', 'detail': tc_sc if tc_sc else 'no Set-Cookie'}] }}"
  when: >-
    tomcat_probe_session_url | length > 0 and not (
    tc_sc is search('(?i);\\s*secure') and tc_sc is search('(?i);\\s*httponly')
    and tc_sc is search('(?i);\\s*samesite=(lax|strict)'))
```
 
#### TC-42
 
**Probe:** An oversized request header (2× `maxHttpHeaderSize`) is rejected (400/413/431).  
**Rule:** Always.
 
```yaml
- name: "TC-42 | oversized request header rejected"
  ansible.builtin.uri:
    validate_certs: "{{ tomcat_probe_validate_certs | default(true) }}"
    url: "{{ tomcat_probe_base_url }}/"
    headers:
      X-TC-Audit-Pad: "{{ 'A' * ((tomcat_limits.maxHttpHeaderSize | int) * 2) }}"
    status_code: [400, 413, 431]
  register: tc_p_bighdr
  failed_when: false
 
- name: "TC-42 | record: oversized header not rejected"
  ansible.builtin.set_fact:
    tc_findings: "{{ tc_findings + [{'id': 'TC-42', 'title': 'Oversized header not rejected', 'detail': 'HTTP ' ~ (tc_p_bighdr.status | string)}] }}"
  when: (tc_p_bighdr.status | int) not in [400, 413, 431]
```
 
 
---
 
## Appendix — Reference hardened snippets (as used in the lab)
 
```xml
<!-- conf/server.xml (excerpt) -->
<Server port="-1" shutdown="DISABLED">
  <Listener className="org.apache.catalina.security.SecurityListener" checkedOsUsers="root" minimumUmask="0027" />
  <Service name="Catalina">
    <Connector port="8080" address="127.0.0.1" protocol="HTTP/1.1"
               server="webserver" xpoweredBy="false" allowTrace="false"
               connectionTimeout="20000" maxPostSize="2097152" maxParameterCount="1000"
               maxPartCount="50" maxPartHeaderSize="512" maxHttpHeaderSize="8192"
               maxSwallowSize="2097152" encodedSolidusHandling="reject"
               encodedReverseSolidusHandling="reject" allowBackslash="false"
               rejectSuspiciousURIs="true" />
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps" unpackWARs="false" autoDeploy="false" deployXML="false">
        <Valve className="org.apache.catalina.valves.AccessLogValve" directory="logs"
               prefix="localhost_access_log" suffix=".txt" pattern="%h %l %u %t &quot;%r&quot; %s %b %D" />
        <Valve className="org.apache.catalina.valves.ErrorReportValve" showReport="false" showServerInfo="false" />
      </Host>
    </Engine>
  </Service>
</Server>
```
 
```xml
<!-- TLS on Tomcat (only if tomcat_needs_tls_on_tomcat): no inline passwords -->
<SSLHostConfig protocols="TLSv1.2+TLSv1.3"
    ciphers="ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256"
    honorCipherOrder="true" disableSessionTickets="true">
  <Certificate certificateKeystoreFile="conf/secrets/ks.p12"
               certificateKeystorePasswordFile="conf/secrets/ks.pass" type="RSA" />
</SSLHostConfig>
```
 
```xml
<!-- conf/web.xml (additions) -->
<!-- inside the "default" DefaultServlet declaration -->
<init-param><param-name>readonly</param-name><param-value>true</param-value></init-param>
<init-param><param-name>allowPartialPut</param-name><param-value>false</param-value></init-param>
<init-param><param-name>showServerInfo</param-name><param-value>false</param-value></init-param>
 
<session-config>
  <session-timeout>15</session-timeout>
  <cookie-config><http-only>true</http-only><secure>true</secure></cookie-config>
  <tracking-mode>COOKIE</tracking-mode>
</session-config>
 
<filter>
  <filter-name>httpHeaderSecurity</filter-name>
  <filter-class>org.apache.catalina.filters.HttpHeaderSecurityFilter</filter-class>
  <init-param><param-name>hstsMaxAgeSeconds</param-name><param-value>31536000</param-value></init-param>
  <init-param><param-name>hstsIncludeSubDomains</param-name><param-value>true</param-value></init-param>
  <async-supported>true</async-supported>
</filter>
<filter-mapping>
  <filter-name>httpHeaderSecurity</filter-name>
  <url-pattern>/*</url-pattern>
  <dispatcher>REQUEST</dispatcher>
</filter-mapping>
 
<error-page>
  <exception-type>java.lang.Throwable</exception-type>
  <location>/error.html</location>
</error-page>
```
 
```xml
<!-- conf/context.xml (addition) -->
<CookieProcessor className="org.apache.tomcat.util.http.Rfc6265CookieProcessor" sameSiteCookies="strict" />
<!-- Tomcat 9.0 only: <Manager pathname="" /> -->
```
 
```properties
# CATALINA_BASE/lib/org/apache/catalina/util/ServerInfo.properties
server.info=Web Server
server.number=0.0.0.0
server.built=
```
 
```bash
# Ownership model (Tomcat security how-to): code/config root-owned, group tomcat read-only
chown -R root:tomcat "$CATALINA_HOME" "$CATALINA_BASE"
chmod -R u=rwX,g=rX,o= "$CATALINA_HOME" "$CATALINA_BASE"
chown -R tomcat:tomcat "$CATALINA_BASE"/{logs,temp,work}
chmod 750 "$CATALINA_BASE"/{logs,temp,work}
```
 
## Limits of this audit
 
* The audit cannot see policy decisions: whether a switch is legitimately `true` must be backed by an owner-approved exception.
* Proxy-side controls (A-11) are only covered indirectly by running the probes through the proxy.
* `community.general.xml` evaluates XPath 1.0. Values are compared as written in the file. `${…}` property placeholders are not resolved; non-numeric values in numeric attributes are reported (`NaN` check) for manual review.
* Verify the patch baseline in `tomcat_min_version` against the Apache Tomcat security pages at every run cycle.
## Sources
 
* Apache Tomcat 11 — Security Considerations: https://tomcat.apache.org/tomcat-11.0-doc/security-howto.html
* Apache Tomcat 11 — HTTP Connector / AJP Connector / Default Servlet / Manager component reference: https://tomcat.apache.org/tomcat-11.0-doc/config/
* Apache Tomcat 9.0.x end-of-support announcement: https://tomcat.apache.org/tomcat-9.0.x-eos.html
* NVD CVE-2025-24813: https://nvd.nist.gov/vuln/detail/CVE-2025-24813
* community.general.xml module: https://docs.ansible.com/ansible/latest/collections/community/general/xml_module.html
 
