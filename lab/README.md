# RED MCP — Practice Lab

Self-contained, intentionally vulnerable targets on the local `redlab` Docker
network, for **authorized practice only**. The `kali-security` MCP container joins
that network, but active calls still require explicit target scope. This Docker
network is not an egress firewall.

```
redlab (subnet assigned by Docker)
├─ dvwa   — Damn Vulnerable Web Application   (web target)
├─ msf    — Metasploit RPC service (msfrpcd)  (backs the msf_* tools)
└─ dc1    — Vulnerable Samba AD DC, REDLAB.LOCAL  (Active Directory target)
```

## Bring it up

```powershell
docker compose -f lab\docker-compose.yml up -d          # DVWA  (http://localhost:8080)
docker compose -f lab\msf-compose.yml   up -d           # Metasploit RPC service
docker compose -f lab\ad-compose.yml    up -d --build    # Samba AD DC (first build provisions the domain)
```

The sample allowlist is empty. Find the DC's actual IP on `redlab`, then add only
that owned lab address (and any other explicitly approved lab hosts) to
`KALI_TARGET_ALLOWLIST`. Do not assume a Docker subnet or authorize a whole private
network by default:

```powershell
docker inspect -f '{{ (index .NetworkSettings.Networks "redlab").IPAddress }}' dc1
```

---

## DVWA (web)
- Browser: `http://localhost:8080`  ·  from the scanner: `http://dvwa`
- Login `admin` / `password`, then **Create / Reset Database** on first run.

## Active Directory — REDLAB.LOCAL (`dc1`)

Deliberately weak accounts (password policy complexity disabled):

| User | Password | Weakness |
|------|----------|----------|
| `Administrator` | `Redlab123!` | domain admin |
| `test` | `monkey` | **AS-REP roastable** (Kerberos pre-auth disabled) |
| `svc_sql` | `sunshine` | **Kerberoastable** (SPN `MSSQLSvc/dc1.redlab.local:1433`) |
| `j.doe` | `password` | low-priv authenticated user |

### The attack chain (ask Claude, using the DC's IP as `dc_ip`)
1. `nmap_scan` the DC → AD ports (88/Kerberos, 389/LDAP, 445/SMB, 3268/GC).
2. `kerbrute_userenum(REDLAB.LOCAL, <dc_ip>)` → valid users (test/administrator/…).
3. `asrep_roast(REDLAB.LOCAL, <dc_ip>)` → `test`'s `$krb5asrep$` hash.
4. `kerberoast(REDLAB.LOCAL, <dc_ip>, j.doe, password)` → `svc_sql`'s `$krb5tgs$` hash.
5. `john_crack` the roasted hashes → `monkey` / `sunshine`.
6. `ldap_search` + `bloodhound_collect` (as `j.doe`) → directory enumeration / attack paths.
7. `netexec_smb` + a Metasploit SMB aux module against the DC.

### Notes / caveats
- **DNS:** ProjectDiscovery & some AD tools don't know `redlab.local`; target the DC by **IP** (`-dc-ip`/`--dc`/`-ns` are handled by the tools). Container clocks are shared with the host, so there's no Kerberos clock skew.
- **secretsdump / DCSync:** impacket's DRSUAPI DCSync **does not work against a Samba DC** (a known Samba limitation — it fails with a DRSR error). It works against real Windows DCs. On Samba the equivalent is `net rpc vampire keytab` with domain-admin creds.
- This is a *GOAD-lite* approximation: enough to exercise AS-REP roasting, Kerberoasting, LDAP/BloodHound enumeration and SMB attacks — not a full multi-DC forest.

## Tear down
```powershell
docker compose -f lab\ad-compose.yml down
docker compose -f lab\msf-compose.yml down
docker compose -f lab\docker-compose.yml down   # note: removes the redlab network
```
