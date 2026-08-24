# 08 — Fleet graph: from checklist to consequence

**Owner: Track B. Phase 3.**

Every tool in this category — including the commercial ones — audits device by device, in
isolation. But breaches are emergent. **A device can be one hundred per cent CIS-compliant while
the network remains trivially breachable.**

We build the fleet as a graph — devices, interfaces, VLANs, ACL rules, trust relationships,
credential reuse — and run path queries over it.

## Four correlations, chosen because each is invisible to a per-device checklist

### 1. Management plane exposure

An edge router permits `any -> any` into the management VLAN where a fully-hardened core switch
lives. Both devices pass individually. The network is owned.

The core switch did nothing wrong. Its own benchmark has no control that can see the edge router.

### 2. NTP authentication drift

NTP is authenticated on 38 of 40 devices. Two drift. Log correlation across the fleet silently
becomes worthless — and every device passed *NTP configured*.

This is the failure that destroys an incident investigation months later, at the exact moment
somebody needs the logs.

### 3. Credential reuse

The same local administrator hash appears on 30 devices: a lateral-movement highway that no
per-device benchmark checks, because from any single device the credential looks fine.

Detected by comparing salted, deployment-local fingerprints of credential material. The raw
digest is never stored — see the IR schema and the security policy.

### 4. ACL shadowing

A permissive ACE early in an access list **shadows** the restrictive rule below it. The
restrictive rule exists, so the checklist passes. It never fires.

This is why ACL entries are ordered in the IR and why order is load-bearing.

## Remediation ranked by consequence

Remediation is ordered by **how many attack paths each fix severs**, not by CIS severity. That
converts the deliverable from *312 findings* into *six fixes, in this order*.

The one shadowed ACE that cuts forty-seven paths matters more than thirty medium-severity timeout
settings. A report that says so is a report an administrator can act on before lunch.

## Graph model

| Node | Key properties |
|------|----------------|
| Device | vendor, os, role, serial, compliance score |
| Interface | name, addresses, zone, vlan, acl_in, acl_out, is_mgmt |
| VLAN / segment | id, trust level, is_management |
| ACL | name, ordered entries |
| Credential | salted fingerprint, algorithm |
| Service | management protocols exposed |

| Edge | Meaning |
|------|---------|
| CONNECTS_TO | Physical or logical adjacency between interfaces |
| MEMBER_OF | Interface belongs to a VLAN or zone |
| FILTERED_BY | Traffic on this interface passes this ACL |
| REACHES | Derived: computed path permitted by filters along the way |
| SHARES_CREDENTIAL | Two devices carry the same credential fingerprint |
| TRUSTS | AAA, NTP or syslog dependency |

Path queries are Cypher over Neo4j, with a NetworkX fallback so the fleet analysis still runs in
a laptop-only deployment. Batfish may be called for hard reachability mathematics — it is open
source, purpose-built for exactly that, and reimplementing it would be strictly worse.

## Honest limits

- The graph is built from configuration, not from live topology discovery. Adjacency inferred
  from addressing and descriptions is marked as inferred, and paths that depend only on inferred
  adjacency are reported at lower confidence.
- Reachability over dynamic routing is approximated. Where the approximation could be wrong, the
  finding stays ASSERTED rather than being promoted.
- Credential reuse detection compares fingerprints, so it detects reuse of identical material,
  not related-but-different passwords.

Stating these plainly costs nothing and is the difference between a graph an evaluator trusts and
a graph they interrogate.
