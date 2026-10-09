# Mihomo integration

## Provider paths

| Logical set | Behavior | Stable path |
|---|---|---|
| Fake-IP bypass | domain | `dist/fake-ip-bypass/mihomo-domain.mrs` |
| Fake-IP force | domain | `dist/fake-ip-force/mihomo-domain.mrs` |
| Ads | classical | `dist/ads/mihomo-classical.yaml` |
| GlobalLegal | classical | `dist/global-legal/mihomo-classical.yaml` |
| AI | classical | `dist/ai/mihomo-classical.yaml` |
| Claude | domain | `dist/void-claude-rules/mihomo-domain.mrs` |
| Claude/AI DNS overlap | domain | `dist/void-claude-ai-overlap/mihomo-domain.mrs` |
| Cross-border finance | classical | `dist/cross-border-finance/mihomo-classical.yaml` |
| PCDN | classical | `dist/pcdn/mihomo-classical.yaml` |

Use `https://gh-proxy.org/https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/<path>` where acceleration is required.

## DNS modes

Blacklist templates:

```yaml
dns:
  fake-ip-filter-mode: blacklist
  fake-ip-filter:
    - rule-set:VoidFakeIPBypass
```

To return Fake-IP only for the force set while preserving compatibility
exceptions, use ordered rule mode (verified with the pinned Mihomo v1.19.28):

```yaml
dns:
  fake-ip-filter-mode: rule
  fake-ip-filter:
    - RULE-SET,VoidFakeIPBypass,real-ip
    - RULE-SET,VoidFakeIPForce,fake-ip
    - MATCH,real-ip
```

Both providers must be defined. A complete DNS/provider fragment is available in
[`examples/mihomo-dns.yaml`](../examples/mihomo-dns.yaml); merge it into your
existing configuration, retaining your DNS resolvers and traffic routing rules.

The two providers are not aliases. `VoidFakeIPBypass` contains compatibility-sensitive
names that must receive real IPs; `VoidFakeIPForce` contains names that should
receive Fake-IP after those exceptions. This DNS choice does not set the traffic
route to DIRECT.

Migrate configurations using only `whitelist` and `VoidFakeIPForce` to the three
ordered rules above. Removing `time.google.com` from the force set does not stop
its `google.com` suffix from matching. Standalone whitelist mode cannot express
this child exception. The final `MATCH,real-ip` preserves the former whitelist
default for names outside the force set. For clients without rule mode, use the
blacklist configuration above; its default for other names is Fake-IP.

`generated/reports/build.json` reports remaining domain/suffix intersections in
`fake_ip_conflicts.coverage_overlaps`. These pairs are retained for rule-mode
precedence, rather than deleting whole parent domains. This diagnostic does not
enumerate keyword, regex or wildcard intersections. Unreviewed exact conflicts
and source-size anomaly gates still block automatic publication.

See the [Mihomo DNS documentation](https://wiki.metacubex.one/config/dns/#fake-ip-filter-mode)
for rule-mode syntax.

## Standalone STUN

`stun` is a separate subscription with `action: match`. It is not a dependency
of `fake-ip-force`, and its members and explicit STUN/TURN wildcard exceptions
are excluded from `fake-ip-bypass` during every build. NTP remains in bypass.
The set merges MetaCubeX's STUN category with rules selected automatically from
DustinWin, RFM, QuixoticHeart and ShellCrash, preserving every contributing
source after deduplication. Selection uses current category members, explicit
STUN/TURN labels and eight protected legacy rules. Upstream-only additions and
deletions propagate without editing local overlays. Unknown new DustinWin
entries block the build before they can enter bypass; existing reviewed NTP
entries remain there. Classification does not probe arbitrary hostnames.
The standalone outputs include domain MRS and classical YAML/text. Choose the
client action explicitly; this repository does not add a STUN DNS rule.

This separates list membership, not all possible DNS matches. Existing broad
rules such as `+.qq.com`, and the final `MATCH,real-ip`, can still return real
addresses for STUN names. The bypass manifest records retained domain/suffix
coverage under `composition.excluded_rulesets.stun.retained_domain_suffix_overlaps`.
This diagnostic does not enumerate wildcard/regex/keyword intersections.

## Claude/AI DNS overlap

The generated `void-claude-ai-overlap` set intersects AI and Claude domain
coverage, including parent/child and whole-label wildcard matches. Use it ahead
of AI in `nameserver-policy` when Claude has a separate egress. The provider
name `VoidAClaudeOverlap` sorts before `VoidAI`, preserving that priority even
when a subscription renderer sorts YAML mapping keys.

```yaml
dns:
  nameserver-policy:
    'rule-set:VoidAClaudeOverlap': ['https://1.1.1.1/dns-query#Claude']
    'rule-set:VoidClaude': ['https://1.1.1.1/dns-query#Claude']
    'rule-set:VoidAI': ['https://1.1.1.1/dns-query#AI']
rule-providers:
  VoidAClaudeOverlap:
    type: http
    behavior: domain
    format: mrs
    interval: 86400
    path: ./rules/void-claude-ai-overlap.mrs
    url: https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/void-claude-ai-overlap/mihomo-domain.mrs
```

Keep the existing `VoidClaude` and `VoidAI` providers and policy groups. Traffic
rules still put Claude before AI; the companion provider controls only DNS
precedence. Keywords, regexes, IP and process rules are outside domain MRS and
do not enter this companion set.

## DNS leak boundary

Routing rules for cross-border finance and other region-sensitive services must appear before generic GFW/geolocation/direct/MATCH rules. Their DNS policy should use encrypted resolvers through the same policy group. Sniffer-discovered Host/SNI, including a regional site probing a global parent such as Bybit EU probing `bybit.com`, must match the same complete service roots.
