# Mihomo integration

## Provider paths

| Logical set | Behavior | Stable path |
|---|---|---|
| Fake-IP bypass | domain | `dist/fake-ip-bypass/mihomo-domain.mrs` |
| Fake-IP force | domain | `dist/fake-ip-force/mihomo-domain.mrs` |
| Ads | classical | `dist/ads/mihomo-classical.yaml` |
| GlobalLegal | classical | `dist/global-legal/mihomo-classical.yaml` |
| AI | classical | `dist/ai/mihomo-classical.yaml` |
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

Whitelist templates:

```yaml
dns:
  fake-ip-filter-mode: whitelist
  fake-ip-filter:
    - rule-set:VoidFakeIPForce
```

The two providers are not aliases. `VoidFakeIPBypass` contains direct/compatibility-sensitive names that must receive real IPs; `VoidFakeIPForce` contains proxy-oriented names that should receive Fake-IP.

## DNS leak boundary

Routing rules for cross-border finance and other region-sensitive services must appear before generic GFW/geolocation/direct/MATCH rules. Their DNS policy should use encrypted resolvers through the same policy group. Sniffer-discovered Host/SNI, including a regional site probing a global parent such as Bybit EU probing `bybit.com`, must match the same complete service roots.
