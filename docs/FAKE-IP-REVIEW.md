# Fake-IP conflict review, 2026-10-08

The [failed synchronization](https://github.com/VoidInTheShell/void-rules/actions/runs/37735563719)
reported 93 unreviewed exact overlaps. All 93 retain their original match types
and resolve to `fake-ip-bypass`: 56 exact domains and 37 domain suffixes.

| Purpose | Count | Bypass source | Overlapping force source |
|---|---:|---|---|
| Time synchronization | 92 | `dustinwin-fakeip` | `metacubex-geolocation-not-cn` |
| Firefox captive-portal detection | 1 | `metacubex-connectivity-check` | `metacubex-geolocation-not-cn` |

The 92 time entries were matched individually by kind and value against V2Fly's
[`category-ntp`](https://github.com/v2fly/domain-list-community/blob/master/data/category-ntp)
and [`category-ntp-jp`](https://github.com/v2fly/domain-list-community/blob/master/data/category-ntp-jp).
They follow the existing time-service real-IP policy. This review classifies DNS
exceptions; it does not certify each server's current availability or recommend
every listed endpoint as a public NTP server.

Mozilla documents `firefox-portal-detection.com` as a
[captive-portal endpoint](https://firefox-source-docs.mozilla.org/networking/captive_portals.html).
Its suffix exception follows the existing connectivity-probe policy.

The reviewed input SHA-256 digests are:

| Input | SHA-256 |
|---|---|
| DustinWin fakeip-filter | `569642dbf432857c19137a16cdb79720afc0191d7a9ec3d7d201efc756504d58` |
| MetaCubeX connectivity-check | `4e4829daacf2623145685dda02cbb45b540d518c9f80e41cf34589e8fa466dec` |
| MetaCubeX geolocation-not-cn | `d525d271b4c2602549ee9713234108923b8f61e3c3d957bdd0c28453e3904cf3` |
| V2Fly category-ntp | `621b8ef74b8b1872ff1e42a69bcbc3aa13b852df2fc23b22dc0b3892e32d63fd` |
| V2Fly category-ntp-jp | `b884fed4ae11bd921a71b1be15da4f7f0acb196cd29a5c088a8e7d4e2976c95d` |

38 of these time domains also match force parents: `nist.gov` (20), `facebook.com`
(6), `google.com` (5), `apple.com` (3), and `ubuntu.com`, `aws.com`, `cloudflare.com`,
`windows.com` (one each). Deleting an exact force entry cannot override its
parent. Keep the parents for ordinary sites, and apply bypass before force using
the [ordered DNS configuration](MIHOMO.md). The build report exposes remaining
domain/suffix coverage in `fake_ip_conflicts.coverage_overlaps`.

The subsequent STUN review accepts the DustinWin snapshot above as the new
557-rule baseline only with STUN separated from bypass. Of its 472 additions,
113 NTP entries stay in bypass and 359 STUN entries join the standalone `stun`
set. Those 359 match MetaCubeX's category-stun snapshot
`e4155e665f098c7a61c396af9b4553c5da1d4ef2145ced6fd9bb115e16acde2a`.
The standalone set unions both sources and keeps both provenance records after
deduplication. It now also synchronizes the STUN/TURN portions of RFM,
QuixoticHeart and ShellCrash, retaining eight original protected rules. These
sources still produce the same 372 distinct rules. The
source growth limit remains 4.0. Future unknown exact overlaps still require
an explicit review.

The bypass recipe now excludes STUN membership across all sources, removing
370 mixed-source entries and retaining NTP. Known local STUN/TURN exceptions
were moved to the standalone set. STUN is not included in force. The bypass
manifest records one retained parent intersection, `stun.qq.com` under
`qq.com`; standalone output does not assign a DNS action or override general
client rules. Fake-IP bypass/force domain-suffix intersections are now 109.

## Initial conflict-review validation, before the STUN split

- Ruff formatting/lint, mypy, catalog validation, 64 Python tests and the Go
  codec tests passed.
- The pinned Mihomo v1.19.28 passed a DNS regression covering all 93 reviewed
  names, all 37 suffix entries' child names, ordinary force domains and the
  real-IP default. The regression uses a local DNS responder and MRS providers.
- Both affected rulesets were rebuilt in an isolated directory from 27 fetched
  sources and the published source-count baseline. All 119 exact conflicts are
  reviewed; 121 domain/suffix coverage pairs remain visible in the report.
  The only review reason is the independent DustinWin growth gate. All outputs
  of both rulesets reproduced byte for byte from the downloaded cache.
- The actual candidate MRS files passed 136 local DNS queries: 132 real-IP
  responses and four Fake-IP responses. The real-IP cases include the reviewed
  names, suffix children, the default, and the pre-existing RFM `*.apple.com`
  exception. `apple.com`, `www.google.com`, `www.nist.gov` and `api.openai.com`
  still receive Fake-IP. Existing broader bypass rules also take precedence in
  rule mode; they are not removed by this change.

## Initial STUN split validation

The 359 DustinWin STUN additions and 113 NTP additions were checked individually
against the separated outputs, with no missing additions. Domain, classical,
MRS and geosite data remain byte-identical when adding the matching DustinWin
provenance to the standalone set. Both synchronization and validation workflows
run STUN separation regression checks before publication.

The updated candidate MRS files passed 140 local DNS queries, including the
original NTP/captive-portal regression, STUN names under a force parent, the
retained QQ parent exception and STUN names receiving the default real-IP
answer. These checks do not contact public NTP/STUN services.

Local `dist/` artifacts and `generated/sources.lock.json` now include the
reviewed baseline and separated STUN outputs. They have not been pushed or
published. Clients must adopt the ordered DNS configuration; updating rule
subscriptions alone cannot migrate an existing whitelist setup.

## GFW parser and STUN automation correction

The Loyalsoldier GFW source is YAML, not domain text. All 4,429 entries now
parse as domain suffixes; 4,428 contribute to force and `nflxvideo.net` remains
in bypass under the existing reviewed policy. The force canonical set changes
from 32,341 to 28,051: 4,429 unusable opaque records are removed and 139 missing
valid rules are added after deduplication. Every previously usable force rule
and all 53 Claude rules remain. Domain/MRS represents 27,984 force rules.

STUN now records contributions from MetaCubeX (359), DustinWin (359), RFM (12),
QuixoticHeart (5), ShellCrash (4), and the original repository overlay (8).
Counts overlap because deduplication preserves all contributing sources.
The STUN membership remains 372 and bypass membership remains 3,217. Seven
upstream-only rules previously copied into the overlay are now synchronized
with their original provenance and automatic addition/deletion propagation.

DustinWin's 198 unmatched entries form the reviewed bypass baseline. New
unclassified entries block the build before writing artifacts or advancing
that baseline; rerunning a failed build cannot approve them. Known STUN/TURN
labels, category members and protected legacy rules are selected automatically.
Unrecognized endpoints are not classified by guessing or contacting services.

Domain-text parsing now rejects YAML containers, including inline lists, and
YAML entries must be nonempty strings. Native matching checks also exposed and
corrected unsupported character-glob handling and the difference between `.`
and `+.` suffixes. Domain MRS, domain YAML and classical YAML are checked against
actual Mihomo DNS matching, including negative examples and NTP preservation.

All seven affected rulesets reproduce byte for byte from the same cached
inputs. All 47 source hashes are unchanged; only parser/classification and
output handling changed in this correction. There are still 119 explicitly
reviewed exact conflicts and 109 reported domain/suffix coverage pairs.

Final validation passed: 127 Python tests, Go codec tests, Ruff formatting and
lint, mypy, and catalog validation. The native DNS tests cover all three STUN
provider formats and the actual rebuilt GFW/Claude/NTP artifacts. Published
artifact checks were rerun after making their source assertions tolerate
legitimate upstream additions and deletions; all three checks passed. The local
CI decision has no review reasons. These changes remain local and unpublished.
