# Binary codecs

## Mihomo MRS

MRS is not concatenated. The pipeline calls a pinned official Mihomo CLI:

```text
mihomo convert-ruleset domain mrs input.mrs decoded.txt
mihomo convert-ruleset domain text encoded.txt output.mrs
mihomo convert-ruleset ipcidr mrs input.mrs decoded.txt
mihomo convert-ruleset ipcidr text encoded.txt output.mrs
```

The default pin is recorded in `catalog/tools.yaml`. CI verifies the downloaded binary checksum. A source can declare a text/YAML companion; that companion remains preferred for readable diffs, while decode-and-compare validates the upstream MRS.

## Xray/V2Ray DAT

`cmd/void-rules-geodata` reads/writes `routercommon.GeoSiteList` and `GeoIPList` protobuf messages. Its interchange format is JSON Lines so the Python pipeline can retain tag, rule kind, attributes and CIDR without importing generated protobuf code.

DAT tests encode a fixture, decode it again and compare normalized semantic rules. Unknown protobuf enum values, malformed IP bytes and invalid prefix lengths fail closed.

## Deterministic gzip

The same pinned Go helper produces provenance and discovery gzip files with a zero timestamp and fixed header. Compression therefore does not depend on whether Python is linked to zlib or zlib-ng on Windows/Linux. Tests compare repeated byte output and decompress it back to the original payload.
