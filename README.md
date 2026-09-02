# Void-Rules

[![Validate rules](https://github.com/VoidInTheShell/void-rules/actions/workflows/validate.yml/badge.svg)](https://github.com/VoidInTheShell/void-rules/actions/workflows/validate.yml)
[![Python >=3.11](https://img.shields.io/badge/Python-%3E%3D3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)

支持多格式的场景化分流规则集，提供Clash、V2Ray、ADGuardHome和通用txt集合

## 提供哪些规则

| 规则集 | 包含内容 | 主要来源 |
|---|---|---|
| `fake-ip-bypass` | 直连、局域网、时间同步、连接检测、游戏和其他兼容性敏感域名。 | [DustinWin/domain-list-custom](https://github.com/DustinWin/domain-list-custom)、[xixu-me/RFM](https://github.com/xixu-me/RFM)、[QuixoticHeart/rule-set](https://github.com/QuixoticHeart/rule-set)、[ShellCrash](https://github.com/juewuy/ShellCrash)、[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)、[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) |
| `fake-ip-force` | eBay、Amazon、Microsoft、Google、Gemini、GFW、非中国地区域名，以及 AI、跨境金融和 IP 代理池服务域名。 | [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)、[Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)、[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)，并包含本仓库的 `ai`、`cross-border-finance` 和 `ip-proxy-pools` 规则 |
| `ads` | 广告和跟踪域名 | [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)、[snapei/clash-pro-rules](https://github.com/snapei/clash-pro-rules)、[TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)、[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) |
| `global-legal` | Nvidia、Samsung、Intel、AMD、Lenovo、Dell 等全球厂商的域名。 | [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) |
| `ai` | MetaCubeX 的非中国 AI 服务域名，以及 OpenAI、Twitter、Claude 规则。 | [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)、[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) |
| `cross-border-finance` | 全球银行、支付、券商、交易所、加密货币平台、运营商和地区探测域名。 | [cross-border-finance-rules](https://github.com/VoidInTheShell/cross-border-finance-rules)、[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) |
| `ip-proxy-pools` | 常见商业 IP 代理池服务商的官网、管理面板、API 和代理网关域名，并保留官方旧品牌和端点。 | 自托管 |
| `pcdn` | PCDN、P2P-CDN 及相关域名阻断规则。 | [pcdn-block-list](https://github.com/VoidInTheShell/pcdn-block-list)、[uselibrary/PCDN](https://github.com/uselibrary/PCDN)、[privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD)、[Block-pcdn-domains](https://github.com/thhbdd/Block-pcdn-domains)、[PCDNFilter-CHN](https://github.com/susetao/PCDNFilter-CHN-)、[MyAdBlockRules](https://github.com/Womsxd/MyAdBlockRules) |

> [!IMPORTANT]
> `fake-ip-bypass` 和 `fake-ip-force` 是两套相反用途的规则，前者不能使用fakeip，后者应该强制fakeip：Mihomo dns fakeip字段 的 `blacklist` 模式使用 `fake-ip-bypass`，`whitelist` 模式使用 `fake-ip-force`。两套规则发生重复时，兼容性需求优先，并要求构建明确记录冲突。

## 规则来源和整理方式

来源清单位于 [`catalog/sources.yaml`](catalog/sources.yaml)，每个来源都记录了公开地址、输入格式、适用的规则类型、来源项目和下载限制。每个规则集的组合范围见 [`recipes/`](recipes/)，人工补充、排除项和兼容性断言位于 [`overlays/`](overlays/)。

仓库会严格检查来源内容：未知的非注释行、异常的规则数量、来源格式变化和无法表达的规则都会让构建失败或进入审阅，不会静默丢弃。每个生成目录还会保留来源清单、规则数量、哈希和无法转换项目的报告，便于追溯本次产物由哪些公开来源生成。

## 可用的规则格式

- Mihomo/Clash：`classical`、`domain`、`ipcidr` 的 YAML 和 text；纯 domain/ipcidr 规则另提供 MRS。
- AdGuard Home：分别提供 block 和 allow 列表。
- Xray/V2Ray：domain list、geosite DAT 和 geoip DAT。
- 普通域名/IP 列表，以及包含逐条来源记录的压缩 JSON Lines、来源清单和兼容性报告。

不同格式的表达能力不同。例如 `DOMAIN-KEYWORD` 可以保留在 Mihomo classical 或 Xray geosite 中，但不能伪装成精确域名；只包含 IP 的规则也不会被塞进 Fake-IP 的域名列表。生成结果会报告这类差异。

## 客户端订阅直链

下面的链接固定指向 `main` 分支。每个单元格都同时列出 GitHub Raw 和 jsDelivr 两个地址：前者直接读取仓库文件，后者适合需要 CDN 或备用入口的客户端。文件也可以在 [`dist/`](dist/) 中按路径查看。

- Raw 基础地址：<https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/>
- jsDelivr 基础地址：<https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/>

| 规则集 | Mihomo/Clash classical YAML | Mihomo domain MRS | Xray/V2Ray geosite DAT | AdGuard Home | 通用域名文本 |
|---|---|---|---|---|---|
| `fake-ip-bypass` | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/fake-ip-bypass/mihomo-classical.yaml) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/fake-ip-bypass/mihomo-classical.yaml) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/fake-ip-bypass/mihomo-domain.mrs) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/fake-ip-bypass/mihomo-domain.mrs) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/fake-ip-bypass/xray-geosite.dat) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/fake-ip-bypass/xray-geosite.dat) | — | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/fake-ip-bypass/plain-domain.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/fake-ip-bypass/plain-domain.txt) |
| `fake-ip-force` | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/fake-ip-force/mihomo-classical.yaml) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/fake-ip-force/mihomo-classical.yaml) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/fake-ip-force/mihomo-domain.mrs) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/fake-ip-force/mihomo-domain.mrs) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/fake-ip-force/xray-geosite.dat) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/fake-ip-force/xray-geosite.dat) | — | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/fake-ip-force/plain-domain.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/fake-ip-force/plain-domain.txt) |
| `ads` | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ads/mihomo-classical.yaml) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ads/mihomo-classical.yaml) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ads/mihomo-domain.mrs) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ads/mihomo-domain.mrs) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ads/xray-geosite.dat) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ads/xray-geosite.dat) | block：[Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ads/adguard-block.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ads/adguard-block.txt)<br>allow：[Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ads/adguard-allow.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ads/adguard-allow.txt) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ads/plain-domain.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ads/plain-domain.txt) |
| `global-legal` | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/global-legal/mihomo-classical.yaml) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/global-legal/mihomo-classical.yaml) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/global-legal/mihomo-domain.mrs) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/global-legal/mihomo-domain.mrs) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/global-legal/xray-geosite.dat) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/global-legal/xray-geosite.dat) | — | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/global-legal/plain-domain.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/global-legal/plain-domain.txt) |
| `ai` | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ai/mihomo-classical.yaml) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ai/mihomo-classical.yaml) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ai/mihomo-domain.mrs) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ai/mihomo-domain.mrs) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ai/xray-geosite.dat) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ai/xray-geosite.dat) | — | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ai/plain-domain.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ai/plain-domain.txt) |
| `cross-border-finance` | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/cross-border-finance/mihomo-classical.yaml) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/cross-border-finance/mihomo-classical.yaml) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/cross-border-finance/mihomo-domain.mrs) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/cross-border-finance/mihomo-domain.mrs) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/cross-border-finance/xray-geosite.dat) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/cross-border-finance/xray-geosite.dat) | — | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/cross-border-finance/plain-domain.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/cross-border-finance/plain-domain.txt) |
| `ip-proxy-pools` | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ip-proxy-pools/mihomo-classical.yaml) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ip-proxy-pools/mihomo-classical.yaml) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ip-proxy-pools/mihomo-domain.mrs) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ip-proxy-pools/mihomo-domain.mrs) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ip-proxy-pools/xray-geosite.dat) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ip-proxy-pools/xray-geosite.dat) | — | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ip-proxy-pools/plain-domain.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/ip-proxy-pools/plain-domain.txt) |
| `pcdn` | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/pcdn/mihomo-classical.yaml) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/pcdn/mihomo-classical.yaml) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/pcdn/mihomo-domain.mrs) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/pcdn/mihomo-domain.mrs) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/pcdn/xray-geosite.dat) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/pcdn/xray-geosite.dat) | block：[Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/pcdn/adguard-block.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/pcdn/adguard-block.txt)<br>allow：[Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules@main/dist/pcdn/adguard-allow.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/pcdn/adguard-allow.txt) | [Raw](https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/pcdn/plain-domain.txt) / [jsDelivr](https://cdn.jsdelivr.net/gh/VoidInTheShell/void-rules@main/dist/pcdn/plain-domain.txt) |

`fake-ip-bypass` 只用于 Fake-IP blacklist，`fake-ip-force` 只用于 Fake-IP whitelist；其他规则集按客户端对应的格式选择即可。每个目录中还提供 classical text/YAML、domain/ipcidr、Xray/V2Ray 和 `rules.jsonl.gz` 等完整输出。

## 自动更新

GitHub Actions 每 24 小时运行一次（每天 00:17 UTC）检查来源并重建全部规则。目录和配置格式、来源数量变化、受保护文件、冲突处理、代码质量、测试以及离线重建检查全部通过后，生成结果会直接提交到 `main`

## 目录说明

```text
catalog/                 公开来源和自动发现范围
recipes/                 每个规则集包含哪些来源
overlays/                人工补充、排除项和兼容性断言
schemas/                 配置格式检查
src/void_rules/          Python 规则整理程序
cmd/void-rules-geodata/  Xray/V2Ray DAT 工具
generated/               来源锁和构建报告
dist/                    可供客户端引用的稳定文件
tests/                   解析、合并、格式转换和自动化测试
```

来源项目的原始条款和署名信息见 [`NOTICE.md`](NOTICE.md) 以及每个生成目录中的来源清单。
