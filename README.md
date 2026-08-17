# void-rules

[![Validate rules](https://github.com/VoidInTheShell/void-rules/actions/workflows/validate.yml/badge.svg)](https://github.com/VoidInTheShell/void-rules/actions/workflows/validate.yml)
[![Python >=3.11](https://img.shields.io/badge/Python-%3E%3D3.11-3776AB?logo=python&logoColor=white)](https://www.python.org/)

从多个公开规则仓库读取域名、IP、CIDR 和路由规则，整理成可直接供 Mihomo、AdGuard Home、Xray/V2Ray 以及普通脚本使用的规则文件。

这个仓库只同步和整理规则数据，不执行上游仓库里的脚本。原有的 [cross-border-finance-rules](https://github.com/VoidInTheShell/cross-border-finance-rules) 和 [pcdn-block-list](https://github.com/VoidInTheShell/pcdn-block-list) 仍然独立维护；本仓库读取它们的公开产物，并不会替代它们。

## 提供哪些规则

| 规则集 | 包含内容 | 主要来源 |
|---|---|---|
| `fake-ip-bypass` | 直连、局域网、时间同步、连接检测、游戏和其他兼容性敏感域名；这些域名应返回真实 IP。 | [DustinWin/domain-list-custom](https://github.com/DustinWin/domain-list-custom)、[xixu-me/RFM](https://github.com/xixu-me/RFM)、[QuixoticHeart/rule-set](https://github.com/QuixoticHeart/rule-set)、[ShellCrash](https://github.com/juewuy/ShellCrash)、[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)、[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) |
| `fake-ip-force` | eBay、Amazon、Microsoft、Google、Gemini、GFW、非中国地区域名，以及 AI 和跨境金融域名；这些域名在白名单模式下使用 Fake-IP。 | [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)、[Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)、[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)，并包含本仓库的 `ai` 和 `cross-border-finance` 规则 |
| `ads` | 广告和跟踪域名，同时保留拦截规则与放行规则的区别。 | [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)、[snapei/clash-pro-rules](https://github.com/snapei/clash-pro-rules)、[TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)、[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) |
| `global-legal` | Nvidia、Samsung、Intel、AMD、Lenovo、Dell 等全球厂商的域名。 | [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) |
| `ai` | MetaCubeX 的非中国 AI 服务域名，以及 OpenAI、Twitter、Claude 规则。 | [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)、[blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script) |
| `cross-border-finance` | 全球银行、支付、券商、交易所、加密货币平台、运营商和地区探测域名。 | [cross-border-finance-rules](https://github.com/VoidInTheShell/cross-border-finance-rules)、[MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat) |
| `pcdn` | PCDN、P2P-CDN 及相关域名阻断规则。 | [pcdn-block-list](https://github.com/VoidInTheShell/pcdn-block-list)、[uselibrary/PCDN](https://github.com/uselibrary/PCDN)、[privacy-protection-tools/anti-AD](https://github.com/privacy-protection-tools/anti-AD)、[Block-pcdn-domains](https://github.com/thhbdd/Block-pcdn-domains)、[PCDNFilter-CHN](https://github.com/susetao/PCDNFilter-CHN-)、[MyAdBlockRules](https://github.com/Womsxd/MyAdBlockRules) |

> [!IMPORTANT]
> `fake-ip-bypass` 和 `fake-ip-force` 是两套相反用途的规则，不能互相替换：Mihomo 的 `blacklist` 模式使用 `fake-ip-bypass`，`whitelist` 模式使用 `fake-ip-force`。两套规则发生重复时，兼容性需求优先，并要求构建明确记录冲突。

## 规则来源和整理方式

来源清单位于 [`catalog/sources.yaml`](catalog/sources.yaml)，每个来源都记录了公开地址、输入格式、适用的规则类型、来源项目和下载限制。每个规则集的组合范围见 [`recipes/`](recipes/)，人工补充、排除项和兼容性断言位于 [`overlays/`](overlays/)。

仓库会严格检查来源内容：未知的非注释行、异常的规则数量、来源格式变化和无法表达的规则都会让构建失败或进入审阅，不会静默丢弃。每个生成目录还会保留来源清单、规则数量、哈希和无法转换项目的报告，便于追溯本次产物由哪些公开来源生成。

## 可用的输出格式

- Mihomo/Clash：`classical`、`domain`、`ipcidr` 的 YAML 和 text；纯 domain/ipcidr 规则另提供 MRS。
- AdGuard Home：分别提供 block 和 allow 列表。
- Xray/V2Ray：domain list、geosite DAT 和 geoip DAT。
- 普通域名/IP 列表，以及包含逐条来源记录的压缩 JSON Lines、来源清单和兼容性报告。

不同格式的表达能力不同。例如 `DOMAIN-KEYWORD` 可以保留在 Mihomo classical 或 Xray geosite 中，但不能伪装成精确域名；只包含 IP 的规则也不会被塞进 Fake-IP 的域名列表。生成结果会报告这类差异。

## 快速开始

需要 Python 3.11 或更高版本：

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
python -m void_rules validate-catalog
python -m void_rules sync
python -m pytest -q
```

Windows PowerShell：

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m void_rules validate-catalog
.\.venv\Scripts\python.exe -m void_rules sync
.\.venv\Scripts\python.exe -m pytest -q
```

离线检查已缓存的输入是否可以重建当前结果：

```bash
python -m void_rules discover --offline --check
python -m void_rules sync --offline --check
```

## Mihomo 使用方式

稳定产物都位于 [`dist/`](dist/)。常用路径如下：

| 规则集 | Mihomo provider |
|---|---|
| Fake-IP bypass | `dist/fake-ip-bypass/mihomo-domain.mrs` |
| Fake-IP force | `dist/fake-ip-force/mihomo-domain.mrs` |
| 广告 | `dist/ads/mihomo-classical.yaml` |
| 全球厂商 | `dist/global-legal/mihomo-classical.yaml` |
| AI | `dist/ai/mihomo-classical.yaml` |
| 跨境金融 | `dist/cross-border-finance/mihomo-classical.yaml` |
| PCDN | `dist/pcdn/mihomo-classical.yaml` |

例如：

```yaml
rule-providers:
  VoidAI:
    type: http
    behavior: classical
    format: yaml
    interval: 21600
    url: "https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ai/mihomo-classical.yaml"
```

Fake-IP 的两种 DNS 配置和完整迁移表见 [`docs/MIHOMO.md`](docs/MIHOMO.md)。

## 自动更新和审阅

GitHub Actions 每 24 小时运行一次（每天 00:17 UTC）检查来源并重建全部规则。通过安全检查且变化较小的结果可以直接更新 `main`；变化较大、发现新来源、出现冲突或需要人工确认时，会把结果推到 `automation/rules-sync`，再创建一个目标为 `main` 的 PR。自动任务只写入 `dist/` 和 `generated/`，不会覆盖来源清单、规则组合或人工补充目录。

> [!WARNING]
> 如果仓库设置没有允许 GitHub Actions 创建 PR，审阅分支仍可能已经推送成功，但 PR 不会出现。此时需要在仓库的 Actions 设置中启用对应权限，或手动从 `automation/rules-sync` 创建 PR。

自动发现只在来源清单声明的仓库、目录、发布文件、JSON 路径或网页规则内工作；新候选默认进入审阅，不会把任意网页内容直接加入正式规则。

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

更多 Mihomo 集成细节见 [`docs/MIHOMO.md`](docs/MIHOMO.md)；来源项目的原始条款和署名信息见 [`NOTICE.md`](NOTICE.md) 以及每个生成目录中的来源清单。
