# void-rules

自有的多上游规则聚合与发布仓库。它把不同来源和不同格式的规则先转换成带来源信息的统一模型，叠加不会被自动任务覆盖的本地需求，完成去重、冲突检查和差异门禁，再发布给 Mihomo、AdGuard Home、Xray/V2Ray 与普通脚本使用的稳定产物。

现有 `cross-border-finance-rules` 和 `pcdn-block-list` 继续独立维护；void-rules 把它们作为受信上游同步，不替代或删除原仓库。

## 首批规则集

| 规则集 | 语义 | 主要输出 |
|---|---|---|
| `fake-ip-bypass` | 直连、局域网、时间同步和兼容性敏感域名不使用 Fake-IP | Mihomo domain YAML/text/MRS、Xray geosite、plain |
| `fake-ip-force` | 一般为明确走代理的域名，使用 Fake-IP | Mihomo domain YAML/text/MRS、Xray geosite、plain |
| `ads` | 广告与跟踪阻断，AdGuard 例外规则独立保留 | Mihomo classical/domain、AdGuard block/allow、Xray geosite |
| `global-legal` | 在大陆通常可直连、但可能需要跨区的全球厂商 | Mihomo classical/domain、Xray geosite |
| `ai` | 主流 AI 服务 | Mihomo classical/domain、Xray geosite |
| `cross-border-finance` | 全球银行、支付、券商、交易所、加密平台、运营商及地区探测域 | Mihomo classical/domain/MRS、AdGuard、Xray geosite |
| `pcdn` | PCDN 域名阻断 | Mihomo classical/domain/MRS、AdGuard、Xray geosite |

Fake-IP 两个集合不会混用：blacklist 模式引用 `fake-ip-bypass`，whitelist 模式引用 `fake-ip-force`。跨集合冲突默认以受保护的 bypass 为兼容性优先，同时让构建失败并要求显式处理。

## 支持的输入

- 纯域名、通配域名、hosts、IPv4/IPv6 与 CIDR 列表。
- Clash/Mihomo domain、ipcidr、classical 的 YAML 或 text。
- Mihomo MRS v1（domain/ipcidr，通过固定版本官方 Mihomo CLI 解码）。
- AdGuard Home/Adblock DNS block 与 `@@` allow，整源白名单和黑名单分开建模。
- Xray/V2Ray routing JSON、domain-list-community 源格式、geosite DAT 与 geoip DAT。
- 声明式 JSON/YAML API、GitHub raw/release 资产和受限 HTML/JSON discovery 适配器。

所有自动检测都可以被 source 的显式 `format` 覆盖。严格来源出现未知非注释行时整次构建失败，避免格式漂移被静默丢弃。

## 支持的输出

- Mihomo classical/domain/ipcidr：YAML、text；domain/ipcidr 另生成 MRS。
- AdGuard Home：block 与 allow 两份列表。
- Xray/V2Ray：可审计 source text、geosite DAT、geoip DAT。
- plain domain/IP、保留完整 provenance 的确定性 gzip JSON Lines IR、来源 manifest、冲突/兼容性/差异报告。

并非所有规则都能无损降级到每种格式。例如 `DOMAIN-KEYWORD` 可以保留在 Mihomo classical 与 Xray geosite，但不能伪装成精确域名；IP 规则不会进入 DNS Fake-IP domain provider。每个规则集的 manifest 会列出输出时跳过的不可表达规则。

## 仓库结构

```text
catalog/                 上游注册表与自动发现策略（人工维护）
recipes/                 每个逻辑规则集的合并配方（人工维护）
overlays/                本地 include/exclude/assertions（自动任务禁止修改）
schemas/                 catalog、recipe 与 overlay JSON Schema
src/void_rules/          Python 聚合器
cmd/void-rules-geodata/  Xray/V2Ray DAT 往返工具
generated/               来源锁、候选与构建报告
dist/                    下游只引用这里的稳定产物
tests/                   parser、合并、往返、差异门禁与安全测试
```

## 快速开始

```text
python -m venv .venv
python -m pip install -e ".[dev]"
python -m void_rules validate-catalog
python -m void_rules sync
python -m pytest
```

Windows PowerShell 示例：

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m void_rules sync
```

## Mihomo 引用

客户端 URL 使用提交到 `dist/` 的稳定路径。需要 GitHub 加速时，在完整 Raw URL 前添加 `https://gh-proxy.org/`，例如：

```yaml
rule-providers:
  VoidAI:
    type: http
    behavior: classical
    format: yaml
    interval: 21600
    url: "https://gh-proxy.org/https://raw.githubusercontent.com/VoidInTheShell/void-rules/main/dist/ai/mihomo-classical.yaml"
```

配置模板的最终迁移表见 `docs/MIHOMO.md`。

## 自动更新与补规则

定时任务每 6 小时同步注册上游并重建全部产物。小幅且通过门禁的上游更新可以自动提交；超阈值变化、来源格式改变、新发现来源和跨集合冲突进入 review 分支/PR。自动任务只写 `dist/` 与 `generated/`，因此不会覆盖 `overlays/` 中的长期需求或人工拒绝记录。

自动发现不是无边界爬虫。它只在 catalog 声明的主机、仓库目录、release 资产、JSON path 或 HTML 规则内工作；新域名必须满足已批准官方根域或多来源证据才可能自动晋级，否则只进入候选报告。

`python -m void_rules discover` 更新完整的 `generated/discovery/candidates.json.gz` 与便于审阅的 `summary.json`；`--offline --check` 可证明缓存输入能重现已提交候选。人工拒绝只写入 `overlays/discovery/rejected.yaml`，后续上游刷新仍按稳定候选 ID 记住该决定。

完整 IR 以 `dist/<ruleset>/rules.jsonl.gz` 发布。gzip 头的时间戳固定为 0，解压后仍是逐行 JSON 且包含每条规则的来源证据；这样既不牺牲审计能力，也避免定时同步把大体积未压缩 provenance 反复写入 Git 历史。

## 许可证

聚合器代码采用 MIT License。第三方规则数据保留各自来源条款，不由本仓库重新许可；详见 `DATA-LICENSE.md`、`NOTICE.md` 与每份生成 manifest。
