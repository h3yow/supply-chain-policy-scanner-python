# Supply Chain Policy Scanner

本地运行的依赖清单 / SBOM 解析与供应链策略合规服务。输入原始清单文本，
输出**可复现、可解释**的合规判定：内容哈希、所用策略版本、逐条判定依据
（rule id、effect、匹配字段、引入位置）都会随结论返回并写入结构化日志。

## 支持的清单格式

| 格式 | `format` 取值 | 说明 |
| --- | --- | --- |
| pip requirements.txt | `requirements.txt` | 支持 `==/!=/>=/<=/>/</~/^/~=`、逗号与空白连接、extras、PEP 440 风格注释与环境标记 |
| npm package.json | `package.json` | `dependencies` / `devDependencies` / `optionalDependencies` |
| npm package-lock.json | `package-lock.json` | lockfileVersion 2/3 的 `packages` map，含依赖边 |
| SPDX 2.3 JSON | `spdx-json` | `packages` + `relationships(DEPENDS_ON)`，purl 识别生态 |
| CycloneDX 1.4/1.5 JSON | `cyclonedx-json` | `components` + `dependencies`，purl 识别生态 |

`format` 省略或传 `auto` 时按内容嗅探；无法识别返回 `415 unsupported_format`。
仅支持生态 **npm** 与 **pypi**；purl 中出现其他生态按 `unsupported_field` 拒绝。

### 拒绝原因（不静默跳过任何条目）

结构完整但单个条目有问题时，HTTP 层返回 `422 manifest_rejected`，
`details.rejections[]` 中每条都带可区分的 `reason`：

- `missing_name` — 有条目但没有包名（例如 `==1.0.0`）
- `missing_version` — 有包名但没有版本/版本说明符
- `invalid_version_range` — 版本说明符语法非法或区间自相矛盾
  （如 `>=2.0,<1.0`、`==1.0,==2.0`、`1.2.3-`）
- `malformed_entry` — 条目结构无法解析（未闭合 extras、非对象成员等）
- `incomplete_structure` — 结构不完整（缺 purl、component 缺 type、类型错误）
- `unsupported_field` — 不支持的引用方式（`-r`、`-e`、git/URL/file/npm alias、
  workspace 协议、未知生态等）

整个文档语法上无法读取（如非法 JSON）返回 `422 manifest_unparseable`。
错误响应同时内嵌该次扫描的部分结论（含 `content_hash` 与 `policy_version`）。

版本规则与规则中的 `version_range` 使用同一套严格的区间解析器
（`scanner/versions.py`），支持 pip 与 npm 操作符：
`== != >= <= > < ~= ~ ^` 以及 `1.2.*` / `1.x` 通配。

## 策略版本模型

- 策略先**登记**（register）为草稿（返回 `draft_id`），校验通过后才能
  **发布**（publish）。发布生成不可变版本号 `v1, v2, ...`。
- **回滚**（rollback）把任一历史版本的文档重新发布为一个**新版本**
  （例如当前 `v2` 回滚到 `v1` 得到 `v3`），历史版本永不被修改或删除。
- 扫描默认使用当前版本，也可用 `policy_version` 固定扫描某个历史版本。
- 规则字段：`id`、`effect`（`deny`/`allow`）、`ecosystem`（`npm`/`pypi`/`*`）、
  `package`、`match`（`exact`/`prefix`/`regex`）、可选 `version_range`、`reason`。
  规则按声明顺序求值：命中 deny 即该包失败；否则第一个 allow 解释该包；
  都不命中时采用文档级 `default_effect`。
- 策略校验失败（重复规则 id、非法区间、非法正则、非法生态等）返回
  `422 invalid_policy`，错误详情带规则 id。

## 角色权限模型

通过 `X-API-Key` 头认证，两种角色：

| 角色 | 内置 key | 权限 |
| --- | --- | --- |
| reader | `reader-local-key` | 扫描、读取当前策略/版本列表 |
| publisher | `publisher-local-key` | 上述全部 + 登记/发布/回滚 |

失败原因刻意区分：

- 无头 / 未知 key → `401 authentication_required`
- reader 调用发布类接口 → `403 permission_denied`（详情含 `role` 与 `required`）

可用环境变量 `SCANNER_READ_KEYS`、`SCANNER_PUBLISH_KEYS`（逗号分隔）覆盖内置 key。

## 缓存与并发语义

- 缓存键 = `SHA-256(内容哈希 + 策略版本 + 格式)`。**策略版本不同则键空间不同**，
  同一份清单在同一策略版本下结论完全一致（响应逐字节可复现）。
- 相同键的并发请求共享同一个 in-flight Future：解析 + 规则求值在并发下
  **只执行一次**，其余请求等待同一结果。
- **发布或回滚即清空缓存**（登记草稿不清）。缓存内部带 epoch 令牌：若清缓存时
  旧计算仍在进行，其旧结论既不会写入缓存，也不会满足清缓存之后到达的请求——
  新请求会重新计算，因此不可能返回基于旧生效策略的结论。
- 依赖图问题作为显式 finding 标记，绝不静默选择其中一个：
  - `circular_dependency`（Tarjan SCC，环上每个节点 + 自环，decision=fail）
  - `version_conflict`（同名多个具体版本=fail；区间与具体版本并存=warn）
  - `duplicate_introduction`（同名同版本由多个来源引入，decision=warn）

## API

所有接口前缀 `/api/v1`。

| 方法 | 路径 | 角色 | 说明 |
| --- | --- | --- | --- |
| POST | `/scan` | reader | body: `{"content": "...", "format": "auto"\|"requirements.txt"\|..., "policy_version": "v1"}` |
| POST | `/policies` | publisher | 登记草稿 |
| POST | `/policies/{draft_id}/publish` | publisher | 发布草稿 |
| POST | `/policies/rollback` | publisher | body: `{"version": "v1"}` |
| GET | `/policies/current` | reader | 当前版本摘要 |
| GET | `/policies/versions` | reader | 历史版本与草稿列表 |
| GET | `/` | - | 保持原引导接口：`{"Hello": "World"}` |

判定 `decision`：`pass` / `warn` / `fail`（取所有 finding 的最高等级）。

## 日志

所有扫描日志为单行 JSON（stderr），至少包含 `event`、`content_hash`、
`policy_version`、`decision`，`scan_computed` 事件还包含每条 finding 的
`basis`（判定依据）与包/拒绝计数。

## 本地验证

```bash
uv sync
uv run python -m pytest -q          # 27 个测试：畸形清单/并发同内容/回滚重算等
uv run python main.py               # 启动服务（端口由 uvicorn 分配）
```

快速手工验证：

```bash
# 1) 登记并发布一条策略
DRAFT=$(curl -s -X POST localhost:8000/api/v1/policies \
  -H "X-API-Key: publisher-local-key" -H "Content-Type: application/json" \
  -d '{"name":"demo","default_effect":"allow","rules":[
       {"id":"DENY-LEFT-PAD","effect":"deny","ecosystem":"npm",
        "package":"left-pad","version_range":"<2.0.0","reason":"do not use"}]}' \
  | python -c 'import sys,json;print(json.load(sys.stdin)["draft_id"])')
curl -s -X POST localhost:8000/api/v1/policies/$DRAFT/publish \
  -H "X-API-Key: publisher-local-key"

# 2) 扫描（reader）
curl -s -X POST localhost:8000/api/v1/scan \
  -H "X-API-Key: reader-local-key" -H "Content-Type: application/json" \
  -d '{"content":"{\"dependencies\":{\"left-pad\":\"1.3.0\",\"lodash\":\"4.17.21\"}}"}'

# 3) 越权（reader 试图发布）-> 403 permission_denied
curl -i -X POST localhost:8000/api/v1/policies \
  -H "X-API-Key: reader-local-key" -H "Content-Type: application/json" -d '{"name":"x"}'
```

## 目录结构

```
scanner/
  models.py            # 领域模型与枚举
  versions.py          # 严格版本/区间解析与匹配
  hashing.py           # 内容哈希与缓存键
  config.py            # 角色 key 配置
  logging_setup.py     # 结构化 JSON 日志
  errors.py            # 可区分错误码
  parsers/             # requirements / package.json / lock / SPDX / CycloneDX
  policy/              # 策略模型、角色鉴权、版本化存储
  scan/                # 图分析、规则引擎、并发缓存
  service.py           # 装配层
  api.py               # FastAPI 路由
main.py                # 应用入口（保留 GET /）
tests/                 # pytest 测试
```
