# Supply Chain Policy Scanner

本地的依赖清单扫描与供应链策略合规服务。解析多种依赖清单 / SBOM 格式，按已发布的策略版本给出可复现、可解释的判定结论。

## 支持的清单格式

| 格式 | 识别方式 | 说明 |
| --- | --- | --- |
| `requirements_txt` | 非 JSON 文本，逐行 `name[spec]` | 支持 `>=`、`==`、`~=`、`!=`、`==1.2.*` 等 PEP 440 风格约束 |
| `package_json` | JSON 且含 `dependencies` / `devDependencies` | 支持 `^`、`~`、区间等 npm 风格约束 |
| `cyclonedx_json` | JSON 且 `bomFormat: CycloneDX` 或含 `components` + `specVersion` | 读取组件版本、许可证（`licenses[0]`）与 `dependencies` 段的依赖边（用于循环检测） |

格式由内容嗅探自动识别，也可在解析层显式指定。

### 条目级拒绝原因（可区分，不静默跳过）

任何畸形条目都会记录到报告的 `errors` 中并使整体判定为 `deny`，原因枚举：

- `empty_content`：内容为空
- `unknown_format`：无法识别格式
- `malformed_document`：JSON 非法 / 行无法解析 / 非 UTF-8
- `missing_name` / `missing_version`：必填字段缺失
- `invalid_version_spec`：版本约束非法（如 `>=abc`）
- `invalid_structure`：结构不完整（如 CycloneDX 缺 `components` 数组、悬空 bom-ref）

每条错误都带 `location`（行号或 JSON 路径）便于定位。

## 策略版本与角色权限模型

- **角色**：`readonly`（只读，可扫描和查询当前策略）与 `publisher`（可登记 / 发布 / 回滚）。通过 `Authorization: Bearer <token>` 认证；内置演示 token：`readonly-token`、`publisher-token`（见 `scanner/policy.py` 的 `DEFAULT_TOKENS`，可注入自定义映射）。
- **越权原因可区分**：`missing_token`（401）、`unknown_token`（401）、`forbidden_role`（403）。
- **生命周期**：`POST /policies` 登记草稿（版本号不可重复，`version_exists`）→ `POST /policies/{v}/publish` 发布为当前生效版本 → `POST /policies/{v}/rollback` 回滚到**曾经发布过**的历史版本（未发布过的版本报 `version_not_published`）。未发布任何策略时扫描报 `no_active_policy`。
- **策略规则**：`denied_packages`（包名，大小写不敏感）、`denied_licenses`（SPDX 标识）、`allow_prerelease`（是否允许预发布版本约束）。
- **可复现性**：扫描报告携带 `content_hash`（SHA-256）与 `policy_version`；同一清单内容在同一策略版本下结论逐字节一致。

## 判定语义

- 任一解析错误 → `deny`。
- 命中 `denied_packages` / `denied_licenses` / 预发布限制 → 对应条目 `deny`，整体 `deny`，`items[].reason` 给出依据。
- 依赖图问题全部显式标记在 `issues` 中，不静默取舍：
  - `cycle`（循环依赖）、`version_conflict`（同名包约束区间不相交）→ 整体 `deny`；
  - `duplicate`（重复引入，约束一致或相容）→ 仅标记，不影响判定。

## 缓存与并发语义

- 缓存键为 `(content_hash, policy_version)`：策略发布 / 回滚后键空间改变，旧版本条目由注册表监听器主动清除（`invalidate_except`），不会返回旧结论。
- **单飞（single-flight）**：相同内容的并发请求共享同一次计算——第一个到达的线程计算，其余等待并复用结果，保证只计算一次且所有并发调用方拿到同一报告对象。
- 注册表与缓存内部均使用锁保护，多线程 / 多请求并发安全。

## HTTP 接口

| 方法 | 路径 | 角色 | 说明 |
| --- | --- | --- | --- |
| GET | `/` | 公开 | 健康检查（保持原有行为） |
| POST | `/scan` | readonly+ | 请求体为原始清单内容，返回判定报告 |
| POST | `/policies` | publisher | 登记策略草稿 |
| POST | `/policies/{v}/publish` | publisher | 发布版本 |
| POST | `/policies/{v}/rollback` | publisher | 回滚到历史已发布版本 |
| GET | `/policies/current` | readonly+ | 查询当前生效策略 |

错误响应统一为 `{"error": <可区分原因>, "detail": ...}`。

## 日志

扫描日志（`scanner.service`）打印 `content_hash`、`policy_version`、`decision`、逐项 denied 数与图问题摘要；拒绝条目逐条打印原因与位置；策略登记 / 发布 / 回滚与缓存失效也有对应日志（`scanner.policy` / `scanner.cache`）。

## 本地验证

```bash
uv sync                 # 安装依赖（含 dev 组：pytest、httpx）
uv run pytest tests/ -q # 运行全部测试（畸形清单、并发同内容、回滚重算等）
uv run uvicorn main:app --host 127.0.0.1 --port 8000

# 发布策略并扫描
curl -X POST localhost:8000/policies -H 'Authorization: Bearer publisher-token' \
     -H 'Content-Type: application/json' -d '{"version": 1, "denied_packages": ["log4j"]}'
curl -X POST localhost:8000/policies/1/publish -H 'Authorization: Bearer publisher-token'
curl -X POST localhost:8000/scan -H 'Authorization: Bearer readonly-token' \
     --data-binary $'flask>=2.0\nlog4j==2.14.0\n'
```
