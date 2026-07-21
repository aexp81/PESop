# C 阶段设计：情报组合-消费-反馈闭环（synth 装配台）

> 承接 docs/ARCH-DECISIONS.md + BACKLOG TASK-006。解决"情报收集了却各自停在发现层,
> 没交叉组合成真实请求"的总病根(实战实证:73 路径/EagleEye 头/token/UUID 互不组合)。
> 方案层次 B(已定):engine 做机械的【组合装配 + 消费追踪 + 入库触发关联】,不自动发包、
> 不全排列爆炸、不替 AI 决定打哪条。状态:v0.1 骨架设计。

---

## 0. 目标与原则对齐

**目标**:把 intel 从"平行躺着的静态仓库"升级为"能把散落情报撮合成【完整请求候选链】、
并追踪每条链发没发过、新情报入库即触发关联提示"的活账本。让 AI 面对的是"已装配好的攻击链
候选 + 为什么这么配 + 发没发过",逼它对每条未消费的链做判断——而非自己从零想起组合。

**两条原则怎么守**:
- **避免过度设计**:engine 只做"机械撮合 + 记账 + 提示",不发包、不判断打哪条、不做全排列。
  组合规则外置到 yaml(可扩展)。
- **不越界(骨架宪法)**:延续"摆事实+提问、不替 AI 决策"。engine 摆"候选链+装配理由+消费状态",
  发不发、怎么改由 AI 定。绝不自动发包(否则组合爆炸 + 抢 AI 判断)。

---

## 1. 先补一个前置缺口:请求头情报没被挖

实战里 EagleEye/X-B3-*/uber-trace-id 等**拦截器注入的请求头**,当前 js_harvester **根本没挖**
(intel 无 headers 字段)。组合链需要"该带哪些头",故先补:
- js_harvester 新增 header 提取:扫 axios 拦截器 `config.headers[...]=`、`setRequestHeader(...)`、
  `headers:{...}` 里的头名(尤其 EagleEye-*/X-*/Authorization/uber-trace-id 等)。
- 写入 intel 新增字段 `headers`:[{name, source, context}]。

---

## 2. 涉及文件

| 文件 | 动作 | 责任 |
| --- | --- | --- |
| `engine/synth.py` | **新建** | 组合装配台:读 intel → 撮合请求候选链 → 消费追踪 → 落盘 |
| `knowledge/combine.yaml` | **新建** | 组合规则库(哪种情报×哪种情报=什么链,可扩展) |
| `engine/js_harvester.py` | **微改** | 补 header 提取 → 写 intel.headers |
| `engine/intel.py` | **微改** | 新增 headers 字段;新增 chains 存储(候选链+消费状态);入库触发关联提示 |
| `engine/run.py` | **微改** | status/next 展示"未消费的候选链"(摆事实,不下指令) |
| `engine/tests/test_synth.py` | **新建** | 单测:组合规则/消费追踪/关联触发 |

> 地基(http_client/evidence)零改动。engine 不发包。

---

## 3. 核心数据结构:请求候选链（chain）

一条 chain = 把散落情报装配成的一个**完整、可直接发的请求描述**(但 engine 不发):

```json
{
  "id": "chain-0001",
  "method": "POST",
  "url": "https://api.corp.com:30812/prod-api/account-auth",   // base+prefix+path 拼好
  "headers": {"EagleEye-TraceID": "<需填>", "Authorization": "Bearer feedbackPamsToken..."},
  "body_hint": "account=?&password=? (来自 JS 登录调用)",
  "assembled_from": {                       // 【为什么这么配】——可回溯
    "base": "backends[0] (axios.baseURL, 30812)",
    "path": "endpoints: /account-auth",
    "headers": "headers: EagleEye-* (拦截器注入)",
    "token": "secrets: feedbackPamsToken"
  },
  "rationale": "登录接口 × 已发现token × 拦截器头 —— token 复用/绕过候选",
  "consumed": false, "consumed_by": null    // 发没发过(消费追踪)
}
```

存于 `runs/<target>/chains.json`(与 intel/findings 平级)。

---

## 4. 扩展点:`knowledge/combine.yaml`（组合规则库）

声明"哪类情报 × 哪类情报 = 什么链",synth 只解释。加组合方式 = 追加一条,零代码。
**关键:每条规则是"有意义的配对",不是全排列**(治组合爆炸)。

```yaml
# 情报组合规则:哪种情报×哪种情报=什么请求候选链。synth 只解释,不发包。
# 只做有意义的配对(非全排列),加规则追加一条即可。
combine_rules:
  - id: base-x-path
    desc: "后端base × 接口路径 = 完整候选URL(治'路径×端口拆成三步')"
    needs: [backends, endpoints]
    produce: "对每个非前端 base,拼 base+prefix+path 成完整 URL"

  - id: authpath-x-token
    desc: "需鉴权接口 × 已发现token = 带鉴权的请求(治'token没复用')"
    needs: [endpoints, secrets]
    match: "path 含 auth/login/admin/user 等 OR endpoint 曾返回 401/403"
    produce: "把 token 以 Authorization:Bearer / X-Token / Cookie 多位置各生成一条候选"

  - id: path-x-tracehdr
    desc: "接口 × 拦截器注入头 = 带完整头的请求(治'EagleEye头第N次才加')"
    needs: [endpoints, headers]
    produce: "对每个 base+path,附上所有拦截器头(EagleEye-*/X-B3-*/uber-trace-id)"

  - id: id-x-param
    desc: "已发现UUID/ID × 形似参数的接口 = 关联调用(治'UUID没关联')"
    needs: [secrets, endpoints]
    match: "value 形如 UUID;endpoint 参数名含 org_id/project_id/id"
    produce: "把 UUID 代入该参数生成候选"

  - id: host-x-proxyhdr
    desc: "内网域名 × 代理头 = 路由绕过候选"
    needs: [hosts, endpoints]
    produce: "对接口附 X-Forwarded-For/X-Real-IP=内网IP 生成候选"
```

---

## 5. `engine/synth.py`（装配台,核心）

```
build(target):
  1. 读 intel(backends/endpoints/secrets/headers/hosts)
  2. 读 combine.yaml 规则,逐条按 needs/match 撮合 → 生成 chains(带 assembled_from/rationale)
  3. 去重(同 method+url+关键头) + 保留旧 chains 的 consumed 状态(不重置已发过的)
  4. 落盘 chains.json;返回摘要
  # 绝不发包。只装配。

consume(target, chain_id, by, result_note):
  把某条 chain 标记 consumed=true(AI 发过后回填),用于"发没发过"追踪。

pending(target):
  返回所有 consumed=false 的候选链(摆给 AI:这些链还没打过,你判断打哪条/怎么改)。

relate(target, new_item):     # 反馈触发(可被 intel.add 调用,或单独跑)
  给定一条新入库情报,返回"它能和哪些旧情报组合成新链"的提示(疑问式)。
```

**CLI**:`synth.py build/pending/consume/relate --target ...`

---

## 6. 反馈循环怎么落地（治"顺序执行不回头"）

两个触发点,都只**提示**不自动做:
- **新情报入库**:`intel.add` 成功后,可选调用 `synth.relate` → 在返回里带
  "这条新情报能和 X/Y 组合成新链,建议 synth build 重新装配"。
- **新响应/新 finding**:AI 拿到接口响应(如返回 UUID/新接口)→ add 进 intel → 再 build →
  pending 会多出新链 → AI 看到"还有未打的链"。
这样"拿到 210331 后回头重看"变成:新 ID 入库 → 触发关联 → 新候选链浮现,而非靠 AI 自觉。

---

## 7. run.py 出口（延续"摆事实+提问"）

status/next 增加一段:
```
⑨ 待消费攻击链:synth 已装配 N 条候选,其中 M 条还没打过。
   (摆出前几条:method+url+为什么这么配) 你判断哪条最可能突破?先打哪条?为什么?
```
只摆"已装配好的链 + 装配理由 + 发没发过 + 反问",不下"去打第 X 条"的指令。

---

## 8. 严守原则自检

| 检查 | 结论 |
| --- | --- |
| 过度设计? | engine 只撮合+记账+提示,不发包/不判断打哪条;规则外置yaml。✅ |
| 组合爆炸? | 只按 combine.yaml 的"有意义配对",非全排列;去重。✅ |
| 越界(替AI决策)? | 只摆候选链+理由+消费状态+反问,发不发/怎么改由AI定。✅ |
| 治好病了? | 三症状对应三规则(base×path/token复用/EagleEye头)+消费追踪(发没发过)+入库触发(反馈循环)。✅ |

---

## 9. 落地节奏（先窄后宽）

1. **补 header 提取 + intel.headers 字段**(前置,组合链需要头)。
2. **synth.build + combine.yaml(base×path / path×header / authpath×token 三条最高频规则)+ chains.json + consume/pending**。
3. **反馈触发 relate + run.py ⑨ 出口**。
4. **单测 + 端到端验证**(造 backends+endpoints+headers+token 态势,看是否装配出"30812+/prod-api/account-auth+EagleEye头+Bearer token"这条链)。

> 做完第 2 步就已解决"路径×端口×头拆成三步、token没复用"的主症状;反馈循环是第 3 步增强。
