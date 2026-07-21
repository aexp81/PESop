# PESop 待办任务清单（BACKLOG）

> 长期迭代项目的待办沉淀。每条含:背景 / 影响 / 建议方向 / 状态。
> 会话内的临时跟踪用 write_todos;跨会话要留存的待办记这里。
> 状态标记:🔴未开始 / 🟡进行中 / 🟢已完成。

---

## TASK-001 · WAF 识别把「CDN」误当「WAF」🔴

**优先级**:中

**发现时间**:2026-07-21(测试前体检,实测 example.com)

**背景**:
`engine/waf.py` 的 `identify` 目前靠响应头/响应体里的指纹关键词判定有无 WAF。
实测 example.com 被判为 `cloudflare`——响应头确实有 `server: cloudflare`/`cf-ray`/
`cf-cache-status`,识别本身没错,但语义有问题:**Cloudflare 作为 CDN 与作为 WAF 是两回事**。
很多站点用 Cloudflare 只做 CDN 加速,并未启用 WAF 规则。当前逻辑只要看到 CDN 指纹
(如 `cf-ray`)就判"有 WAF"。

**影响**:
- 大量仅用 CDN 的普通站点被误标成"有 WAF"。
- `run.py` 的 next_advice 会持续提示"发 payload 前先绕过",而实际并无拦截,产生噪声、
  干扰判断,甚至诱导 AI 做无谓的绕过尝试。

**建议方向**(待定,不急于改):
- WAF 的**存在性**应由"发带攻击特征的探测包时是否被拦截"(如正常包 200 但攻击包 403/
  返回拦截页/连接被重置)来判定,而非仅凭 CDN 指纹。
- 可把"CDN 身份"与"WAF 是否拦截"拆成两个字段:`intel.waf` 记 `cdn`(如 cloudflare)与
  `blocking`(是否观察到拦截行为)分别记录,advise 只在 `blocking=true` 时才强提示绕过。
- 需保留 waf.py 现有的"识别是什么 WAF/CDN"能力(供 advise 选绕过手法),只是不再把
  "识别到 CDN 指纹"等同于"有 WAF 拦截"。

**验证数据**:待本次实战测试回来补充(有多少目标被误标"有WAF")。

---

## TASK-002 · floor_guard 覆盖下限判定过粗（多域共用同一终态判断）🔴

**优先级**:中

**发现时间**:2026-07-21(测试前体检 + 前期设计已知简化)

**背景**:
`engine/floor_guard.py` 的原子检查 `_check_fingerprint_tag_covered` 目前用 v0.1 简化规则:
"某 tag 有指纹命中,但 findings 里**没有任何**终态(confirmed/disproved) → 判该域未覆盖"。
问题在于**三个打法域(infra/framework/application)共用同一个"有没有终态 finding"的判断**,
没有把 finding 归属到具体的域。

**影响**:
- 跑多域目标时,只要**任意一个域**打出一个终态 finding,其它域的覆盖检查也会被误判为
  "已达标"。
- 后果:下限守门可能**过早放行**(误报"下限已达标/可判走不通"),削弱"防漏测"这一核心职责,
  与骨架宪法"守下限"的目的相悖。

**建议方向**(待定):
- 让 finding 记录所属域(如给 `evidence.add_finding` 加 `domain` 字段:infra/framework/
  application),`_check_fingerprint_tag_covered` 按域匹配"该域是否有对应终态 finding",
  而非全局判断。
- 或引入更细的"域覆盖台账"(每个命中指纹是否已被展开攻击链/推到终态),按指纹粒度判覆盖。
- 注意保持"避免过度设计"原则:优先用最小改动(finding 加 domain 字段)解决,不新造复杂子系统。

**验证数据**:待本次实战测试回来补充(多域目标下,下限体检是否过早说"允许判走不通")。

---

## TASK-003 · js_harvester 密钥提取误报（2字母常量名过宽）🔴

**优先级**:低-中

**发现时间**:2026-07-21(JS 全量提取重构后,对 github.com 端到端实测)

**背景**:
`engine/js_harvester.py` 的 `_SECRET_KEY_NAMES` 含 `AK`/`SK` 这类 2 字母常量名,配 `_RE_SECRET`
做 `名=值` 匹配。实测把 SVG 里的 `sk = url(#mask0_...)`(mask 引用)误当成密钥,产生噪声
(github.com 一次跑出 18 个"疑似密钥",多为误报)。

**影响**:
- 疑似密钥清单噪声大,人工确认成本高;误报 value 还会经 intel 自动流入 secrets,
  可能拖累"榨干下限"判定(把噪声当成待利用情报)。

**建议方向**(待定):
- `AK`/`SK` 等短名要求更严格上下文(前面紧跟 access/secret/_,或值形如云 AK 特征),而非裸 2 字母。
- 或对 value 做形态校验(排除 url()/#hex/纯 CSS 值等明显非密钥形态)。
- 保留高信号长常量名(APP_KEY/SENTRY_DSN 等)不动,只收紧短名与 value 形态。

**验证数据**:本次实战测试可统计误报率,回来据此校准。

---

## TASK-004 · SPA 懒加载路由未主动触发（JS 收割深度短板）🔴

**优先级**:中-高(直接影响 JS 收割完整度)

**发现时间**:2026-07-21(实战反馈:未触发 SPA 懒加载路由发现更多 webpack chunk)

**背景**:
JS 全量提取重构后,L1 静态分包已能识别打包工具并递归收割 chunk,L2(js_browser)已做
**被动捕获**(加载首页时浏览器实际请求的 JS)。但**未做"主动触发路由跳转"**——SPA 的
`/aec-app/`、`/plan-app/` 等不同路由,其懒加载 chunk 只有真的跳转过去才会加载。
v0.1 的 js_browser 只被动捕获首页(设计文档 5 节已标注 v0.1 仅被动)。

**影响**:
- 首页之外路由的懒加载业务模块(往往是核心接口所在)收割不到,JS 覆盖仍不完整。
- 实战反馈:实际可收割 JS 应 100+,旧版只拿到 ~22;需主动跳路由才能逼近全量。

**建议方向**(待定):
- js_browser 增加:从 JS 里抠路由表(react-router/vue-router 配置) → 逐个 goto 触发懒加载
  → 捕获新增的 chunk URL → 交回 http_client 下载存证。
- **前提**:测试环境需装 playwright(pip install playwright && playwright install chromium),
  否则 L2 不生效,只能靠静态层。

**验证数据**:本次实战测试记录"静态收割数 vs 应有数",回来据此评估必要性。

---

## TASK-005 · 微前端子应用入口未自动发现（JS 收割广度短板）🔴

**优先级**:中

**发现时间**:2026-07-21(实战反馈:未递归收割 /aec-app/ 等微前端子应用 JS)

**背景**:
微前端(qiankun/micro-app/wujie 等)的子应用 JS 往往是运行时从子应用 entry 动态加载,
静态扫主应用 chunk 可能扫不到子应用入口,除非主应用配置里硬编码了子应用地址。

**影响**:
- 各子应用(独立业务域)的 JS 与接口整片漏挖,是"漏测"的重灾区。

**建议方向**(待定):
- bundlers.yaml 加一条"微前端配置识别"规则:扫主应用里的子应用注册表
  (如 `registerMicroApps([{entry:'/aec-app/'}])`) → 把每个子应用 entry 加入收割队列 →
  对每个子应用入口重跑一遍 L0/L1 收割。
- 成本低(复用现有 chunk 提取),可与 TASK-004 一并做。

**验证数据**:本次实战测试记录漏掉的子应用清单。

---

## 其它已知项（暂不列为独立 TASK，记录在此备查）

- **intel/findings 无并发保护**(低):单进程串行跑无影响;若未来并行打多域需加文件锁或
  append-only 结构。
- **infra 域 TCP 端口扫描未接入**(设计现状):现阶段只打 HTTP 可达的中间件未授权。
- **FUZZ 无执行器**(待规划):接口/参数/业务 FUZZ 目前靠 AI 手工发 http_client 包,
  engine 尚无 FUZZ 骨架——这是前期讨论确认的"精髓待落地"部分,后续单独立项。
