# AGENT.md · PESop 全自动执行框架 v5.0（AI 唯一入口）

> 你（AI）拿到一个授权目标后,读这一个文件就开工。不必通读 L1/L2/L3。
> L1/L2/L3 是给人的方法论事实源;本文件是给你的可执行工程契约。
> 仅用于**授权范围内**的安全评估。

---

## 0. 架构总览（三维 + 贯穿内核）

PESop 把安全测试拆成"**三个打法域 + 两个横切维度 + 一个推理内核**":

```
        ┌────────── 情报库 intel（维度二·共享供料,所有域读写）──────────┐
        │  端口/DNS/证书 · 指纹 · WAF · 系统类型 · 接口 · 密钥 · 内网IP     │
        └────────────────────────────────────────────────────────────────┘
              ↓取料           ↓取料              ↓取料
        ┌───────────┬──────────────────┬────────────────────┐
        │ infra 域   │ framework 域      │ application 域      │  ← 维度一·三打法域
        │ 端口/中间件 │ 框架/组件确定性链  │ 接口/业务发散       │
        │ (反射档)   │ (反射档,给全弹药) │ (建模档,只给判据)   │
        └───────────┴──────────────────┴────────────────────┘
              ↑产物流动(一域产出→写intel→另一域取用,漏洞穿成链)
        ┌──────── WAF 调节器（维度三·横切:有WAF则payload先绕过）─────────┐
        └────────────────────────────────────────────────────────────────┘
        ┌──────── Q1-Q5 推理内核（贯穿,按域确定性分三档运行）────────────┐
        └────────────────────────────────────────────────────────────────┘
```

工具映射:
- `engine/http_client.py` 发包+存证(一切地基) · `engine/evidence.py` 证据台账
- `engine/recon.py` 指纹→按 tag 分诊到三域 + 写 intel
- `engine/intel.py` 情报库(共享供料+产物流动) · `engine/waf.py` WAF识别+绕过手法
- `engine/js_harvester.py` (application域)JS挖掘 · `engine/reflow.py` 分层回灌
- `knowledge/domains/{infra,framework,application}/` 各域 playbook
- `knowledge/waf/` WAF资产 · `knowledge/payloads/` 绕过库 · `knowledge/wordlists/` 字典

一句话范式:**用执行结果说话,不用文字声称。** 你没真发过的请求,不许写进结论。

---

## 1. 铁律（违反即本次测试作废）

1. **发包必走 engine,证据即落盘。** 用 `engine/http_client.py`,禁止脑内"我访问了X返回Y"当证据。
2. **确认漏洞必须挂真实 evidence_id。** `engine/evidence.py add --status confirmed` 挂不上真实证据会被自动降级 suspected。谎报物理上做不到。
3. **终态才算完成。** `unknown→suspected→confirmed/disproved`,suspected 是库存不是成果。
4. **application 域思路必须显式化。** 进该域(建模档)先写 Q1-Q5,人靠看推理审计你。
5. **深度优先。** 发现高价值点(RCE/接管/未授权写/越权)立刻钻到终态,不回头铺广度。

---

## 2. Q1-Q5 三档运行（内核,回答"何时建模")

Q1-Q5 是贯穿全程的推理内核,但**投入与不确定性成正比,分三档**:

| 档 | 触发 | 怎么跑 |
|----|------|--------|
| **反射档** | infra/framework 域,指纹/端口已命中 | Q1身份秒确定→Q2/Q3由指纹**确定性展开**成攻击链→直接打。**内化,不写作文** |
| **建模档** | application 域 | Q1-Q5 **必须显式写出**:什么系统/若我是开发者接口怎么设计/最可能哪坏。重成本发散 |
| **纠偏档** | 任何域遇意外信号(该403却200/异常报错/绕过成功) | Q5 抢占:假设被打破→修正模型→切维度 |

**核心:确定性高的域(infra/framework)少建模多打;确定性低的域(application)重建模。**

Q1-Q5 定义:
- Q1 这是什么系统?(定位技术栈层,据 recon/intel)
- Q2 我若是开发者会怎么建?(技术选型+业务链+敏感点+易漏防护处)
- Q3 最可能哪里失效?(由Q1+Q2推3-5个针对性假设,禁答"清单上有")
- Q4 怎么验?(变量隔离:控制组→只改一个变量→发包看变化)
- Q5 响应说明什么?(每个响应含403都是信号;证伪≠系统安全,是模型要修正,切维度继续)

---

## 3. 标准作业流程（SOP loop）

```
0 授权     复述边界与禁区
1 情报就位  engine/run.py init(自动串 waf识别 + recon指纹分诊 + 写intel,一条命令完成)
2 看态势    engine/run.py status(看 WAF/指纹分诊/接口/密钥/建模状态 + 下一步建议)
3 framework域(反射档,优先,投产比最高):
     读intel指纹→加载domains/framework对应playbook→按chains展开确定性攻击链
     →有WAF则engine/waf.py advise拿绕过手法包装payload→http_client发包存证
     →命中的密钥/DB串/session会经 intel 自动/手动沉淀,供别域取用
4 infra域(反射档):
     读intel端口/中间件指纹→domains/infra打未授权→拿到的内网IP/凭证写回intel
5 application域(建模档):
     js_harvester挖接口(自动写intel)→【必须先 intel.py model 填Q1-Q5】
     →未授权→绕过(读payloads+waf.advise)→FUZZ(业务发散+wordlists兜底)→越权/业务不变量
6 收尾     engine/evidence.py report(发现+情报聚合)→写runs/<target>/report.md→reflow分层回灌
```

**编排:step1-2 用 `run.py init/status` 固化,不必自己记工具顺序;随时 `run.py next`
问下一步该干嘛。跨域产物(密钥/接口/内网IP)经 intel 流动——js_harvester/recon/waf
的产出会自动写 intel;framework/infra 域手动打出的密钥用 `intel.py add` 沉淀。**

---

## 4. engine 用法速查

```
# —— 编排(推荐入口,固化流程骨架)——
python engine/run.py init   --target https://t.com   # 情报就位:waf识别+recon分诊+写intel
python engine/run.py status --target https://t.com   # 全局态势+下一步建议
python engine/run.py next   --target https://t.com   # 只看下一步该干嘛

# —— 单模块(需要精细控制时)——
python engine/waf.py identify --target https://t.com        # 判WAF,写intel
python engine/recon.py --target https://t.com               # 指纹分诊,写intel
python engine/intel.py summary --target https://t.com        # 看情报库

# framework/infra 域(反射档):读分诊结果→加载对应 domains/ playbook→发包
python engine/http_client.py --target https://t.com GET /actuator/env --note "framework:actuator"
python engine/waf.py advise --waf cloudflare                 # 有WAF先拿绕过手法

# application 域(建模档):挖接口→必须先建模→再测
python engine/js_harvester.py --target https://t.com         # 挖接口/密钥(自动写intel)
python engine/intel.py model --target https://t.com \
    --q1 "订单系统" --q2 "若我开发会用..." --q3 "最可能越权/改价"   # 进application域前必填Q1-Q5

# 跨域产物流动:手动打出的密钥/接口沉淀进 intel 供别域用
python engine/intel.py add --target https://t.com --field secrets \
    --json '{"name":"NACOS_PWD","value":"...","source":"actuator/env"}' --dedup-key name

# 记发现(确认必挂真实 evidence_id)
python engine/evidence.py add --target https://t.com \
    --title "Actuator→Nacos接管→DB" --severity critical --status confirmed \
    --evidence ev-xxx --hypothesis "..." --impact "拿DB/改配置"

# 收尾
python engine/evidence.py report --target https://t.com      # 发现+情报聚合(一处可见)
python engine/reflow.py fingerprint/check/waf/payload ...    # 分层回灌(见第6节)
```

评级按**真实可利用性**,拿不准降级标 suspected,不为显高危拔高。

---

## 5. 三域各自的打法要点

### infra 域（基础设施,反射档）
- 读 intel 端口/中间件指纹 → `domains/infra/`(ports.yaml 映射 + middleware.yaml 打法)
- 能力边界:纯 TCP 端口扫描待接入;现阶段打 HTTP 可达的中间件未授权(Druid/Nacos/ES等)
- 产出(session/DB串/内网IP)写回 intel

### framework 域（框架组件,反射档,给全弹药）
- 读 intel 指纹 → `domains/framework/` 对应 playbook 的 **chains**(确定性攻击链)
- Spring Boot 例:SpEL/Spring4Shell/log4j2/FastJSON/Actuator→Nacos→DB/heapdump→密钥/Druid→后台
- 鉴权框架(Shiro/Spring Security)绕过 → `knowledge/payloads/auth-bypass.yaml` 按框架身份选
- 这层是确定性的:指纹一定,攻击链直接展开打,不必逐条写 Q1-Q5

### application 域（应用业务,建模档,只给判据）
- `domains/application/`:unauth-bypass-fuzz(未授权→绕过→FUZZ流程)、business-invariants(业务不变量)、oauth-sso、zhuyun-iam
- 必须先写 Q1-Q5 建模,再发散;FUZZ 由业务语义驱动,wordlists 只兜底
- 越权/业务漏洞:先建对象模型+状态机+不变量,再找违反不变量的证据(带副作用)

---

## 6. 收尾回灌（复利飞轮,分层沉淀）

每次收尾用 `engine/reflow.py` 把可复用知识分层 append 进 knowledge(只增不删+去重):
- 新指纹 → `reflow.py fingerprint`(带 tag,自动归对应域)
- 新攻击链/check → `reflow.py check`(写进对应 domains/ playbook)
- 新 WAF 指纹/绕过手法 → `reflow.py waf`
- 新绕过 payload → `reflow.py payload`
- **只回灌可复用判据/手法,目标专属数据留 runs/**

分层回灌 = 分层复利:framework 弹药越足秒杀越多;application 判据越准发散越好;
WAF/payload 库越厚绕过越强。且按域按需调取,沉淀增长不拖累单次上下文。

---

## 7. 你要避免的五种失效（人会盯这几点看你）

| 失效 | 表现 | 本工程如何治 |
|------|------|-------------|
| F1 半成品当交付 | 铺得好看没钻透 | 铁律5深度优先+终态才算完 |
| F2 谎报 | 声称确认无真证据 | evidence.py 强制挂真实 evidence_id |
| F3 漏假设 | 套固定清单/漏域 | 三域分诊全覆盖 + application域Q1-Q5发散 |
| F4 评级偏差 | 为显高危拔高 | 按真实可利用性,拿不准降级 |
| F5 用例脱离语义 | 通用payload硬套 | application域payload必须业务发散;每条能回答"为何对它用" |

> 人看你的:Q1-Q5推理链(application域)、每个结论挂的evidence_id、
> 高价值点有没有真钻穿、跨域产物有没有真的串起来(intel里的流动)。
