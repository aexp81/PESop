# 人机协作渗透测试 SOP + 全自动执行工程

> 长期迭代资产。仅用于授权范围内的安全评估。
> 版本 v5.2 · 三维架构(三打法域 + 情报库/WAF 两横切 + Q1-Q5 三档内核) + 下限守门层。

## v5.0 架构（三维 + 贯穿内核）

在 v4.0「证据驱动 + 按需调取 + 越用越强」基础上,把测试组织成**三个正交维度**:

- **维度一·三打法域(tag)**:按攻击面所处技术栈位置分诊,每域独立探测/漏洞/知识/打法
  - `infra` 基础设施:端口/中间件未授权(反射档,确定性)
  - `framework` 框架组件:框架/组件确定性攻击链(反射档,给全弹药——SpEL/Spring4Shell/log4j2/FastJSON/Actuator→Nacos→DB…)
  - `application` 应用业务:接口/业务(建模档,发散,只给判据——未授权→绕过→FUZZ→越权/业务不变量)
- **维度二·情报库 intel**:侦察不是"阶段"而是持续累积、所有域共享读写的情报。
  一个域的产出(密钥/内网IP/session)写回 intel 成为另一域输入——**漏洞穿成链**。
- **维度三·WAF 调节器**:横切。识别有无 WAF+什么 WAF→有则发 payload 前先取绕过手法;无则常规打。
- **贯穿内核·Q1-Q5 三档**:反射档(infra/framework,指纹已定直接展开攻击链,不写作文)/
  建模档(application,必须显式写 Q1-Q5 发散)/纠偏档(遇意外信号抢占修正模型)。
  **核心原则:建模投入与不确定性成正比——确定性高的域少建模多打,低的域重建模。**

## 下限守门层（floor guard · 骨架承重墙）

三维架构解决"怎么打",下限守门层解决"打到什么程度算够、什么时候才算走不通"。

- **目的驱动**:安全测试的目的是产出**有价值的漏洞**(严重/高危/中危),其次是不漏测。
  指挥测试进度的不是技术信号(如返回 403),而是**价值密度**。
- **只守下限,不设上限**:engine 只负责守住下限(防漏测/防偷懒/防跑偏);下限之上放开,
  让模型尽情发散深挖,engine 不封顶。
- **"走不通"的定义** = 价值未达成(无 confirmed 的中危+漏洞) **且** 努力已充分
  (覆盖下限达标 且 榨干下限达标)。只有两者都满足,才允许判"走不通"、才发散/变思路。
- **只出缺口,不下指令**:守门员说"你还差 framework 域没覆盖"(陈述缺口),不说"去打 Druid"
  (下达指令)。缺口怎么补是 AI 的发挥空间。
- **可扩展**:下限定义在 `knowledge/floor.yaml`,加新下限追加一条即可,骨架不改动。

> 详见 `docs/ARCH-DECISIONS.md`(为什么这么定)与 `docs/A-floor-guard-design.md`(怎么搭)。

## 目录结构

| 路径 | 作用 | 谁读 |
| --- | --- | --- |
| `AGENT.md` | **AI 唯一入口**:三维架构执行契约(铁律/三档内核/SOP loop/分层回灌) | AI 每次读 |
| `engine/run.py` | **编排器**:init(串waf+recon+写intel) / status(态势+下一步+下限体检) / next | AI 流程入口 |
| `engine/http_client.py` | 统一发包+自动存证(curl 优先,python 兜底) | AI 调用 |
| `engine/evidence.py` | 证据台账(无真实证据不许 confirmed) + report(聚合intel) | AI 调用 |
| `engine/recon.py` | 指纹识别(纯读yaml的match)→按 tag 分诊 + 自动写 intel | AI 调用 |
| `engine/intel.py` | 情报库:共享供料+跨域产物流动+Q1-Q5建模档(model)+consumed标记(consume) | AI 调用 |
| `engine/waf.py` | WAF 横切调节器:识别(写intel) + 给绕过手法 | AI 调用 |
| `engine/js_harvester.py` | (application域)JS 全量拉取+接口/密钥提取(自动写intel) | AI 调用 |
| `engine/floor_guard.py` | **下限守门**:读态势→对照 floor.yaml→出缺口清单+三态裁决(只守下限不设上限) | AI 调用 |
| `engine/reflow.py` | 分层回灌:新指纹(带match)/链/WAF/payload(只增不删+去重) | AI 调用 |
| `engine/tests/` | engine 单元测试(mock 态势,守护证据校验/下限裁决等承重墙语义) | 开发者/CI |
| `knowledge/fingerprints.yaml` | 指纹→身份→tag(分诊域)+playbook | AI 按需读 |
| `knowledge/floor.yaml` | **下限定义**(声明式检查项:覆盖下限+榨干下限,加下限追加一行即可) | floor_guard 读 |
| `knowledge/domains/{infra,framework,application}/` | 三域 playbook(framework 含确定性攻击链 chains) | AI 命中才读 |
| `knowledge/waf/` | WAF 识别指纹 + 各 WAF 绕过手法 | AI 命中才读 |
| `knowledge/payloads/` | 鉴权绕过 payload 库(按框架身份分组) | AI 按需读 |
| `knowledge/wordlists/` | TOP 路径字典(FUZZ 兜底) | AI 按需读 |
| `runs/<target>/` | 每次产物:证据/intel情报/发现台账/报告(不进版本库) | AI 写,人看 |
| `docs/` | 骨架决策记录(ADR)+ 各阶段设计文档(长期迭代的地基约定) | 人(架构演进) |
| `L1-methodology.md` | 方法论事实源(为什么这么做),F1-F5/四准则的推导 | 人(审计时) |
| `L2-ai-prompt.md` | 老执行清单,现作 HF-1~7 细则参考,被 AGENT.md 引用 | 人/AI 查阅 |
| `L3-knowledge.md` | 历史经验散文库,新知识优先结构化进 knowledge/ | 人 |

## 怎么用（全自动模式）

1. 把项目 down 到你的持久化环境(能真发包)。
2. 给 AI 一个授权目标 + 让它读 `AGENT.md` 开工。
3. AI 按 SOP loop 跑,每步都有对应 engine 命令:
   ```
   情报就位   python engine/run.py init   --target https://t.com   (串 waf+recon+写intel)
   看态势     python engine/run.py status --target https://t.com   (态势 + 下一步 + 下限体检)
   加载playbook  读 recon 提示的 knowledge/domains/<tag>/<id>.yaml
   建模       python engine/intel.py model ...(application 域写 Q1-Q5)
   挖接口     python engine/js_harvester.py --target https://t.com
   深钻P0     python engine/http_client.py ...(每步发包自动存证)
   记发现     python engine/evidence.py add ...(确认必挂真实 evidence_id)
   榨干情报   python engine/intel.py consume ...(密钥/内网IP 用过了标记 consumed)
   下限体检   python engine/floor_guard.py assess --target https://t.com (够不够收工)
   收尾       python engine/evidence.py report + 写报告 + engine/reflow.py 回灌
   ```
4. 你看 `runs/<target>/` 里的 Q1-Q5 推理、每个 finding 挂的 evidence_id、
   P0 是否钻穿、下限体检有没有缺口——从执行思路和证据一眼审出跑偏。

## 迭代规则（复利飞轮,工程化版）

- **runs/ 留具体数据,knowledge/ 留可复用判据**:每次收尾用 `engine/reflow.py` 把新
  指纹/新手法 append 到 knowledge/(工具保证只增不删+去重+格式统一),目标专属数据留 runs/。
- **飞轮已闭环**:reflow 回灌的新指纹,下次 `engine/recon.py` 就能自动识别——
  沉淀越多,AI 单次任务反而越聚焦(按需调取,不通读)。
- **靠扩展变强,不改原生骨架**:新增下限追加 `knowledge/floor.yaml` 一条;新增指纹/域
  playbook 加文件即可。原生 engine 骨架保持稳定,能力靠可插拔扩展点生长。
- knowledge/ 里反复命中、验证稳定的模式,再提炼进 L1/L2(人做,打版本号)。
- engine/ 保持零第三方依赖(pyyaml 可选,无则内置解析兜底),持久化环境到哪都能跑;
  承重墙语义(证据校验/下限裁决)由 `engine/tests/` 单元测试守护。

## 版本历史


| 版本 | 日期 | 核心变化 |
| --- | --- | --- |
| v1.1 | 2026-06-30 | 首版入库：攻击面穷举机制 + CVE 反幻觉硬规 |
| v1.2 | 2026-06-30 | 谎报治理：确认必带 PoC，补上"漏报"的对称盲区 |
| v1.3 | 2026-07-01 | 实战回灌：OAuth/SSO 服务端指纹 + CDN 绕过强制项 |
| v2.0 | 2026-07-03 | 第一性原理重构：L2 从"五项强制堆叠"改为"四条根本准则推导" |
| v3.0 | 2026-07-08 | 架构纠偏：四条根本准则/F1-F5 迁回 L1（唯一事实源），L2 瘦身为锚点+清单，对齐闸独立首用，删除已实施完毕的重构草案文件 |
| v3.1 | 2026-07-08 | 对标资深渗透/赏金猎人补差距（Phase 1）：四项强制扩为五项（新增资产暴露面 OSS/MinIO）、准则一补 OOB 证据形式、新增「危害升级」小节、攻击面穷举补实时协议层（WebSocket/MQTT）、HF-4 扩写账号权限矩阵与交叉测试、HF-2 补 APK 静态提取分支；报告交付物质量/GraphQL 专项列为 Phase 2，未纳入本次 |
| v3.2 | 2026-07-08 | 权限绕过项（五项强制第4项/HF-4）重写为四步递进序列：接口未授权→接口权限绕过→水平越权→垂直越权，前提为 HF-2+HF-3.1 产出的全量接口清单；②步新增「框架身份驱动绕过」（先识别鉴权框架身份再查该框架已知绕过模式，Java+Shiro/Java+Spring Security/PHP 给代表性历史模式锚点，非穷尽、非断言必中）；新增「错误驱动参数回填」（缺参数先按报错回填参数名，FUZZ 为次选）|
| v3.3 | 2026-07-09 | 业务逻辑层穷举（HF-5）补四类识别信号：多入口防护不一致、状态机中间态被当终态（准则二反向应用于目标系统）、长效凭证签发强度弱于短效凭证、委托身份断言校验缺陷（挂准则三）；协作范式新增「触发器只给判据、不给案例」写法规范，约束此后新增识别类规则不得写成案例清单（已验证的具体历史模式/CVE 引用例外，那是证据溯源规范）|
| v4.0-1 | 2026-07-17 | **工程化重构·第一阶段(证据驱动地基)**:清理所有一次性目标产物;新增 engine/http_client(curl优先+python兜底,发包自动存证)、engine/evidence(无真实证据不许confirmed);新增 knowledge/ 指纹库+4样板playbook;新增 AGENT.md 作为AI全自动执行唯一入口,取代"粘贴L2";L1/L2/L3 保留为人读方法论事实源 |
| v4.0-2 | 2026-07-17 | **第二阶段(能力补全)**:engine/recon(指纹识别→自动指向该加载的playbook,pyyaml优先内置解析兜底)、engine/js_harvester(JS全量拉取+接口/密钥/路由提取);回填 shiro/spring-security/kong-gateway,指纹引用零悬空(10指纹/7playbook) |
| v4.0-3 | 2026-07-17 | **第三阶段(复利飞轮)**:engine/reflow(自动回灌新指纹/新check进knowledge,只增不删+去重+格式统一);闭环验证——回灌新指纹后 recon 可自动识别;AGENT.md/README 纳入 recon/js_harvester/reflow |
| v5.0 | 2026-07-17 | **三维架构重构**:knowledge 按三打法域(infra/framework/application)重组,指纹加 tag 分诊字段;framework 域 playbook 补确定性攻击链 chains(SpEL/Spring4Shell/log4j2/FastJSON/Actuator→Nacos→DB);新增 engine/intel(情报库,共享供料+跨域产物流动,漏洞穿成链)、engine/waf(WAF横切:识别+绕过手法);新增 knowledge/waf、payloads、wordlists 资产;recon 改为按 tag 分诊到三域并写 intel;reflow 扩展为分层回灌(fingerprint/check/waf/payload);AGENT.md 重写为三维架构+Q1-Q5三档内核(反射档/建模档/纠偏档,建模投入与不确定性成正比) |
| v5.1 | 2026-07-17 | **架构审计修复(P0/P1)**:①S1/M10 新增 engine/run.py 编排器(init 自动串 waf+recon+写intel,status 给态势+下一步建议,固化流程骨架不再靠AI自觉拼);②S2/M8 产物自动流动(js_harvester/recon/waf 产出自动写 intel,不再手工搬运);③M7 evidence report 聚合 findings+intel(两套存储打通);④O3 recon 改为纯读 yaml 的 match 字段(删硬编码 keywords,reflow 回灌带 match 即可被识别,飞轮不断);⑤O5 Q1-Q5 三档给落地载体(intel model 写建模产物,run.py status 检查 application 域是否已建模) |
| v5.2 | 2026-07-21 | **下限守门层(骨架承重墙)**:确立"价值密度驱动、只守下限不设上限"的骨架宪法(docs/ARCH-DECISIONS.md);新增 engine/floor_guard(读态势→对照 knowledge/floor.yaml→出缺口清单+三态裁决:未达标禁判走不通/达标有价值可收敛/达标无价值才允许判走不通)、knowledge/floor.yaml(声明式下限:覆盖下限+榨干下限,加下限追加一条即可);intel 加 consumed 标记 + consume 命令(榨干下限判定);run.py status/next 挂"⑧ 下限体检";新增 engine/tests 单元测试守护承重墙语义;清理历史演进痕迹注解与死代码 |

## 一句话

老范式:人当导演,AI 当知识源,靠人逐条审计。
新范式(v4.0):AI 全自动执行,**用证据说话**——发包必存证、确认必挂真实证据、
思路必显式,人从执行链和证据一眼审出跑偏。沉淀进 knowledge/,越用越聚焦。
