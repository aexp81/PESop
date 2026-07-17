# 人机协作渗透测试 SOP + 全自动执行工程

> 长期迭代资产。仅用于授权范围内的安全评估。
> 版本 v4.0 · 工程化重构：从「粘贴长 prompt 靠人审计」升级为
> 「证据驱动 + 按需调取知识 + 越用越强」的可执行工程。

## v4.0 做了什么（为什么改）

老版本是纯文档 SOP（L1/L2/L3），假设"人读 L1 建立判断力 + 人当导演逐条审计"。
实际用法是"把项目 down 下来、给个网址、让 AI 全自动跑",于是:
- 人不在回路 → 追问扳手/完成度自检退化成 **AI 自问自答、自己盖章**（谎报治不住）。
- 沉淀是散文 → AI 每次要通读全部,**沉淀越多越拖累**,与"越用越强"相反。

v4.0 针对性重构为工程,核心三招:

1. **证据驱动**:所有发包走 `engine/http_client.py`,自动落盘 raw 请求/响应;
   `engine/evidence.py` 强制"确认漏洞"必须挂真实 `evidence_id`,否则降级。
   谎报（F2）从"靠自觉"变成"物理做不到"。
2. **按需调取知识**:`engine/recon.py` 自动发探测包→匹配 `knowledge/` 指纹库→
   告知该加载哪个 playbook;`engine/js_harvester.py` 全量挖 JS 接口/密钥。
   AI 识别到什么才读什么,沉淀增长的是可精准检索的条目,**不是要通读的长文**。
3. **越用越强 + 深度优先**:`engine/reflow.py` 把新指纹/新手法自动回灌进 knowledge
   (只增不删,下次 recon 即可识别,飞轮闭环);`AGENT.md` 取代"粘 L2",强制显式
   Q1-Q5 推理 + 火力集中 P0,让人从"AI 的执行思路和产出"就能一眼审出问题。

## 目录结构

| 路径 | 作用 | 谁读 |
| --- | --- | --- |
| `AGENT.md` | **AI 唯一入口**:全自动执行契约(铁律/SOP loop/engine用法/回灌) | AI 每次读 |
| `engine/http_client.py` | 统一发包+自动存证(curl 优先,python 兜底) | AI 调用 |
| `engine/evidence.py` | 结构化证据台账(无真实证据不许 confirmed) | AI 调用 |
| `engine/recon.py` | 指纹识别:发探测包→匹配指纹库→告知该加载哪个 playbook | AI 调用 |
| `engine/js_harvester.py` | JS 全量拉取+接口/密钥/路由提取(对应 HF-2) | AI 调用 |
| `engine/reflow.py` | 自动回灌:把新指纹/新手法 append 进 knowledge(只增不删+去重) | AI 调用 |
| `knowledge/fingerprints.yaml` | 指纹信号 → 产品身份 → 触发哪个 playbook | AI 按需读 |
| `knowledge/playbooks/*.yaml` | 按身份的攻击手册(spring-boot/security/shiro/envoy/kong/oauth/竹云) | AI 命中才读 |
| `runs/<target>/` | 每次测试产物:证据/发现台账/报告(不进版本库) | AI 写,人看 |
| `L1-methodology.md` | 方法论事实源(为什么这么做),F1-F5/四准则的推导 | 人(审计时) |
| `L2-ai-prompt.md` | 老执行清单,现作 HF-1~7 细则参考,被 AGENT.md 引用 | 人/AI 查阅 |
| `L3-knowledge.md` | 历史经验散文库,新知识优先结构化进 knowledge/ | 人 |

## 怎么用（全自动模式）

1. 把项目 down 到你的持久化环境(能真发包)。
2. 给 AI 一个授权目标 + 让它读 `AGENT.md` 开工。
3. AI 按 SOP loop 跑,每步都有对应 engine 命令:
   ```
   侦察指纹   python engine/recon.py --target https://t.com
   加载playbook  读 recon 提示的 knowledge/playbooks/<id>.yaml
   建模       写出 Q1-Q5 + 开发者共情
   挖接口     python engine/js_harvester.py --target https://t.com
   深钻P0     python engine/http_client.py ...(每步发包自动存证)
   记发现     python engine/evidence.py add ...(确认必挂真实 evidence_id)
   收尾       python engine/evidence.py summary + 写报告 + engine/reflow.py 回灌
   ```
4. 你看 `runs/<target>/` 里的 Q1-Q5 推理、每个 finding 挂的 evidence_id、
   P0 是否钻穿——从执行思路和证据一眼审出跑偏。

## 迭代规则（复利飞轮,工程化版）

- **runs/ 留具体数据,knowledge/ 留可复用判据**:每次收尾用 `engine/reflow.py` 把新
  指纹/新手法 append 到 knowledge/(工具保证只增不删+去重+格式统一),目标专属数据留 runs/。
- **飞轮已闭环**:reflow 回灌的新指纹,下次 `engine/recon.py` 就能自动识别——
  沉淀越多,AI 单次任务反而越聚焦(按需调取,不通读)。
- knowledge/ 里反复命中、验证稳定的模式,再提炼进 L1/L2(人做,打版本号)。
- engine/ 保持零第三方依赖(pyyaml 可选,无则内置解析兜底),持久化环境到哪都能跑。

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

## 一句话

老范式:人当导演,AI 当知识源,靠人逐条审计。
新范式(v4.0):AI 全自动执行,**用证据说话**——发包必存证、确认必挂真实证据、
思路必显式,人从执行链和证据一眼审出跑偏。沉淀进 knowledge/,越用越聚焦。
