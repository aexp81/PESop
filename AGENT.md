# AGENT.md · PESop 全自动执行框架（AI 唯一入口）

> 你（AI）拿到一个授权目标后,读这一个文件就开工。不需要通读 L1/L2/L3。
> L1/L2/L3 是给人的方法论事实源;本文件是给你的可执行工程契约。
> 仅用于**授权范围内**的安全评估。

---

## 0. 这套工程和老 SOP 的关系

- 老的 `L1/L2/L3.md` = 给人读的方法论（为什么这么做）。你不必全文吃。
- `engine/` = 你的手（发包+存证+指纹+JS挖掘+回灌）。**所有发包必须走 engine,不许你口述响应。**
- `knowledge/` = 你的记忆（指纹库+playbook）。**按需精准调取,不通读。**
- `runs/<target>/` = 本次测试的一切产物（证据、发现台账、报告）。

一句话范式:**用执行结果说话,不用文字声称。** 你没真发过的请求,不许写进结论。

---

## 1. 铁律（违反即本次测试作废）

1. **发包必走 engine,证据即落盘。**
   任何一次 HTTP 请求都用 `python engine/http_client.py ...` 发,它会自动把
   raw 请求+响应存成一条证据并回一个 `evidence_id`。禁止用你自己脑内的"我
   访问了 X,返回 Y"当证据。

2. **确认漏洞必须挂真实 evidence_id。**
   登记发现用 `python engine/evidence.py add ...`。声明 `--status confirmed`
   时必须挂真实存在的 `evidence_id`,否则会被工具**自动降级为 suspected**。
   这不是建议,是工具强制。谎报在这里物理上做不到。

3. **状态只有四种,终态只有两个:**
   `unknown -> suspected -> confirmed(带证据) / disproved(带证据)`
   suspected 是库存,不是成果。收工前每个 suspected 要么推成 confirmed,
   要么推成 disproved,要么明确写清"为何停在 suspected"。

4. **思路必须显式化(给人审计用)。**
   每进入一个新系统 / 遇到防御信号(403/401/限流),先把 Q1-Q5 写出来再动手
   (见第 3 节)。人是靠看你的推理和证据来发现你有没有跑偏的,思路不写出来=
   剥夺了审计,等于回到"自问自答空转"。

5. **深度优先,别广度平摊。**
   发现一个高价值点(能控设备/关键写/无鉴权写/支付/越权),立刻用 engine 钻到
   终态,而不是回去把所有子域、所有 JS 先铺完。宁可 P0 打穿 3 个,不要 30 个
   各打一层皮。

---

## 2. 标准作业流程（SOP loop）

```
0 授权确认   复述目标边界与禁区(不在授权内的不碰)
1 侦察指纹   engine/recon.py 发探测包 -> 匹配 knowledge/fingerprints.yaml
2 加载记忆   命中指纹 -> 读对应 knowledge/playbooks/<id>.yaml(只读命中的,不全读)
3 建模       Q1-Q5 + 开发者共情:这是什么系统/怎么建的/最可能哪坏(写出来)
4 挖接口     engine/js_harvester.py 挖 JS(或APK) + 路径探测/文档 -> 接口清单
5 分诊       接口按 危害×可利用性 分 P0/P1/P2,火力集中 P0
6 深钻       对 P0 用 engine/http_client 打到终态:每步发包->存证->判定->记 finding
7 越权/业务  多账号交叉、状态机、业务不变量(见 knowledge + L2 HF-4/HF-5)
8 收尾       evidence.py summary 出汇总 -> 写报告 -> reflow.py 回灌新知识(第 5 节)
```

不要求你把 0-8 每步都铺满再往下。允许在第 4 步发现一个 P0 就直接跳到第 6 步
钻穿它,回头再补广度——这正是"深度优先"。

---

## 3. Q1-Q5（进新系统 / 遇防御信号 前必写）

- **Q1 这是什么系统?** 定位它在栈里哪一层(WAF/网关/框架/中间件),据 fingerprints.yaml。
- **Q2 我若是开发者会怎么建?** 技术选型+业务链+敏感点+最容易漏防护的地方。
- **Q3 最可能哪里失效?** 由 Q1+Q2 推 3-5 个针对性假设(不许答"因为清单上有")。
- **Q4 怎么验?** 变量隔离:控制组(已知通过的请求)->只改一个变量->发包看变化。
- **Q5 响应说明什么?** 每个响应(含 403/401)都是信号。假设被证伪≠系统安全,
  是你的模型要修正。切维度继续:路径不通切 CT,CT 不通切方法,方法不通切协议。

---

## 4. engine 用法速查

发包+存证（一切请求的地基）:
```
python engine/http_client.py --target https://t.com GET /api/user \
    -H "Authorization: Bearer xxx" --note "越权:B账号token读A资源"
# 返回 evidence_id / status_code / evidence_path / raw_response_preview
# 后端默认 auto(curl优先,失败自动降级python);可 --backend curl|python 强制
```

指纹识别 + 攻击面切换（SOP loop 第1-2步自动化）:
```
python engine/recon.py --target https://t.com
# 发探测包 -> 匹配 fingerprints.yaml -> 输出命中身份 + 该加载哪个 playbook
# 命中即读对应 knowledge/playbooks/<id>.yaml,不要通读全部 playbook
```

JS 全量拉取 + 接口/密钥提取（SOP loop 第4步,对应 HF-2）:
```
python engine/js_harvester.py --target https://t.com --max-js 100
# 拉HTML->下全部JS->挖 api路径/调用点/硬编码密钥/内部域名
# 产物 runs/<target>/js_assets.json;跳过的文件会显式标"跳过+理由+但未验证"
```

登记发现（确认必须挂真实 evidence_id）:
```
python engine/evidence.py add --target https://t.com \
    --title "IDOR:订单越权读取" --severity high --status confirmed \
    --evidence ev-xxx --evidence ev-yyy \
    --hypothesis "普通用户可读他人订单" --impact "可批量枚举全站订单"
```

查看/汇总:
```
python engine/evidence.py list    --target https://t.com
python engine/evidence.py summary --target https://t.com
```

回灌新知识（收尾做,让下次更强,见第5节）:
```
python engine/reflow.py fingerprint --id <新指纹> --layer <层> \
    --signal "<信号>" --identity "<身份>" --confidence high --playbook <id>
python engine/reflow.py check --playbook <id> --check-id <新check> \
    --why "<为什么测>" --how "<怎么发>" --signal "<什么算命中>"
python engine/reflow.py suggest --target https://t.com   # 从产物找可回灌线索
```

严重度: info/low/medium/high/critical。评级按**真实可利用性**,拿不准就降级
标 suspected,不许为显高危拔高。

---

## 5. 收尾回灌（让工程越用越强 —— 这是复利关键）

每次测试结束,你必须做两件让下次更强的事:

1. **写报告**到 `runs/<target>/report.md`(基于 evidence.py summary + 各 finding)。
2. **回灌新知识**到 knowledge/(用 `engine/reflow.py`,它保证只增不删+去重+格式统一):
   - 遇到 fingerprints.yaml 没有的指纹信号 -> `reflow.py fingerprint ...` 追加。
   - 某产品/框架跑出 playbook 没写的有效 check -> `reflow.py check ...` 追加,
     playbook 不存在时会自动新建。
   - 拿不准有没有可回灌的 -> `reflow.py suggest --target ...` 从产物找线索。
   - **只回灌"可复用的判据/手法",不回灌"这个目标的具体数据"**(具体数据留 runs/)。

这样沉淀增长的是 knowledge/ 里可精准调取的条目,而不是让你下次要通读的长文。
回灌进去的新指纹,下次 recon.py 就能自动识别——这就是越用越强的复利飞轮。

---

## 6. 你要避免的五种失效(人会盯这几点看你)

| 失效 | 表现 | 本工程如何治 |
|------|------|-------------|
| F1 半成品当交付 | 铺得好看、填满表、没钻到底 | 铁律5 深度优先 + 终态才算完 |
| F2 谎报 | 声称确认但没真证据 | evidence.py 强制挂真实 evidence_id |
| F3 漏假设 | 等人喂、套固定清单 | Q1-Q5 从攻击面穷举 + playbook 按需扩展 |
| F4 评级偏差 | 为显高危拔高 | 按真实可利用性,拿不准降级 |
| F5 用例脱离语义 | 通用 payload 硬套 | 每条 payload 回答"为什么对它用这条" |

> 人不看你填了多少表,人看你的 Q1-Q5 推理链、你每个结论挂的 evidence_id、
> 以及你有没有把 P0 真的钻穿。思路和证据经不起看,再漂亮的结构也是空的。
