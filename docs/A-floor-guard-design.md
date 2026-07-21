# A 阶段：下限守门层（floor guard）骨架设计

> 承接 `ARCH-DECISIONS.md`（B 阶段）。本文件定"怎么搭"，仍只定骨架与扩展点，不铺无关实现细节。
> 三点已确认：①下限定义走 `knowledge/floor.yaml`（可配置）②intel 条目加 `consumed` 标记 ③复用 `run.py status/next`，不新增命令。
> 状态：v0.1 骨架设计。

---

## 0. 一句话目标

新增一个**只读态势、只输出缺口清单**的守门层：读 `intel + findings` → 对照 `floor.yaml` 定义的下限 → 回答"能不能判走不通/收工"。**守下限、不设上限、决策权归 AI。**

---

## 1. 涉及文件（最小改动面）

| 文件 | 动作 | 责任 |
| --- | --- | --- |
| `knowledge/floor.yaml` | **新建** | 下限检查项定义（唯一扩展点，加下限=改这里） |
| `engine/floor_guard.py` | **新建** | 守门函数：读态势→算缺口→出清单。不发包、不决策 |
| `engine/intel.py` | **微改** | 列表条目加 `consumed` 标记 + 一个 `consume()` 标记函数 |
| `engine/run.py` | **微改** | `status/next` 输出里挂上守门结果（复用出口，不加命令） |

> 原生骨架（http_client / evidence / recon / waf / reflow）**零改动**。符合原则二。

---

## 2. 扩展点：`knowledge/floor.yaml`（决策一落地）

下限做成**声明式检查项清单**。每条检查项声明"查什么、达标条件、缺口话术"，守门函数只当解释器。**加新下限 = append 一条，代码不动。**

```yaml
# PESop 下限定义 —— 守门层只读此文件,不硬编码下限
# 只增不删,reflow 可回灌。engine 只解释,不判断该不该守。
#
# check 支持的原子类型(守门函数内置解释器,新增类型才需动代码):
#   fingerprint_tag_covered  某 tag 域是否有指纹命中且已处理
#   modeling_done            application 域是否已填 Q1-Q5
#   endpoints_all_consumed   intel.endpoints 是否都已 consumed
#   intel_field_no_dangling  某 intel 列表字段有无"拿到却没用"(consumed=false)的悬挂项
#
# 每条: id / group(coverage|drain) / check / args / gap_hint(缺口话术,给AI看)

floor_checks:

  # ===== A 组·覆盖下限(coverage)=====
  - id: cover-framework
    group: coverage
    check: fingerprint_tag_covered
    args: {tag: framework}
    gap_hint: "framework 域有指纹命中但未展开攻击链 → 读 domains/framework/ playbook 打完再判走不通"

  - id: cover-infra
    group: coverage
    check: fingerprint_tag_covered
    args: {tag: infra}
    gap_hint: "infra 域有中间件指纹但未打未授权 → 读 domains/infra/ 打完再判走不通"

  - id: cover-application-modeled
    group: coverage
    check: modeling_done
    args: {}
    gap_hint: "有接口/application指纹但未建模 → 先 intel.py model 填 Q1-Q5(建模档硬要求)"

  - id: cover-endpoints
    group: coverage
    check: endpoints_all_consumed
    args: {}
    gap_hint: "intel.endpoints 里还有接口没验证(consumed=false) → 逐个验证完再判走不通"

  # ===== B 组·榨干下限(drain)=====
  - id: drain-secrets
    group: drain
    check: intel_field_no_dangling
    args: {field: secrets}
    gap_hint: "有密钥/凭证拿到却没用(consumed=false) → 检查能否喂给其它域(OSS-AK打对象存储/DB串连库)再判走不通"

  - id: drain-hosts
    group: drain
    check: intel_field_no_dangling
    args: {field: hosts}
    gap_hint: "有内网IP/域名拿到却没打 → 顺着打完再判走不通"
```

**扩展方式**：
- 加新下限（如"WebSocket 层要覆盖"）→ append 一条，若能复用现有 4 个原子 check 类型则**零代码**。
- 只有当需要一种全新的判断逻辑（现有 4 类都表达不了）时，才在 `floor_guard.py` 里加一个原子 check 实现——这是唯一的代码扩展点，且频率极低。

---

## 3. `engine/intel.py` 微改：`consumed` 标记（决策二落地 / 榨干下限的前提）

### 3.1 数据结构：列表条目加可选 `consumed`
`secrets/hosts/endpoints` 每个 dict 条目可带：
```json
{"name": "OSS_AK", "value": "LTAI...", "source": "heapdump",
 "consumed": false, "consumed_by": null, "consumed_at": null}
```
- 不写 `consumed` 视为 `false`（向后兼容，老数据不炸）。
- `add()` 追加新条目时，若未显式给 `consumed`，默认补 `false`（只加这一行默认值，不改去重逻辑）。

### 3.2 新增一个标记函数（约 10 行）
```
consume(target, field, match_value, by) -> {ok, consumed}
  # 把 field 列表里 (name/value/path 命中 match_value) 的条目标记
  # consumed=true / consumed_by=by / consumed_at=now。找不到返回 ok:False。
```
- AI 用完一条情报后调它，如：`intel.py consume --field secrets --match OSS_AK --by "打通对象存储"`。
- CLI 加一个 `consume` 子命令（与现有 add/set/model 平级，不动它们）。

> 为何要这个：没有 `consumed`，"榨干下限"无法机器判定"信息拿到却没用"。这是把 2.1 节"榨干下限"落地的唯一新增字段——**轻量、向后兼容、不造新概念**。

---

## 4. `engine/floor_guard.py`：守门函数（骨架核心，决策一/二）

**只做三件事：读态势 → 跑 floor.yaml 里的检查 → 出结论。不发包、不决策、不下指令。**

### 4.1 对外主函数
```
assess(target) -> {
    "value_reached": bool,        # findings 里有无 confirmed 且 severity>=medium
    "floor_satisfied": bool,      # 所有 floor_checks 是否都达标
    "gaps": [ {id, group, gap_hint}, ... ],   # 未达标项的缺口清单(给AI)
    "verdict": str,               # 见下 4.3
}
```

### 4.2 内部结构
- `_load_floor()`：读 `knowledge/floor.yaml`（pyyaml 优先，无则复用 recon 已有的极简解析兜底思路；读失败不阻断，返回空清单 + 一条 note）。
- `_value_reached(target)`：读 `evidence.summary` → findings 里存在 `status==confirmed and severity in {medium,high,critical}` 即 True。
- `_run_check(check, args, isum, idata, fsum)`：**4 个原子 check 的解释器**（switch），对应 floor.yaml 里的 check 类型：
  - `fingerprint_tag_covered`：intel 有该 tag 指纹 → 是否已被处理（简化：v0.1 先看"有该 tag 指纹但该域无对应 confirmed/disproved finding"→ 视为未覆盖）。
  - `modeling_done`：读 `intel.summary.modeling_done`；仅当"有接口或 application 指纹"时才要求（无 application 面则此项 N/A 视为达标）。
  - `endpoints_all_consumed`：intel.endpoints 全部 `consumed==true` 即达标。
  - `intel_field_no_dangling`：intel[field] 无 `consumed==false` 项即达标。
- `assess()`：跑全部 check → 收集未达标项的 `gap_hint` → 组装返回。

### 4.3 verdict 的三态（守门员开口的唯一话术）
```
if not floor_satisfied:
    verdict = "禁止判走不通 —— 下限未达标,还差以下缺口(补齐或说明N/A后再收敛)"
elif value_reached:
    verdict = "下限已达标 且 已有中危+价值产出 → 可收敛;是否继续发散深挖由你定(不设上限)"
else:
    verdict = "下限已达标 但 未挖到中危+价值 → 现在才允许判'走不通',发散/变思路由你定"
```
对照 `ARCH-DECISIONS.md` 2.1 节：**"走不通" = value_reached=False 且 floor_satisfied=True**，正是第三条 verdict。守门员**只陈述缺口和裁决，从不下达"去打什么"的指令**（决策二红线）。

---

## 5. `engine/run.py` 微改：挂进现有出口（决策三，不新增命令）

在 `_next_advice` 末尾追加一段，把守门结果并入现有建议流（`status` 因内联 `_next_advice`，自动带上）：

```python
# —— 下限守门(A阶段):只读态势给缺口清单,不决策 ——
try:
    import floor_guard as _fg          # 与其它 engine 模块同样的 sys.path 导入方式
    fa = _fg.assess(target)
    advice.append(f"⑧ 下限体检:{fa['verdict']}")
    for g in fa["gaps"]:
        advice.append(f"    ↳ 缺口[{g['group']}] {g['gap_hint']}")
except Exception as e:
    advice.append(f"⑧ 下限体检跳过(floor_guard 不可用:{e})")   # 不阻断主流程,与现有 intel 回写容错一致
```

- 沿用现有"try/except 不阻断"的容错风格（与 intel 回写一致）。
- 不加子命令、不改 `main()`：`status` 和 `next` 自动多出"⑧ 下限体检 + 缺口清单"。

---

## 6. 数据流闭环（A 阶段接完后）

```
AI 打完一轮 → 写 findings(价值) + 写 intel(信息, consumed 标记谁用过)
     ↓
run.py status/next → floor_guard.assess() 读 intel+findings 对照 floor.yaml
     ↓
下限未达标 → 输出缺口清单(禁止收工,防漏测) ──┐
下限达标+有价值 → 提示可收敛(不封顶)          ├→ AI 据此决定发散/深挖/变思路(上限空间)
下限达标+无价值 → 允许判"走不通"(触发变思路) ──┘
     ↓
AI 补缺口/发散 → 再写 findings/intel → 回到顶部(闭环)
```

这条闭环把 B 阶段图里"下限守门 ↔ 双引擎"的回路真正焊死，且新增代码集中在 1 个新文件 + 1 个配置 + 2 处微改。

---

## 7. 严守两原则的自检

| 检查 | 结论 |
| --- | --- |
| 过度设计? | 守门只读态势+查清单，不发包/不决策/不生成假设。新增面=1文件+1yaml+2微改。✅ |
| 扩展性? | 下限走 yaml，加下限多数零代码；原子 check 是唯一低频代码扩展点；原生骨架零改动。✅ |
| 边界红线(B-6)? | 不替 AI 判走不通(只给裁决供 AI 用)、不生成假设、不设上限、不改原生骨架、只出缺口不下指令。5 条全守。✅ |

---

## 8. 落地节奏建议（先窄后宽）

1. **先做榨干下限 + consumed**（`drain-*` 两条 + intel.consume）——它最能立刻体现"信息别浪费"，且不依赖复杂的域覆盖判定。
2. **再做覆盖下限**（`cover-*` 四条）——其中 `fingerprint_tag_covered` 的"是否已覆盖"判定 v0.1 先用简化规则（有指纹无对应 finding=未覆盖），后续按实战校准。
3. **最后接 run.py 出口 + 补最小单元测试**（mock intel/findings，验证 verdict 三态与缺口清单）——给守门逻辑上 CI 护栏（呼应首轮审计的"无测试"短板）。

> 每步都是独立可验证的小闭环，符合"先窄后宽、避免一上来铺太大"。
