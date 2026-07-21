# B 阶段设计：JS 全量提取重构（静态为主 + 浏览器可选增强 + sourcemap 还原）

> 承接 docs/ARCH-DECISIONS.md。解决"js_harvester 只抓 HTML 里的 <script>,漏掉
> webpack/vite 分包 chunk、SPA 懒加载路由、sourcemap"的地基缺陷。
> 路线已定(用户确认):**3 = 静态为主 + 浏览器可选增强 + sourcemap 还原**。
> 状态:v0.1 骨架设计。

---

## 0. 目标与原则对齐

**目标**:把"JS 提取"从"只抓入口 <script>"升级为"尽可能拿到应用的全部 JS 代码",
再在全量 JS 上做接口/密钥/路由提取。

**两条原则怎么守**:
- **避免过度设计**:默认走**纯静态**(零依赖,发包+正则/解析),保证到哪都能跑;浏览器增强
  是**可选后端**,环境有浏览器才用,没有就降级静态,不强迫。
- **极强扩展性**:打包工具的识别与 chunk 提取规则做成**可扩展规则库**(knowledge/js/),
  加一种打包工具 = 加一条规则,不改代码;浏览器后端做成**可插拔**,不侵入静态主干。

---

## 1. 分层设计（三级递进,能力可插拔）

JS 发现分三级,从"零依赖必做"到"有环境才做",逐级增强覆盖面:

```
L0 入口层(现有,保留)      HTML 里的 <script src> + 内联 <script>
        ↓ 拿到 entry JS
L1 静态分包层(新增,零依赖) 识别打包工具 → 按规则抠出 chunk 映射 → 递归拼 URL 下载全部 chunk
        ↓ 每个 JS 若有 sourceMappingURL
L1.5 sourcemap 还原(新增)  下载 .js.map → 解出 sourcesContent 原始源码 → 在源码上做提取(信息最全)
        ↓ 静态抓不全时(动态 chunk 名/运行时计算)
L2 浏览器增强层(新增,可选) headless 浏览器真实加载 → 捕获实际请求的所有 JS → 补静态的盲区
```

**关键**:L0/L1/L1.5 是**零依赖主干**(默认执行);L2 是**可选后端**(检测到浏览器可用才跑,
否则跳过并在产物里标注"未做浏览器增强,动态 chunk 可能漏")。

---

## 2. 涉及文件

| 文件 | 动作 | 责任 |
| --- | --- | --- |
| `knowledge/js/bundlers.yaml` | **新建** | 打包工具指纹 + chunk 提取规则(可扩展规则库) |
| `engine/js_harvester.py` | **重构** | 主干:L0→L1→L1.5;调度可选 L2;提取逻辑复用 |
| `engine/js_browser.py` | **新建** | L2 浏览器增强后端(可选,独立文件,主干不 import 失败也不影响) |
| `engine/reflow.py` | **微改** | 新增 `bundler` 回灌(把实战遇到的新打包工具规则 append 进 bundlers.yaml) |
| `engine/tests/test_js_harvester.py` | **新建** | 单测:分包规则解析/sourcemap 解析/后端降级 |

> 原生地基(http_client/intel/evidence)零改动。js_harvester 产物结构向后兼容(旧字段保留)。

---

## 3. 扩展点:`knowledge/js/bundlers.yaml`（打包工具规则库）

仿 fingerprints.yaml 的"声明式 + 可回灌"设计。每条描述一种打包工具:怎么识别它、
怎么从它的 entry JS 里抠出所有 chunk。

```yaml
# 打包工具识别 + chunk 提取规则。加一种打包工具追加一条即可,js_harvester 只解释。
# 只增不删,reflow bundler 回灌。
#
# 字段:
#   id          打包工具标识
#   detect      识别信号(在 HTML 或 entry JS 里的子串,命中任一即认定)
#   chunk_rule  如何拼 chunk URL 的规则类型(见 js_harvester 内置的规则解释器)
#   patterns    该规则需要的正则(抠 chunkId→filename 映射 / publicPath 等)
#   note        人读说明

bundlers:
  - id: webpack
    detect: ["webpackJsonp", "__webpack_require__", "webpackChunk"]
    chunk_rule: webpack_chunk_map
    patterns:
      # entry JS 里形如  {0:"chunk-abc",1:"chunk-def"}  的 chunkId→name 映射
      chunk_map: '\{(?:\d+:"[\w\-]+",?)+\}'
      # publicPath:  __webpack_require__.p="/static/js/"
      public_path: '\.p\s*=\s*["\']([^"\']+)["\']'
      # 文件名模板:  "static/js/" + chunkId + "." + {…}[chunkId] + ".js"
      filename_tpl: '["\']([\w\-/.]*?)["\']\s*\+.*?\+\s*["\']\.js["\']'
    note: "最常见;chunk 映射在 runtime/app.js 里"

  - id: vite
    detect: ["/assets/", "type=\"module\"", "__vite__", "import.meta"]
    chunk_rule: vite_modulepreload
    patterns:
      # vite 用 <link rel="modulepreload" href="/assets/xxx.js"> 声明依赖
      preload: '<link[^>]+rel=["\']modulepreload["\'][^>]+href=["\']([^"\']+)["\']'
      # 以及入口 module 里的 import "…/assets/xxx.js"
      import_stmt: 'import[^"\']*["\'](/assets/[^"\']+\.js)["\']'
    note: "vite 用 ES module + modulepreload 声明依赖,静态即可拿到大部分"

  # 后续实战遇到的 rollup/esbuild/requirejs 等,reflow bundler 追加
```

**扩展方式**:
- 加新打包工具 → append 一条;若能复用现有 `chunk_rule` 类型则零代码。
- 只有出现一种全新的 chunk 组织方式(现有 rule 类型表达不了)时,才在 js_harvester 加一个
  `chunk_rule` 解释器——低频代码扩展点。

---

## 4. `engine/js_harvester.py` 重构（主干逻辑）

### 4.1 主流程 harvest()
```
harvest(target, html_path="/", max_js=100, use_browser="auto"):
  1. L0  拉入口 HTML(现有)→ 抓 <script src> + 内联 → 得 entry_js_urls
  2. 识别打包工具:读 knowledge/js/bundlers.yaml,拿 HTML+entry JS 文本匹配 detect → bundler_id
  3. L1  按 bundler 的 chunk_rule 从 entry JS 抠出全部 chunk URL(递归:新下的 JS 可能再引 JS)
         → 汇入待下载队列(去重,受 max_js 限;超限显式标"跳过+未验证")
  4. 逐个下载所有 JS(entry + chunk),走 http_client 存证
  5. L1.5 对每个 JS 检查末尾 sourceMappingURL → 若有 .js.map 就下载 → 解出 sourcesContent
          → 在【还原后的源码】上做提取(优于压缩码)
  6. 在全部 JS(或其 sourcemap 源码)上跑接口/密钥/路由提取(现有 _extract_from_js 复用)
  7. L2  若 use_browser 且 js_browser 可用:调 js_browser.capture(target) 补动态 chunk
         → 把浏览器抓到、静态没抓到的 JS URL 补下载+提取(标注来源 browser)
         → 不可用则跳过,产物标注 browser_augment=false
  8. 汇总落盘 js_assets.json(结构向后兼容,新增字段见 4.3)+ 自动写 intel(现有)
```

### 4.2 chunk_rule 解释器(内置,对应 bundlers.yaml 的 chunk_rule)
- `webpack_chunk_map`:用 patterns 里的正则从 entry JS 抠 chunkId→name 映射 + publicPath +
  文件名模板 → 笛卡尔拼出所有 chunk URL。
- `vite_modulepreload`:抠 modulepreload/import 里的 /assets/*.js。
- 未知 chunk_rule → 跳过该规则,产物标注"未知 chunk_rule,该 bundler 分包未展开"(不崩)。

### 4.3 产物 js_assets.json 新增字段(向后兼容)
```json
{
  "bundler": "webpack",               // 识别到的打包工具(null=未识别)
  "js_files": [ { "url","source":"entry|chunk|browser","from_sourcemap":bool, ... } ],
  "sourcemaps": [ {"js_url","map_url","recovered_sources": N} ],
  "browser_augment": true,            // 是否跑了 L2
  "coverage_note": "静态展开 webpack chunk;浏览器增强已跑" ,
  "aggregate": { ...现有... }
}
```

---

## 5. `engine/js_browser.py`（L2 可选后端）

- **独立文件**,主干用 `try: import js_browser` 调用,import 失败/浏览器不可用都不影响 L0/L1。
- 优先用已装的 headless 方案(playwright / puppeteer via node / chromium --headless),
  探测顺序内置,任一可用即用;都没有则返回 `{"available": False}`。
- `capture(target, timeout)`:无头加载页面 → 监听网络 → 返回实际请求到的所有 `*.js` URL
  (+ 可选:自动点击/触发路由以诱发懒加载,v0.1 先只做被动捕获)。
- **发包一致性**:浏览器抓到的 JS URL 仍交回 js_harvester 用 http_client 下载存证(保证"发包必存证"
  铁律不被浏览器绕过);js_browser 只负责"发现 URL",不负责"取证"。

---

## 6. `reflow.py` 微改:`bundler` 回灌

`python engine/reflow.py bundler --id rollup --detect "..." --chunk-rule ... --pattern k=v ...`
把实战新遇到的打包工具规则 append 进 knowledge/js/bundlers.yaml(只增不删+去重,同 id 跳过)。
→ 下次 js_harvester 自动识别该打包工具 → 飞轮:JS 提取能力越用越全。

---

## 7. 严守原则自检

| 检查 | 结论 |
| --- | --- |
| 过度设计? | 主干零依赖(L0/L1/L1.5);浏览器是可选后端;规则外置。新增=1规则库+1可选后端+主干重构。✅ |
| 扩展性? | 打包工具走 yaml(加工具多零代码);chunk_rule/浏览器后端是可插拔扩展点;reflow bundler 闭环飞轮。✅ |
| 地基不破? | 所有 JS 下载仍走 http_client 存证(浏览器只发现不取证);intel/evidence 零改动。✅ |
| 边界红线? | 浏览器不绕过发包存证;静态抓不全会显式标注(不假装抓全,治 F3)。✅ |

---

## 8. 落地节奏（先窄后宽）

1. **L1 静态分包(webpack + vite)+ bundlers.yaml + 单测**——覆盖最主流的两类,先把"分包漏挖"这个
   最大的洞补上;webpack chunk 解析先支持最常见格式。
2. **L1.5 sourcemap 还原**——检测 sourceMappingURL → 下载 .js.map → 解 sourcesContent → 源码上提取。
3. **L2 浏览器增强(js_browser)+ 降级逻辑**——探测环境浏览器,被动捕获动态 JS;不可用则跳过标注。
4. **reflow bundler 回灌 + 文档更新**。

> 每步独立可验证。L1 做完就已经能解决你说的"webpack 分包漏挖"主要痛点;sourcemap 和浏览器是
> 逐级增强,不必一次到位。
