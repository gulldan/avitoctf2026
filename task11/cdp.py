#!/usr/bin/env python
import json
import threading
import time
import urllib.request

import websocket  # websocket-client  # ty: ignore[unresolved-import]

CDP_HTTP = "http://localhost:9222"


def http_get(path):
    return json.load(urllib.request.urlopen(CDP_HTTP + path))


class CDP:
    def __init__(self, ws_url):
        self.ws = websocket.create_connection(ws_url, max_size=None)
        self.id = 0
        self.lock = threading.Lock()
        self.pending = {}
        self.events = []
        self.session_events = []
        self.running = True
        self.t = threading.Thread(target=self._reader, daemon=True)
        self.t.start()

    def _reader(self):
        while self.running:
            try:
                msg = self.ws.recv()
            except Exception:
                break
            if not msg:
                continue
            try:
                data = json.loads(msg)
            except Exception:
                continue
            if "id" in data:
                with self.lock:
                    self.pending[data["id"]] = data
            else:
                self.events.append(data)

    def send(self, method, params=None, sessionId=None, timeout=15):
        with self.lock:
            self.id += 1
            mid = self.id
        payload = {"id": mid, "method": method, "params": params or {}}
        if sessionId:
            payload["sessionId"] = sessionId
        self.ws.send(json.dumps(payload))
        start = time.time()
        while time.time() - start < timeout:
            with self.lock:
                if mid in self.pending:
                    return self.pending.pop(mid)
            time.sleep(0.005)
        raise TimeoutError(f"{method} timed out")

    def drain_events(self):
        evs = self.events
        self.events = []
        return evs

    def close(self):
        self.running = False
        try:
            self.ws.close()
        except Exception:
            pass
