#!/usr/bin/env python3
"""Task12 «Undercover»: постоянный SSH-канал, удерживающий ОДИН эфемерный контейнер.

Зачем: на каждое SSH-подключение цель поднимает свежий Docker-контейнер, поэтому всю
цепочку privesc (cron→backupuser → SGID-mail → OTP-по-почте → root) нужно проходить в
ОДНОЙ живой сессии — иначе созданные файлы теряются между командами. Этот сервер
открывает интерактивный shell-канал `worker@target` один раз и держит его открытым,
исполняя команды из очереди по мере их появления.

Протокол очереди (файловый, чтобы гонять шаги из любого процесса):
    * следит за каталогом QDIR за файлами `NNN.cmd` (в порядке сортировки);
    * каждый исполняет в том же shell-канале, собирает вывод до персонального
      маркера-часового `__END_n__`, пишет `NNN.out`, переименовывает `NNN.cmd → NNN.done`;
    * завершается, когда появляется `QDIR/STOP` или по таймауту простоя.

Зависимость `paramiko` без стабов типов → на импорте стоит точечный `# ty: ignore`;
креды — это выданные условием задачи публичные CTF-креды (см. task.md).
"""

import glob
import os
import sys
import time

import paramiko

HOST = "undercover-zhvo8wkj.avitoctf.ru"
USER = "worker"
PASS = "ufqIDMVBm5MHPHg8dcVTcQ"
QDIR = sys.argv[1] if len(sys.argv) > 1 else "/tmp/q"

os.makedirs(QDIR, exist_ok=True)

cli = paramiko.SSHClient()
cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
cli.connect(
    HOST, port=22, username=USER, password=PASS, look_for_keys=False, allow_agent=False, timeout=30
)
chan = cli.invoke_shell(term="dumb", width=250, height=100)
chan.settimeout(0.3)
time.sleep(1.2)


def drain():
    b = b""
    try:
        while True:
            d = chan.recv(65536)
            if not d:
                break
            b += d
    except Exception:
        pass
    return b


drain()
chan.send("stty -echo 2>/dev/null; PS1=''; PS2=''; set +m\n")
time.sleep(0.4)
drain()

with open(os.path.join(QDIR, "SERVER_READY"), "w") as f:
    f.write(str(os.getpid()))

n = 0
idle = 0
while True:
    if os.path.exists(os.path.join(QDIR, "STOP")):
        break
    cmds = sorted(glob.glob(os.path.join(QDIR, "*.cmd")))
    if not cmds:
        idle += 1
        if idle > 4000:  # ~ generous idle timeout
            break
        time.sleep(0.05)
        continue
    idle = 0
    cf = cmds[0]
    base = cf[:-4]
    with open(cf) as f:
        script = f.read()
    sent = "__END_%d__" % n
    n += 1
    drain()
    chan.send(script + "\n")
    chan.send("printf '\\n%s %s\\n' " + sent + " $?\n")
    out = b""
    deadline = time.time() + 180
    while time.time() < deadline:
        try:
            d = chan.recv(65536)
            if not d:
                break
            out += d
            if sent.encode() in out:
                time.sleep(0.15)
                out += drain()
                break
        except Exception:
            time.sleep(0.05)
    text = out.decode(errors="replace")
    i = text.find(sent)
    if i != -1:
        text = text[:i]
    tmp = base + ".out.tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, base + ".out")
    os.replace(cf, base + ".done")

try:
    chan.close()
    cli.close()
except Exception:
    pass
