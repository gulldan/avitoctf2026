#!/usr/bin/env python3
"""Scan text for payloads encoded with invisible Unicode codepoints."""

import os
import sys

# ---- codepoint classifiers -------------------------------------------------


def is_vs(cp):
    return 0xFE00 <= cp <= 0xFE0F or 0xE0100 <= cp <= 0xE01EF


def vs_byte(cp):
    if 0xFE00 <= cp <= 0xFE0F:
        return cp - 0xFE00
    return cp - 0xE0100 + 16


def is_tag(cp):
    return 0xE0000 <= cp <= 0xE007F


# "invisible / suspicious" codepoints worth flagging generically
def is_invisible(cp):
    if is_vs(cp) or is_tag(cp):
        return True
    if cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD):
        return True
    if 0x2000 <= cp <= 0x200F:  # spaces + bidi marks (skip normal space handled below)
        return True
    if 0x202A <= cp <= 0x202E:  # bidi embeddings/overrides
        return True
    return 0x2066 <= cp <= 0x2069  # bidi isolates


# ---- decoders --------------------------------------------------------------


def decode_vs_run(cps):
    """cps: list of codepoints (all variation selectors). -> decoded str or None"""
    try:
        b = bytes(vs_byte(c) for c in cps)
        return b.decode("utf-8")
    except Exception:
        try:
            return bytes(vs_byte(c) for c in cps).decode("latin-1")
        except Exception:
            return None


def decode_tag_run(cps):
    try:
        b = bytes((c - 0xE0000) for c in cps if (c - 0xE0000) <= 0xFF)
        return b.decode("utf-8")
    except Exception:
        return None


def decode_zw_run(cps):
    """Zero-width binary. Map 200B/2060->0, 200C/200D->1 (try both polarities)."""
    results = []
    for zero, one in ((0x200B, 0x200C), (0x200C, 0x200B), (0x200B, 0x200D)):
        bits = []
        for c in cps:
            if c == zero:
                bits.append("0")
            elif c == one:
                bits.append("1")
        if len(bits) >= 8:
            byts = bytearray()
            for i in range(0, len(bits) - len(bits) % 8, 8):
                byts.append(int("".join(bits[i : i + 8]), 2))
            try:
                s = bytes(byts).decode("utf-8")
                if s and all(0x20 <= ord(ch) <= 0x7E or ch in "\n\t" for ch in s):
                    results.append(s)
            except Exception:
                pass
    return results[0] if results else None


# ---- core scan -------------------------------------------------------------


def scan_text(text, label, findings):
    """Walk text, find runs of invisible codepoints, decode, append to findings."""
    n = len(text)
    i = 0
    while i < n:
        cp = ord(text[i])
        if is_vs(cp):
            j = i
            run = []
            while j < n and is_vs(ord(text[j])):
                run.append(ord(text[j]))
                j += 1
            dec = decode_vs_run(run)
            findings.append((label, i, "variation-selector", len(run), dec))
            i = j
        elif is_tag(cp):
            j = i
            run = []
            while j < n and is_tag(ord(text[j])):
                run.append(ord(text[j]))
                j += 1
            dec = decode_tag_run(run)
            findings.append((label, i, "tag-chars", len(run), dec))
            i = j
        elif cp in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF):
            j = i
            run = []
            while j < n and ord(text[j]) in (0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF):
                run.append(ord(text[j]))
                j += 1
            if len(run) >= 8:
                dec = decode_zw_run(run)
                findings.append((label, i, "zero-width", len(run), dec))
            i = j
        elif is_invisible(cp):
            j = i
            run = []
            while (
                j < n
                and is_invisible(ord(text[j]))
                and not is_vs(ord(text[j]))
                and not is_tag(ord(text[j]))
            ):
                run.append(ord(text[j]))
                j += 1
            if len(run) >= 4:
                names = ",".join(hex(c) for c in run[:8])
                findings.append((label, i, "misc-invisible", len(run), names))
            i = j
        else:
            i += 1
    return findings


TEXT_EXTS = {
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".go",
    ".py",
    ".rb",
    ".html",
    ".htm",
    ".css",
    ".scss",
    ".md",
    ".markdown",
    ".json",
    ".txt",
    ".conf",
    ".cfg",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".env",
    ".sh",
    ".sql",
    ".xml",
    ".svg",
    ".rs",
    ".java",
    ".c",
    ".h",
    ".cpp",
    ".php",
    ".vue",
    ".svelte",
    ".graphql",
    ".proto",
    ".lock",
    ".log",
    ".csv",
    ".tf",
    ".dockerfile",
    ".properties",
    ".gradle",
    ".kt",
    ".swift",
}

SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "env",
    ".ruff_cache",
    "__pycache__",
    ".next",
    "dist",
    "build",
    ".cache",
    "vendor",
    "site-packages",
    "dist-packages",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    "egg-info",
}


def looks_readable(s):
    """Heuristic: decoded string is human-meaningful (URL/message), not junk."""
    if not s or len(s) < 3:
        return False
    printable = sum(1 for ch in s if 0x20 <= ord(ch) <= 0x7E or ord(ch) > 0x2000)
    return printable / len(s) >= 0.8


def iter_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            ext = os.path.splitext(fn)[1].lower()
            base = fn.lower()
            if ext in TEXT_EXTS or "dockerfile" in base or base in ("makefile", "readme"):
                yield os.path.join(dirpath, fn)


def scan_repo(root):
    findings = []
    scanned = 0
    for path in iter_files(root):
        try:
            with open(path, encoding="utf-8", errors="strict") as f:
                text = f.read()
        except Exception:
            continue
        scanned += 1
        # quick reject: only scan if any invisible cp present
        if not any(is_invisible(ord(ch)) for ch in text):
            continue
        scan_text(text, path, findings)
        scan_interleaved(text, path, findings)
    return findings, scanned


def scan_interleaved(text, label, findings):
    """Some tools put ONE selector per visible char. Gather the whole-file
    ordered stream of VS / tag chars and try to decode it as one payload.
    """
    vs = [ord(ch) for ch in text if is_vs(ord(ch))]
    tg = [ord(ch) for ch in text if is_tag(ord(ch))]
    if len(vs) >= 6:
        dec = decode_vs_run(vs)
        already_reported = any(
            found_label == label and found_dec == dec
            for found_label, _, _, _, found_dec in findings
        )
        if dec and looks_readable(dec) and not already_reported:
            findings.append((label, -1, "vs-whole-file", len(vs), dec))
    if len(tg) >= 6:
        dec = decode_tag_run([c for c in tg if c != 0xE007F])
        already_reported = any(
            found_label == label and found_dec == dec
            for found_label, _, _, _, found_dec in findings
        )
        if dec and looks_readable(dec) and not already_reported:
            findings.append((label, -1, "tag-whole-file", len(tg), dec))


def fetch(url):
    try:
        import urllib.request

        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 meme-scan"})
        with urllib.request.urlopen(req, timeout=20) as r:
            raw = r.read()
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def main():
    args = sys.argv[1:]
    if "--stdin" in args:
        text = sys.stdin.read()
        findings = []
        scan_text(text, "<stdin>", findings)
        print_findings(findings)
        return
    urls_file = None
    root = "."
    i = 0
    while i < len(args):
        if args[i] == "--urls":
            urls_file = args[i + 1]
            i += 2
        else:
            root = args[i]
            i += 1

    findings, scanned = scan_repo(root)
    print(f"# scanned {scanned} text files under {os.path.abspath(root)}")
    print_findings(findings)

    if urls_file:
        with open(urls_file) as f:
            urls = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        for url in urls:
            text = fetch(url)
            if text is None:
                print(f"# FETCH FAIL {url}")
                continue
            uf = []
            scan_text(text, url, uf)
            print(f"# fetched {url} ({len(text)} chars)")
            print_findings(uf)


def print_findings(findings, show_all=False):
    seen = set()
    for label, off, scheme, runlen, dec in findings:
        # noise filter: single variation selector = legit emoji VS-16; skip
        interesting = False
        if scheme in ("variation-selector", "tag-chars", "vs-whole-file", "tag-whole-file"):
            interesting = runlen >= 2 and (dec is None or looks_readable(dec))
        elif scheme == "zero-width":
            interesting = dec is not None and looks_readable(dec)
        elif scheme == "misc-invisible":
            interesting = runlen >= 6
        if not (interesting or show_all):
            continue
        key = (scheme, dec)
        dedup = "" if key not in seen else "  [dup]"
        seen.add(key)
        d = repr(dec) if dec is not None else "<undecodable>"
        print(f"{label}:{off}\t[{scheme} n={runlen}]\t{d}{dedup}")


if __name__ == "__main__":
    main()
