"""Lighter Nuna APK forensic dump: just APK+DEX (no full call-graph analysis).

Goals, in order:
  1. List every BLE-related class in `com.xthings.nuna` / `com.things.common.ble`.
  2. Dump the source of MessageBodyCreator (the framing builder) and
     MessageType (opcodes), CommandManager, BleManager, and anything
     mentioning HANDSHAKE / verification.
  3. Search the DEX strings table for any UUIDs we know (a000/a001/a002).
  4. Search every byte-array literal in the matched classes — those are how
     hard-coded handshake / verification bodies typically end up encoded.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

# silence noisy loguru output before importing androguard
from loguru import logger
logger.remove()
logger.add(sys.stderr, level="WARNING")

from androguard.core.apk import APK
from androguard.core.dex import DEX

APK_PATH = Path("/Users/longcao/Downloads/Nuna_1.9.1.apk")
OUT_DIR = Path("recordings/_apk_decompile")

HINTS = (
    "MessageBodyCreator",
    "MessageType",
    "BleManager",
    "CommandManager",
    "Handshake",
    "AudioRecording",
    "MileWave",
    "MILE_WAVE",
    "AUDIO_RECORDING",
    "verification",
    "VerifyCode",
)

UUID_HINTS = (
    "0000a000",
    "0000a001",
    "0000a002",
    "0000a003",
)


def _classes_of_interest(dex: DEX):
    out = []
    for c in dex.get_classes():
        cn = c.get_name().replace("/", ".").strip("L;")
        # Focus on app + BLE wrapper packages but allow hint matches anywhere
        in_pkg = (
            cn.startswith("com.xthings.nuna")
            or cn.startswith("com.things.common.ble")
            or cn.startswith("com.things.common.message")
        )
        in_hints = any(h.lower() in cn.lower() for h in HINTS)
        if in_pkg or in_hints:
            out.append(c)
    return out


def main() -> None:
    print(f"loading {APK_PATH}")
    apk = APK(str(APK_PATH))
    print(f"package: {apk.get_package()!r}  version: {apk.get_androidversion_name()!r}")
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    dex_blobs = apk.get_all_dex()
    dexes = []
    for i, raw in enumerate(dex_blobs):
        print(f"  parsing dex #{i}: {len(raw):,} bytes")
        dexes.append(DEX(raw))
    print(f"total dexes: {len(dexes)}")

    # 1) Search every dex for UUID strings
    print("\n--- UUID string hits ---")
    for d_i, dex in enumerate(dexes):
        for s in dex.get_strings():
            sl = str(s).lower()
            if any(h in sl for h in UUID_HINTS):
                print(f"  dex#{d_i}: {s!r}")

    # 2) Match classes of interest across all dexes
    print("\n--- candidate classes ---")
    matched = []
    for d_i, dex in enumerate(dexes):
        cls = _classes_of_interest(dex)
        for c in cls:
            matched.append((d_i, dex, c))
            print(f"  dex#{d_i}: {c.get_name()}")

    if not matched:
        print("(no matches; dumping any class containing 'a002' string)")
        for d_i, dex in enumerate(dexes):
            for c in dex.get_classes():
                src = ""
                try:
                    src = c.get_source() or ""
                except Exception:
                    pass
                if "a002" in src.lower() or "0000A002" in src:
                    print(f"  dex#{d_i}: {c.get_name()}")
                    matched.append((d_i, dex, c))

    # 3) Dump source of each matched class
    print("\n--- saving sources to", OUT_DIR.resolve())
    for d_i, _dex, c in matched:
        cn = c.get_name().replace("/", "_").strip("L_;").replace(";", "")
        path = OUT_DIR / f"d{d_i}_{cn}.java"
        try:
            src = c.get_source() or "// (empty)"
        except Exception as exc:
            src = f"// source unavailable: {exc}\n"
        path.write_text(src)

    # 4) Print short summaries of high-value classes inline
    INLINE = ("MessageBodyCreator", "MessageType", "CommandManager", "Handshake")
    for tag in INLINE:
        for d_i, _dex, c in matched:
            if tag.lower() not in c.get_name().lower():
                continue
            print(f"\n========== {c.get_name()} ==========")
            try:
                src = c.get_source() or "(empty)"
            except Exception as exc:
                src = f"(source error: {exc})"
            # truncate long sources
            print(src[:8000])
            if len(src) > 8000:
                print(f"... [{len(src)-8000} more bytes elided; full file in {OUT_DIR.resolve()}]")
            break

    # 5) Find every byte-array literal (`new byte[] { ... }`) in matched classes
    BYTE_LITERAL = re.compile(
        r"new\s+byte\[\]\s*\{[^}]*\}|byte\[\]\s*\w+\s*=\s*\{[^}]*\}",
        re.IGNORECASE,
    )
    print("\n--- byte[] literals in matched classes ---")
    for d_i, _dex, c in matched:
        try:
            src = c.get_source() or ""
        except Exception:
            continue
        for m in BYTE_LITERAL.finditer(src):
            line = m.group(0).replace("\n", " ").replace("  ", " ")[:200]
            print(f"  [{c.get_name()}] {line}")


if __name__ == "__main__":
    main()
