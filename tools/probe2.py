"""Probe v2: bonded connect + state-change detection.

After each write, re-reads a small set of state chars (a001, f001, f002) to
detect if the device's internal state advanced. If a state change is seen,
that write is meaningful even if no notifications come back.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from bleak import BleakClient
from bleak.backends.characteristic import BleakGATTCharacteristic

from ble_scan_util import make_scanner, name_matches

NAME = "nuna"
NOTIFY_UUIDS = [
    "0000a001-0000-1000-8000-00805f9b34fb",
    "0000a002-0000-1000-8000-00805f9b34fb",
    "0000a003-0000-1000-8000-00805f9b34fb",
    "00006487-3c17-d293-8e48-14fe2e4da212",
]
STATE_UUIDS = [
    "0000a001-0000-1000-8000-00805f9b34fb",
    "0000f001-0000-1000-8000-00805f9b34fb",
    "0000f002-0000-1000-8000-00805f9b34fb",
    "0000fff1-0000-1000-8000-00805f9b34fb",
    "0000fff3-0000-1000-8000-00805f9b34fb",
]

# Broader trigger set, including 2-byte & "request file" patterns.
TRIGGERS: list[tuple[str, str]] = [
    ("0000a002-0000-1000-8000-00805f9b34fb", "01"),
    ("0000a002-0000-1000-8000-00805f9b34fb", "02"),
    ("0000a002-0000-1000-8000-00805f9b34fb", "03"),
    ("0000a002-0000-1000-8000-00805f9b34fb", "04"),
    ("0000a002-0000-1000-8000-00805f9b34fb", "05"),
    ("0000a002-0000-1000-8000-00805f9b34fb", "10"),
    ("0000a002-0000-1000-8000-00805f9b34fb", "20"),
    ("0000a002-0000-1000-8000-00805f9b34fb", "0100"),
    ("0000a002-0000-1000-8000-00805f9b34fb", "0200"),
    ("0000a003-0000-1000-8000-00805f9b34fb", "01"),
    ("0000a003-0000-1000-8000-00805f9b34fb", "02"),
    ("0000a003-0000-1000-8000-00805f9b34fb", "0100"),
    ("0000a003-0000-1000-8000-00805f9b34fb", "0001"),
    ("0000a003-0000-1000-8000-00805f9b34fb", "020001"),
    ("00006387-3c17-d293-8e48-14fe2e4da212", "01"),
    ("00006387-3c17-d293-8e48-14fe2e4da212", "02"),
    ("0000ffd1-0000-1000-8000-00805f9b34fb", "01"),
    ("0000ffd1-0000-1000-8000-00805f9b34fb", "02"),
    ("0000ffd1-0000-1000-8000-00805f9b34fb", "03"),
]


async def find():
    print("[scan] looking for 'nuna'...")
    found = {"d": None}
    done = asyncio.Event()
    def cb(d, adv):
        if name_matches(NAME, d, adv) and not found["d"]:
            found["d"] = d
            done.set()
    s = make_scanner(detection_callback=cb)
    await s.start()
    try:
        await asyncio.wait_for(done.wait(), 25)
    except asyncio.TimeoutError:
        pass
    finally:
        await s.stop()
    return found["d"]


async def read_state(client: BleakClient) -> dict[str, str]:
    state = {}
    for u in STATE_UUIDS:
        try:
            data = await client.read_gatt_char(u)
            state[u] = bytes(data).hex()
        except Exception as exc:
            state[u] = f"err:{exc}"
    return state


async def main() -> int:
    out_dir = Path("recordings") / time.strftime("probe2-%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "probe.log"
    log_f = log_path.open("w")
    def log(line: str) -> None:
        msg = f"[{time.strftime('%H:%M:%S')}] {line}"
        print(msg); log_f.write(msg + "\n"); log_f.flush()

    log(f"output dir: {out_dir.resolve()}")

    device = await find()
    if device is None:
        log("device not found, bailing.")
        log_f.close(); return 2
    log(f"target: {device.address}  name={device.name!r}")

    files = {u: (out_dir / f"{u}.bin").open("wb") for u in NOTIFY_UUIDS}
    counts = {u: 0 for u in NOTIFY_UUIDS}
    bytes_count = {u: 0 for u in NOTIFY_UUIDS}

    interesting: list[dict] = []

    try:
        log("connecting (pair=True)...")
        client = BleakClient(device, timeout=20.0, pair=True)
        await client.connect()
        log(f"connected. mtu={getattr(client, 'mtu_size', '?')}")

        def make_cb(u):
            def _cb(char: BleakGATTCharacteristic, data: bytearray) -> None:
                payload = bytes(data)
                files[u].write(payload)
                counts[u] += 1
                bytes_count[u] += len(payload)
                preview = payload[:32].hex()
                log(f"  notify {u[4:8]} +{len(payload)}B  {preview}")
            return _cb

        for u in NOTIFY_UUIDS:
            try:
                await client.start_notify(u, make_cb(u))
                log(f"subscribed {u[4:8]}")
            except Exception as exc:
                log(f"subscribe {u[4:8]} failed: {exc}")

        log("baseline state read...")
        baseline = await read_state(client)
        for u, v in baseline.items():
            log(f"  {u[4:8]} = {v}")

        last_state = baseline
        log(f"trying {len(TRIGGERS)} triggers, watching for state changes & notifies...")

        for char, hex_str in TRIGGERS:
            data = bytes.fromhex(hex_str)
            before_bytes = sum(bytes_count.values())
            try:
                await client.write_gatt_char(char, data, response=False)
            except Exception as exc:
                log(f"  WRITE-ERR  {char[4:8]} <- {hex_str}  ({exc})")
                continue

            await asyncio.sleep(0.8)
            new_state = await read_state(client)
            byte_delta = sum(bytes_count.values()) - before_bytes

            changes = {u: (last_state.get(u), new_state.get(u))
                       for u in STATE_UUIDS
                       if last_state.get(u) != new_state.get(u)}

            tag = "OK"
            if byte_delta > 0 or changes:
                tag = "*** REACTION ***"
                interesting.append({
                    "char": char, "hex": hex_str,
                    "byte_delta": byte_delta, "state_changes": changes,
                })
            log(f"  {tag}  {char[4:8]} <- {hex_str}  bytes+={byte_delta}  state_changes={list(changes.keys())}")
            for u, (old, new) in changes.items():
                log(f"     {u[4:8]}: {old}  ->  {new}")

            if byte_delta >= 64:
                log("  large burst — letting it run 5s of quiet...")
                last_total = sum(bytes_count.values())
                last_change = time.time()
                while time.time() - last_change < 5:
                    await asyncio.sleep(0.5)
                    total = sum(bytes_count.values())
                    if total != last_total:
                        last_total = total; last_change = time.time()
                log(f"  done. total bytes now {last_total}")
                break

            last_state = new_state

        log("disconnecting...")
        for u in NOTIFY_UUIDS:
            try: await client.stop_notify(u)
            except Exception: pass
        await client.disconnect()

    except Exception as exc:
        log(f"ERROR: {exc!r}")
    finally:
        for f in files.values():
            try: f.flush(); f.close()
            except Exception: pass
        manifest = {
            "out_dir": str(out_dir.resolve()),
            "uuids": NOTIFY_UUIDS,
            "packets": counts, "bytes": bytes_count,
            "total_bytes": sum(bytes_count.values()),
            "files": {u: str((out_dir / f"{u}.bin").resolve()) for u in NOTIFY_UUIDS},
            "interesting_writes": interesting,
        }
        (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
        log_f.close()
        print()
        print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))
