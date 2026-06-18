"""Standalone BLE probe: connect, subscribe to all notify chars, fire a list of
candidate trigger commands, and capture every notification to disk. Used to
reverse-engineer the start-of-transfer command for an unknown vendor protocol.

Usage:
  python tools/probe.py [--address <CB-UUID>] [--scan-only]

Outputs:
  recordings/probe-<timestamp>/<char-uuid>.bin     -- raw notification bytes per char
  recordings/probe-<timestamp>/probe.log           -- human-readable timeline
  recordings/probe-<timestamp>/manifest.json       -- summary
"""

from __future__ import annotations

import argparse
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

from ble_scan_util import advertisement_name, make_scanner, name_matches

DEFAULT_ADDRESS = "22347659-9F8F-0161-6A94-2578A69C26A6"

NOTIFY_UUIDS = [
    "0000a001-0000-1000-8000-00805f9b34fb",
    "0000a002-0000-1000-8000-00805f9b34fb",
    "0000a003-0000-1000-8000-00805f9b34fb",
    "00006487-3c17-d293-8e48-14fe2e4da212",
    "00002a19-0000-1000-8000-00805f9b34fb",
]

TRIGGERS: list[tuple[str, str, str]] = [
    ("0000a002-0000-1000-8000-00805f9b34fb", "01", "a002 <- 01"),
    ("0000a002-0000-1000-8000-00805f9b34fb", "02", "a002 <- 02"),
    ("0000a002-0000-1000-8000-00805f9b34fb", "0101", "a002 <- 0101"),
    ("0000a002-0000-1000-8000-00805f9b34fb", "0102", "a002 <- 0102"),
    ("0000a003-0000-1000-8000-00805f9b34fb", "01", "a003 <- 01"),
    ("0000a003-0000-1000-8000-00805f9b34fb", "02", "a003 <- 02"),
    ("0000a003-0000-1000-8000-00805f9b34fb", "fe01", "a003 <- FE 01"),
    ("00006387-3c17-d293-8e48-14fe2e4da212", "01", "6387 <- 01"),
    ("00006387-3c17-d293-8e48-14fe2e4da212", "0101", "6387 <- 0101"),
    ("0000ffd1-0000-1000-8000-00805f9b34fb", "01", "ffd1 <- 01"),
]

PER_TRIGGER_WINDOW_S = 1.0
QUIET_THRESHOLD_S = 4.0


async def find_device(
    target_address: str | None,
    target_name_substr: str | None = "nuna",
    total_seconds: float = 10.0,
):
    """Scan up to total_seconds; return the first BLEDevice that matches by
    address (preferred) or name substring."""
    print(
        f"[scan] looking for address={target_address!r} or name~{target_name_substr!r} "
        f"(up to {total_seconds:.0f}s)..."
    )
    matched: dict = {"device": None, "adv": None}
    done = asyncio.Event()

    def _cb(device, adv):
        if matched["device"]:
            return
        addr_ok = target_address and device.address.lower() == target_address.lower()
        name_ok = (
            bool(target_name_substr)
            and name_matches(target_name_substr, device, adv)
        )
        if addr_ok or name_ok:
            matched["device"] = device
            matched["adv"] = adv
            name = advertisement_name(device, adv) or ""
            print(
                f"[scan] FOUND: name={name!r} addr={device.address} "
                f"rssi={getattr(adv, 'rssi', '?')}"
            )
            done.set()

    scanner = make_scanner(detection_callback=_cb)
    await scanner.start()
    try:
        await asyncio.wait_for(done.wait(), timeout=total_seconds)
    except asyncio.TimeoutError:
        pass
    finally:
        await scanner.stop()
    return matched["device"]


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--address", default=None)
    parser.add_argument("--name", default="nuna",
                        help="substring of the advertised name to match")
    parser.add_argument("--scan-only", action="store_true")
    parser.add_argument("--no-scan", action="store_true",
                        help="skip the discovery scan and try connecting directly")
    args = parser.parse_args()

    out_dir = Path("recordings") / time.strftime("probe-%Y%m%d-%H%M%S")
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "probe.log"
    log_f = log_path.open("w")

    def log(line: str) -> None:
        ts = time.strftime("%H:%M:%S")
        msg = f"[{ts}] {line}"
        print(msg)
        log_f.write(msg + "\n")
        log_f.flush()

    log(f"output dir: {out_dir.resolve()}")
    log(f"target: address={args.address!r} name~{args.name!r}")

    device = None
    if args.scan_only:
        device = await find_device(args.address, args.name, total_seconds=15)
        log(f"scan-only result: {device}")
        log_f.close()
        return 0 if device else 2

    if not args.no_scan:
        device = await find_device(args.address, args.name)
        if device is None:
            log("not advertising. Will try direct connect with the given address (if any).")

    files: dict[str, any] = {}
    counts: dict[str, int] = {u: 0 for u in NOTIFY_UUIDS}
    bytes_count: dict[str, int] = {u: 0 for u in NOTIFY_UUIDS}
    last_seen: dict[str, float] = {}
    trigger_log: list[dict] = []

    for u in NOTIFY_UUIDS:
        files[u] = (out_dir / f"{u}.bin").open("wb")

    try:
        log("connecting...")
        target = device if device is not None else (args.address or DEFAULT_ADDRESS)
        client = BleakClient(target, timeout=20.0)
        await client.connect()
        log(f"connected. mtu={getattr(client, 'mtu_size', '?')}")

        def make_cb(u):
            def _cb(char: BleakGATTCharacteristic, data: bytearray) -> None:
                payload = bytes(data)
                files[u].write(payload)
                counts[u] += 1
                bytes_count[u] += len(payload)
                last_seen[u] = time.time()
                preview = payload[:24].hex()
                log(f"  notify {u[4:8]} +{len(payload)}B  {preview}{'...' if len(payload)>24 else ''}")
            return _cb

        for u in NOTIFY_UUIDS:
            try:
                await client.start_notify(u, make_cb(u))
                log(f"subscribed to {u}")
            except Exception as exc:
                log(f"subscribe failed on {u}: {exc}")

        log("baseline (3s of silence to establish quiet)...")
        await asyncio.sleep(3.0)
        baseline_bytes = sum(bytes_count.values())
        log(f"baseline bytes={baseline_bytes}")

        log(f"trying {len(TRIGGERS)} candidate triggers...")
        for char, hex_str, label in TRIGGERS:
            data = bytes.fromhex(hex_str)
            before = sum(bytes_count.values())
            try:
                await client.write_gatt_char(char, data, response=False)
                log(f"  TRY  {label}  (write {hex_str} -> {char[:8]})")
            except Exception as exc:
                log(f"  SKIP {label}  write error: {exc}")
                trigger_log.append({"char": char, "hex": hex_str, "label": label, "error": str(exc)})
                continue

            await asyncio.sleep(PER_TRIGGER_WINDOW_S)
            delta = sum(bytes_count.values()) - before
            trigger_log.append({"char": char, "hex": hex_str, "label": label, "bytes_after": delta})
            if delta > 0:
                log(f"  -> got {delta}B in {PER_TRIGGER_WINDOW_S}s")
                if delta >= 64:
                    log(f"  ! significant burst — letting it run until {QUIET_THRESHOLD_S}s of quiet")
                    last_total = sum(bytes_count.values())
                    last_change = time.time()
                    while time.time() - last_change < QUIET_THRESHOLD_S:
                        await asyncio.sleep(0.5)
                        total = sum(bytes_count.values())
                        if total != last_total:
                            last_total = total
                            last_change = time.time()
                    log(f"  quiet reached. total bytes now {last_total}")
                    break

        log("disconnecting...")
        for u in NOTIFY_UUIDS:
            try:
                await client.stop_notify(u)
            except Exception:
                pass
        await client.disconnect()

    except Exception as exc:
        log(f"ERROR: {exc!r}")
    finally:
        for f in files.values():
            try:
                f.flush(); f.close()
            except Exception:
                pass
        manifest = {
            "address": args.address,
            "out_dir": str(out_dir.resolve()),
            "uuids": NOTIFY_UUIDS,
            "packets": counts,
            "bytes": bytes_count,
            "total_bytes": sum(bytes_count.values()),
            "total_packets": sum(counts.values()),
            "files": {u: str((out_dir / f"{u}.bin").resolve()) for u in NOTIFY_UUIDS},
            "triggers": trigger_log,
        }
        (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
        log("manifest written.")
        log_f.close()
        print()
        print("SUMMARY")
        print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
