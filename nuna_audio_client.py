#!/usr/bin/env python3
"""nuna_audio_client.py — connect to a Nuna pendant, enable live audio
recording, and capture every AUDIO_RECORDING_DATA payload to disk.

Saves both:
  audio.bin   raw concatenated AUDIO_RECORDING_DATA payloads (codec-agnostic)
  audio.wav   wrapped as PCM (16 kHz mono 16-bit by default; override flags)
  session.log human-readable timeline + counts + observed packet rate
  manifest.json summary

By default the saved WAV assumes 16 kHz / mono / 16-bit PCM. If the device
emits a compressed codec (Opus / ADPCM / G.711) the WAV will be noise — keep
audio.bin and decode it externally. Run with --report-frame-sizes to see a
histogram of payload sizes; that often reveals codec framing.

Usage:
    python nuna_audio_client.py --seconds 30
    python nuna_audio_client.py --address 22347659-... --seconds 60 --out-dir my-session
"""
from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
import wave
from collections import Counter
from pathlib import Path

from bleak import BleakClient

from ble_scan_util import advertisement_name, make_scanner, name_matches

from nuna_protocol import (
    CHAR_NOTIFY,
    CHAR_WRITE,
    MessageType,
    Parser,
    build_packet,
    enable_audio,
    handshake,
    heartbeat,
)

DEFAULT_NAME = "nuna"


async def find_device(name_substr: str, timeout: float = 15.0):
    print(f"[scan] looking for name~{name_substr!r} (up to {timeout:.0f}s)...")
    found: dict = {"d": None}
    done = asyncio.Event()

    def cb(d, adv):
        if name_matches(name_substr, d, adv) and not found["d"]:
            found["d"] = d
            print(
                f"[scan] FOUND: {d.address} name={advertisement_name(d, adv)!r} "
                f"rssi={getattr(adv, 'rssi', '?')}"
            )
            done.set()

    s = make_scanner(detection_callback=cb)
    await s.start()
    try:
        await asyncio.wait_for(done.wait(), timeout)
    except asyncio.TimeoutError:
        pass
    finally:
        await s.stop()
    return found["d"]


async def run(args) -> int:
    out_dir = Path(args.out_dir or f"recordings/nuna-audio-{time.strftime('%Y%m%d-%H%M%S')}")
    out_dir.mkdir(parents=True, exist_ok=True)
    bin_path = out_dir / "audio.bin"
    wav_path = out_dir / "audio.wav"
    log_path = out_dir / "session.log"
    manifest_path = out_dir / "manifest.json"

    bin_f = bin_path.open("wb")
    log_f = log_path.open("w")

    def log(msg: str) -> None:
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        print(line)
        log_f.write(line + "\n")
        log_f.flush()

    log(f"output dir: {out_dir.resolve()}")

    if args.address:
        target = args.address
    else:
        device = await find_device(args.name, timeout=args.scan_timeout)
        if device is None:
            log("device not found. Power-cycle Nuna or pass --address.")
            bin_f.close()
            log_f.close()
            return 2
        target = device

    parser = Parser()
    counts: Counter = Counter()
    audio_bytes = 0
    audio_packets = 0
    frame_sizes: Counter = Counter()
    rate_window_bytes = 0
    rate_window_start = time.time()
    first_audio_at: float | None = None
    last_audio_at: float | None = None

    def on_notify(_handle, data: bytearray) -> None:
        nonlocal audio_bytes, audio_packets, rate_window_bytes
        nonlocal first_audio_at, last_audio_at
        for mtype, payload in parser.feed(bytes(data)):
            name = mtype.name if isinstance(mtype, MessageType) else f"UNK_{mtype}"
            counts[name] += 1
            if mtype == MessageType.AUDIO_RECORDING_DATA:
                bin_f.write(payload)
                audio_bytes += len(payload)
                audio_packets += 1
                rate_window_bytes += len(payload)
                frame_sizes[len(payload)] += 1
                now = time.time()
                if first_audio_at is None:
                    first_audio_at = now
                    log(f"first audio frame received: {len(payload)}B  preview={payload[:24].hex()}")
                last_audio_at = now
            elif mtype == MessageType.BATTERY_LEVEL and payload:
                log(f"BATTERY_LEVEL payload={payload.hex()}")
            elif mtype == MessageType.HANDSHAKE:
                log(f"HANDSHAKE reply payload={payload.hex()}")
            elif mtype == MessageType.AUDIO_RECORDING_SWITCH:
                log(f"AUDIO_RECORDING_SWITCH ack payload={payload.hex()}")
            else:
                log(f"recv {name} payload={payload[:32].hex()}{'...' if len(payload)>32 else ''} ({len(payload)}B)")

    log(f"connecting to {getattr(target, 'address', target)}...")
    async with BleakClient(target, timeout=20.0) as client:
        log(f"connected. mtu={getattr(client, 'mtu_size', '?')}")
        await client.start_notify(CHAR_NOTIFY, on_notify)
        log("subscribed to notify char a001")

        try:
            log("HANDSHAKE...")
            await client.write_gatt_char(CHAR_WRITE, handshake(), response=True)
        except Exception as exc:
            log(f"handshake error (continuing): {exc}")
        await asyncio.sleep(0.5)

        try:
            log(f"enabling audio: write {enable_audio(True).hex(' ')} -> a002")
            await client.write_gatt_char(CHAR_WRITE, enable_audio(True), response=True)
        except Exception as exc:
            log(f"enable audio FAILED: {exc}")

        end_time = time.time() + args.seconds
        log(f"recording for {args.seconds}s (Ctrl+C to stop early)...")
        try:
            while time.time() < end_time and client.is_connected:
                await asyncio.sleep(1.0)
                now = time.time()
                if now - rate_window_start >= 5.0:
                    rate = rate_window_bytes / (now - rate_window_start)
                    log(
                        f"audio rate: {rate:7.0f} B/s  total={audio_bytes}B "
                        f"packets={audio_packets}  other_msgs={dict(counts)}"
                    )
                    rate_window_start = now
                    rate_window_bytes = 0
                try:
                    await client.write_gatt_char(CHAR_WRITE, heartbeat(), response=False)
                except Exception:
                    pass
        except asyncio.CancelledError:
            log("cancelled")
        finally:
            try:
                log("disabling audio...")
                await client.write_gatt_char(CHAR_WRITE, enable_audio(False), response=True)
            except Exception as exc:
                log(f"disable audio error: {exc}")
            try:
                await client.stop_notify(CHAR_NOTIFY)
            except Exception:
                pass

    bin_f.close()

    log(f"counts: {dict(counts)}")
    log(f"audio: {audio_packets} packets, {audio_bytes} bytes")

    if frame_sizes:
        common = frame_sizes.most_common(8)
        log(f"frame size histogram (size: count): {common}")
        sizes = [s for s, _ in common]
        log(f"size stats: min={min(sizes)} max={max(sizes)} median={statistics.median(sizes)}")

    elapsed_audio = (
        (last_audio_at - first_audio_at) if (first_audio_at and last_audio_at) else 0.0
    )
    avg_rate = audio_bytes / elapsed_audio if elapsed_audio > 0 else 0.0
    log(f"audio span: {elapsed_audio:.2f}s  avg rate: {avg_rate:.0f} B/s")

    # Wrap as PCM WAV
    wav_info: dict | None = None
    if audio_bytes > 0:
        sr = args.sample_rate
        ch = args.channels
        sw = args.sample_width
        raw = bin_path.read_bytes()
        if args.skip_header_bytes:
            raw = raw[args.skip_header_bytes:]
        frame_size = sw * ch
        if len(raw) % frame_size:
            raw = raw[: (len(raw) // frame_size) * frame_size]
        with wave.open(str(wav_path), "wb") as wf:
            wf.setnchannels(ch)
            wf.setsampwidth(sw)
            wf.setframerate(sr)
            wf.writeframes(raw)
        duration = (len(raw) // frame_size) / sr if sr else 0.0
        wav_info = {
            "path": str(wav_path),
            "sample_rate": sr,
            "channels": ch,
            "sample_width": sw,
            "duration_s": duration,
            "frames": len(raw) // frame_size,
        }
        log(
            f"WAV: {wav_path}  "
            f"({duration:.2f}s, sr={sr}Hz, ch={ch}, {sw*8}-bit PCM)"
        )

    manifest = {
        "out_dir": str(out_dir.resolve()),
        "bin": str(bin_path.resolve()),
        "wav": wav_info,
        "address": getattr(target, "address", target),
        "counts": dict(counts),
        "audio_packets": audio_packets,
        "audio_bytes": audio_bytes,
        "frame_size_histogram": dict(frame_sizes),
        "audio_span_s": elapsed_audio,
        "avg_byte_rate": avg_rate,
        "first_audio_at": first_audio_at,
        "last_audio_at": last_audio_at,
        "wav_assumptions": {
            "sample_rate": args.sample_rate,
            "channels": args.channels,
            "sample_width": args.sample_width,
            "skip_header_bytes": args.skip_header_bytes,
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2))
    log(f"manifest: {manifest_path.resolve()}")
    log_f.close()
    print()
    print(json.dumps(manifest, indent=2))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--address", default=None,
                    help="BLE address (CB UUID on macOS); skip scan if given")
    ap.add_argument("--name", default=DEFAULT_NAME,
                    help="advertised-name substring (default 'nuna')")
    ap.add_argument("--scan-timeout", type=float, default=15.0)
    ap.add_argument("--seconds", type=float, default=20.0,
                    help="how long to record (default 20s)")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--sample-rate", type=int, default=16000)
    ap.add_argument("--channels", type=int, default=1)
    ap.add_argument("--sample-width", type=int, default=2,
                    help="bytes per sample for the .wav guess (1, 2, 3, or 4)")
    ap.add_argument("--skip-header-bytes", type=int, default=0,
                    help="strip N leading bytes from audio.bin before writing wav")
    args = ap.parse_args()
    sys.exit(asyncio.run(run(args)))


if __name__ == "__main__":
    main()
