"""BLE manager wrapping `bleak` in a dedicated background asyncio loop.

Flask handlers are synchronous; bleak is async. We run one event loop in a
background thread and submit coroutines to it via `run_coroutine_threadsafe`.
Notifications are fanned out to subscriber queues so SSE endpoints can stream,
and to per-characteristic recording sessions that write the raw bytes to disk.
"""

from __future__ import annotations

import asyncio
import json
import struct
import threading
import time
import uuid as uuidlib
from pathlib import Path
from queue import Queue
from typing import Any, Callable, Optional

from bleak import BleakClient, BleakScanner
from bleak.backends.characteristic import BleakGATTCharacteristic
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from nuna_protocol import (
    CHAR_RECORDING as NUNA_RECORDING,
    CHAR_STATUS as NUNA_STATUS,
    CHAR_TRANSFER as NUNA_TRANSFER,
    HARDCODED_VERIFY,
    HandshakeMessageType,
    MessageType as NunaMsgType,
    NOTIFY_CHARS as NUNA_NOTIFY_CHARS,
    AudioReassembler,
    Parser as NunaParser,
    handshake_completed_packet,
    handshake_request_packet,
    heartbeat as nuna_heartbeat,
    parse_audio_frame,
    set_time_packet as nuna_set_time_packet,
    switch_record_packet as nuna_switch_record_packet,
)

# Backward-compat aliases (existing methods reference these names)
NUNA_NOTIFY = NUNA_STATUS
NUNA_WRITE = NUNA_TRANSFER


def _norm(uuid: str) -> str:
    return uuid.lower().strip()


class _RecordingSession:
    """Captures raw notification payloads from one or more characteristics
    into per-characteristic .bin files on disk."""

    def __init__(
        self,
        session_id: str,
        uuids: list[str],
        directory: Path,
        idle_timeout_s: Optional[float],
    ) -> None:
        self.id = session_id
        self.uuids = [_norm(u) for u in uuids]
        self.dir = directory
        self.idle_timeout_s = idle_timeout_s
        self.files: dict[str, Any] = {}
        self.byte_count: dict[str, int] = {u: 0 for u in self.uuids}
        self.packet_count: dict[str, int] = {u: 0 for u in self.uuids}
        self.started_at = time.time()
        self.last_packet_at: Optional[float] = None
        self.stopped = False
        self._lock = threading.Lock()

    def open(self) -> None:
        self.dir.mkdir(parents=True, exist_ok=True)
        for u in self.uuids:
            self.files[u] = open(self.dir / f"{u}.bin", "wb")

    def write(self, char_uuid: str, payload: bytes) -> None:
        u = _norm(char_uuid)
        with self._lock:
            if self.stopped:
                return
            f = self.files.get(u)
            if f is None:
                return
            f.write(payload)
            self.byte_count[u] = self.byte_count.get(u, 0) + len(payload)
            self.packet_count[u] = self.packet_count.get(u, 0) + 1
            self.last_packet_at = time.time()

    def close(self) -> dict[str, Any]:
        with self._lock:
            if self.stopped:
                return self._manifest()
            self.stopped = True
            for f in self.files.values():
                try:
                    f.flush()
                    f.close()
                except Exception:
                    pass
        manifest = self._manifest()
        try:
            (self.dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
        except Exception:
            pass
        return manifest

    def status(self) -> dict[str, Any]:
        now = time.time()
        return {
            **self._manifest(),
            "elapsed_s": now - self.started_at,
            "since_last_packet_s": (
                None if self.last_packet_at is None else now - self.last_packet_at
            ),
        }

    def _manifest(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "uuids": self.uuids,
            "dir": str(self.dir.resolve()),
            "files": {
                u: str((self.dir / f"{u}.bin").resolve()) for u in self.uuids
            },
            "started_at": self.started_at,
            "last_packet_at": self.last_packet_at,
            "stopped": self.stopped,
            "idle_timeout_s": self.idle_timeout_s,
            "bytes": dict(self.byte_count),
            "packets": dict(self.packet_count),
            "total_bytes": sum(self.byte_count.values()),
            "total_packets": sum(self.packet_count.values()),
        }


class _NunaSession:
    """Live-audio capture from a Nuna pendant. Reassembles AUDIO_RECORDING_DATA
    chunks into Opus packets, handles the 3-step handshake echo, and writes
    everything to disk for offline decoding. Notifications are fed in via
    `feed_notify` from the BleManager's _subscribe callback."""

    def __init__(self, session_id: str, directory: Path, verification_code: str) -> None:
        self.id = session_id
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self.verification_code = verification_code

        # raw notifications, by source characteristic, for postmortem analysis
        self.raw_path = self.dir / "raw_notify.bin"
        self.raw_file = self.raw_path.open("wb")

        # length-prefixed Opus packets (one per assembled frame): for each
        # assembled frame we write <u32 LE length><opus_bytes><u64 LE timestamp_ms>
        self.opus_packets_path = self.dir / "audio.opus_packets.bin"
        self.opus_file = self.opus_packets_path.open("wb")

        # per-channel parsers (each notify char carries its own framed stream)
        self.parsers: dict[str, NunaParser] = {}
        self.assembler = AudioReassembler()

        self.audio_packets = 0          # # Opus frames assembled
        self.audio_bytes = 0             # bytes in assembled Opus payloads
        self.audio_chunks = 0            # # AUDIO_RECORDING_DATA notifications received
        self.frame_size_hist: dict[int, int] = {}
        self.message_counts: dict[str, int] = {}
        self.notify_counts: dict[str, int] = {}

        self.first_audio_at: Optional[float] = None
        self.last_audio_at: Optional[float] = None
        self.started_at = time.time()
        self.stopped = False
        self.last_battery: Optional[str] = None

        # handshake state
        self.handshake_event: Optional[asyncio.Event] = None  # set externally
        self.handshake_response_value: Optional[str] = None
        self.handshake_response_match: Optional[bool] = None
        self.handshake_error_code: Optional[int] = None
        self.handshake_completed_sent = False

        # post-handshake control flow (mirrors the app)
        self.set_time_sent = False
        self.status_read_value: Optional[str] = None
        self.switch_record_sent = False

        # CONTROL_REQUEST command-id counter (the app's
        # `CommandManager.createCommandSession()`).
        self._next_cmd_id = 0

        self._lock = threading.Lock()

    def next_command_id(self) -> int:
        with self._lock:
            cid = self._next_cmd_id
            self._next_cmd_id = (self._next_cmd_id + 1) & 0xFFFF
            return cid

    def _set_handshake_event(self) -> None:
        evt = self.handshake_event
        if evt is None:
            return
        loop = getattr(evt, "_loop", None)
        if loop is not None and loop.is_running():
            loop.call_soon_threadsafe(evt.set)
        else:
            try:
                evt.set()
            except RuntimeError:
                pass

    def feed_notify(self, char_uuid: str, payload: bytes, publish) -> None:
        with self._lock:
            if self.stopped:
                return
            try:
                self.raw_file.write(struct.pack("<HH", len(char_uuid), len(payload)))
                self.raw_file.write(char_uuid.encode("ascii", "replace"))
                self.raw_file.write(payload)
            except Exception:
                pass
            self.notify_counts[char_uuid] = self.notify_counts.get(char_uuid, 0) + 1

            parser = self.parsers.setdefault(char_uuid, NunaParser())
            for mtype, body in parser.feed(payload):
                self._handle_message(char_uuid, mtype, body, publish)

    def _handle_message(self, char_uuid: str, mtype: Any, body: bytes, publish) -> None:
        name = mtype.name if hasattr(mtype, "name") else f"UNK_{mtype}"
        self.message_counts[name] = self.message_counts.get(name, 0) + 1

        if mtype == NunaMsgType.AUDIO_RECORDING_DATA:
            self._on_audio_chunk(body, publish)
        elif mtype == NunaMsgType.HANDSHAKE:
            self._on_handshake_message(body, publish)
        elif mtype == NunaMsgType.BATTERY_LEVEL:
            self.last_battery = body.hex()
            publish({
                "type": "nuna_event", "name": name, "uuid": char_uuid,
                "hex": body.hex(), "ts": time.time(),
            })
        else:
            publish({
                "type": "nuna_event", "name": name, "uuid": char_uuid,
                "hex": body.hex(), "len": len(body), "ts": time.time(),
            })

    def _on_handshake_message(self, body: bytes, publish) -> None:
        if not body:
            publish({"type": "nuna_event", "name": "handshake_empty", "ts": time.time()})
            return
        sub = body[0]
        rest = body[1:]
        if sub == HandshakeMessageType.HANDSHAKE_RESPONSE:
            try:
                value = rest.decode("ascii")
            except UnicodeDecodeError:
                value = rest.hex()
            self.handshake_response_value = value
            self.handshake_response_match = (rest == self.verification_code.encode("utf-8"))
            publish({
                "type": "nuna_event", "name": "handshake_response",
                "value": value, "match": self.handshake_response_match,
                "ts": time.time(),
            })
            self._set_handshake_event()
        elif sub == HandshakeMessageType.HANDSHAKE_ERROR:
            self.handshake_error_code = rest[0] if rest else None
            publish({
                "type": "nuna_event", "name": "handshake_error",
                "code": self.handshake_error_code, "ts": time.time(),
            })
            self._set_handshake_event()
        else:
            publish({
                "type": "nuna_event", "name": "handshake_other",
                "sub": sub, "hex": body.hex(), "ts": time.time(),
            })

    def _on_audio_chunk(self, body: bytes, publish) -> None:
        self.audio_chunks += 1
        try:
            frame = parse_audio_frame(body)
        except Exception as exc:
            publish({
                "type": "nuna_event", "name": "audio_parse_err",
                "error": str(exc), "len": len(body), "ts": time.time(),
            })
            return
        result = self.assembler.add(frame)
        if result is None:
            return
        frame_id, ts_ms, opus = result
        self.audio_packets += 1
        self.audio_bytes += len(opus)
        self.frame_size_hist[len(opus)] = self.frame_size_hist.get(len(opus), 0) + 1
        now = time.time()
        if self.first_audio_at is None:
            self.first_audio_at = now
        self.last_audio_at = now
        try:
            self.opus_file.write(struct.pack("<I", len(opus)))
            self.opus_file.write(opus)
            self.opus_file.write(struct.pack("<Q", ts_ms))
        except Exception:
            pass
        publish({
            "type": "nuna_audio", "session": self.id, "ts": now,
            "frame_id": frame_id, "frame_bytes": len(opus),
            "device_ts_ms": ts_ms,
            "total_packets": self.audio_packets,
            "total_bytes": self.audio_bytes,
        })

    def close(self) -> dict[str, Any]:
        with self._lock:
            if self.stopped:
                return self.status()
            self.stopped = True
            for f in (self.raw_file, self.opus_file):
                try:
                    f.flush()
                    f.close()
                except Exception:
                    pass
        manifest = self.status()
        try:
            (self.dir / "manifest.json").write_text(json.dumps(manifest, indent=2))
        except Exception:
            pass
        return manifest

    def status(self) -> dict[str, Any]:
        elapsed_audio = (
            (self.last_audio_at - self.first_audio_at)
            if (self.first_audio_at and self.last_audio_at)
            else 0.0
        )
        avg_rate = self.audio_bytes / elapsed_audio if elapsed_audio > 0 else 0.0
        return {
            "id": self.id,
            "dir": str(self.dir.resolve()),
            "raw": str(self.raw_path.resolve()),
            "opus_packets": str(self.opus_packets_path.resolve()),
            "stopped": self.stopped,
            "started_at": self.started_at,
            "first_audio_at": self.first_audio_at,
            "last_audio_at": self.last_audio_at,
            "audio_packets": self.audio_packets,
            "audio_bytes": self.audio_bytes,
            "audio_chunks": self.audio_chunks,
            "avg_byte_rate": avg_rate,
            "message_counts": dict(self.message_counts),
            "notify_counts": dict(self.notify_counts),
            "frame_size_histogram": dict(self.frame_size_hist),
            "last_battery": self.last_battery,
            "verification_code": self.verification_code,
            "handshake_response_value": self.handshake_response_value,
            "handshake_response_match": self.handshake_response_match,
            "handshake_error_code": self.handshake_error_code,
            "handshake_completed_sent": self.handshake_completed_sent,
            "set_time_sent": self.set_time_sent,
            "status_read_value": self.status_read_value,
            "switch_record_sent": self.switch_record_sent,
        }


class BleManager:
    def __init__(self, recordings_root: Optional[Path] = None) -> None:
        self._loop: asyncio.AbstractEventLoop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name="ble-loop", daemon=True
        )
        self._thread.start()

        self._client: Optional[BleakClient] = None
        self._connected_address: Optional[str] = None
        self._connected_name: Optional[str] = None
        self._subscribed: set[str] = set()
        self._notify_callbacks: dict[str, list[Callable[[str, bytes], None]]] = {}
        self._subscribers: list[Queue] = []
        self._sessions: dict[str, _RecordingSession] = {}
        self._nuna_sessions: dict[str, _NunaSession] = {}
        self._lock = threading.Lock()

        self.recordings_root = recordings_root or Path("recordings")

        self._idle_watcher = threading.Thread(
            target=self._watch_idle_sessions, name="ble-idle-watch", daemon=True
        )
        self._idle_watcher.start()

    # ---------- background loop plumbing ----------

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _submit(self, coro, timeout: Optional[float] = 30.0):
        future = asyncio.run_coroutine_threadsafe(coro, self._loop)
        return future.result(timeout=timeout)

    # ---------- public sync API used by Flask ----------

    def scan(self, seconds: float = 5.0) -> list[dict[str, Any]]:
        return self._submit(self._scan(seconds), timeout=seconds + 10)

    def connect(self, address: str, timeout: float = 15.0) -> dict[str, Any]:
        return self._submit(self._connect(address, timeout), timeout=timeout + 10)

    def disconnect(self) -> dict[str, Any]:
        return self._submit(self._disconnect(), timeout=15)

    def status(self) -> dict[str, Any]:
        connected = self._client is not None and self._client.is_connected
        return {
            "connected": connected,
            "address": self._connected_address if connected else None,
            "name": self._connected_name if connected else None,
            "subscribed": sorted(self._subscribed) if connected else [],
            "active_recordings": [
                s.id for s in self._sessions.values() if not s.stopped
            ],
        }

    def services(self) -> list[dict[str, Any]]:
        return self._submit(self._services(), timeout=15)

    def read(self, char_uuid: str) -> dict[str, Any]:
        return self._submit(self._read(char_uuid), timeout=15)

    def read_all_readable(self) -> dict[str, Any]:
        return self._submit(self._read_all_readable(), timeout=60)

    def write(
        self, char_uuid: str, data: bytes, response: bool = True
    ) -> dict[str, Any]:
        return self._submit(self._write(char_uuid, data, response), timeout=15)

    def subscribe(self, char_uuid: str) -> dict[str, Any]:
        return self._submit(self._subscribe(char_uuid), timeout=15)

    def unsubscribe(self, char_uuid: str) -> dict[str, Any]:
        return self._submit(self._unsubscribe(char_uuid), timeout=15)

    # ---------- recording API ----------

    def start_recording(
        self,
        uuids: list[str],
        idle_timeout_s: Optional[float] = 3.0,
        name: Optional[str] = None,
        trigger: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        if not uuids:
            raise ValueError("uuids list is empty")
        if self._client is None or not self._client.is_connected:
            raise RuntimeError("Not connected. Call /api/connect first.")

        ts = time.strftime("%Y%m%d-%H%M%S")
        session_id = f"{ts}-{uuidlib.uuid4().hex[:6]}" if not name else f"{ts}-{name}"
        directory = self.recordings_root / session_id

        subscribe_errors: dict[str, str] = {}
        good_uuids: list[str] = []
        for u in uuids:
            try:
                self.subscribe(u)
                good_uuids.append(u)
            except Exception as exc:
                subscribe_errors[_norm(u)] = str(exc)

        if not good_uuids:
            raise RuntimeError(
                f"could not subscribe to any of the given UUIDs: {subscribe_errors}"
            )

        session = _RecordingSession(session_id, good_uuids, directory, idle_timeout_s)
        session.open()

        with self._lock:
            for u in session.uuids:
                self._notify_callbacks.setdefault(u, []).append(session.write)
            self._sessions[session_id] = session

        trigger_result: Optional[dict[str, Any]] = None
        if trigger:
            char = trigger.get("char")
            data_hex = trigger.get("hex")
            response = bool(trigger.get("response", False))
            if not char or data_hex is None:
                raise ValueError("trigger requires 'char' and 'hex'")
            try:
                payload = bytes.fromhex(str(data_hex).replace(" ", ""))
            except ValueError as exc:
                raise ValueError(f"invalid trigger hex: {exc}")
            try:
                self.write(char, payload, response=response)
                trigger_result = {"char": char, "hex": payload.hex(), "ok": True}
            except Exception as exc:
                trigger_result = {
                    "char": char,
                    "hex": payload.hex(),
                    "ok": False,
                    "error": str(exc),
                }

        status = session.status()
        status["subscribe_errors"] = subscribe_errors
        if trigger_result is not None:
            status["trigger"] = trigger_result
        return status

    def recording_status(self, session_id: str) -> dict[str, Any]:
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"no recording session '{session_id}'")
        return session.status()

    def stop_recording(self, session_id: str) -> dict[str, Any]:
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"no recording session '{session_id}'")
        with self._lock:
            for u in session.uuids:
                callbacks = self._notify_callbacks.get(u)
                if callbacks and session.write in callbacks:
                    callbacks.remove(session.write)
        return session.close()

    def list_recordings(self) -> list[dict[str, Any]]:
        return [s.status() for s in self._sessions.values()]

    # ---------- Nuna pendant: live audio ----------

    def nuna_connect_and_start(
        self,
        address: Optional[str] = None,
        name_substr: str = "nuna",
        scan_seconds: float = 12.0,
        pair: bool = False,
        force_reconnect: bool = False,
        verification_code: str = HARDCODED_VERIFY,
        device_uuid: Optional[str] = None,
        account_code: int = 0,
        handshake_timeout_s: float = 5.0,
    ) -> dict[str, Any]:
        """Connect to a Nuna pendant and execute the full reverse-engineered
        handshake from the Android app, then enable live audio.

        Flow (matches `BluetoothService` + `HandshakeManager.startHandshake`):
          1. Connect (scanning if no address given), bond if pair=True.
          2. Subscribe to A001 (status), A002 (transfer), A003 (recording).
          3. Send HANDSHAKE_REQUEST on A002 with 27-byte body:
                [0]      = 0x01 (HANDSHAKE_REQUEST)
                [1..7]   = `verification_code` (UTF-8, NUL-padded to 6)
                [7..23]  = `device_uuid` 16 bytes (any stable client UUID)
                [23..27] = `account_code` uint32 LE
          4. Wait for HANDSHAKE_RESPONSE: device echoes the 6 bytes back.
          5. If they match, send HANDSHAKE_COMPLETED on A002.
          6. Send AUDIO_RECORDING_SWITCH=1 on A002.
          7. Audio frames stream as AUDIO_RECORDING_DATA on A003.
        """
        return self._submit(
            self._nuna_connect_and_start(
                address=address,
                name_substr=name_substr,
                scan_seconds=scan_seconds,
                pair=pair,
                force_reconnect=force_reconnect,
                verification_code=verification_code,
                device_uuid=device_uuid,
                account_code=account_code,
                handshake_timeout_s=handshake_timeout_s,
            ),
            timeout=scan_seconds + handshake_timeout_s + 30,
        )

    def nuna_stop(self, force: bool = False) -> dict[str, Any]:
        return self._submit(self._nuna_stop(force=force), timeout=15)

    def nuna_status(self) -> dict[str, Any]:
        active = next(
            (s for s in self._nuna_sessions.values() if not s.stopped), None
        )
        return {
            "active": active.status() if active else None,
            "sessions": [s.status() for s in self._nuna_sessions.values()],
        }

    def nuna_try_mmwave(self) -> dict[str, Any]:
        """Sanity probe: enable MILE_WAVE_SWITCH=1 on the existing client and
        watch for any SENSOR_DATA notification. If even mmWave is silent, the
        device universally requires the verification handshake before it'll
        emit anything."""
        return self._submit(self._nuna_try_mmwave(), timeout=10)

    def nuna_make_ogg(
        self,
        session_id: str,
        channels: int = 1,
        input_sample_rate: int = 16000,
        samples_per_frame: int = 960,
    ) -> dict[str, Any]:
        """Mux the captured raw Opus packets into a proper OGG-Opus file
        (RFC 7845). The device emits raw Opus; AudioFrameHandler in the
        official app appends them to a `*_continuous.opus` file but never
        wraps them, so they're not directly playable. We add a minimal
        OpusHead + OpusTags + framed pages so the result plays in VLC,
        ffmpeg, etc."""
        session = self._nuna_sessions.get(session_id)
        if session is None:
            raise KeyError(f"no nuna session '{session_id}'")

        packets: list[bytes] = []
        with session.opus_packets_path.open("rb") as f:
            while True:
                lenb = f.read(4)
                if len(lenb) < 4:
                    break
                (plen,) = struct.unpack("<I", lenb)
                pkt = f.read(plen)
                if len(pkt) < plen:
                    break
                f.read(8)  # discard per-packet timestamp
                if pkt:
                    packets.append(pkt)
        if not packets:
            raise RuntimeError(
                f"no opus packets captured in session '{session_id}'"
            )

        ogg_path = session.dir / "audio.ogg"
        ogg_bytes = _build_ogg_opus(
            packets,
            channels=channels,
            input_sample_rate=input_sample_rate,
            samples_per_frame=samples_per_frame,
        )
        ogg_path.write_bytes(ogg_bytes)
        duration_s = (len(packets) * samples_per_frame) / 48000.0
        return {
            "path": str(ogg_path),
            "packets": len(packets),
            "channels": channels,
            "input_sample_rate": input_sample_rate,
            "samples_per_frame": samples_per_frame,
            "approx_duration_s": duration_s,
            "bytes_written": len(ogg_bytes),
        }

    nuna_make_wav = nuna_make_ogg  # backward-compat alias for older clients

    def _watch_idle_sessions(self) -> None:
        while True:
            time.sleep(0.5)
            now = time.time()
            for session in list(self._sessions.values()):
                if session.stopped or session.idle_timeout_s is None:
                    continue
                last = session.last_packet_at
                if last is None:
                    continue
                if now - last >= session.idle_timeout_s:
                    try:
                        self.stop_recording(session.id)
                    except Exception:
                        pass

    # ---------- SSE pub/sub for notifications ----------

    def add_subscriber(self) -> Queue:
        q: Queue = Queue(maxsize=4096)
        with self._lock:
            self._subscribers.append(q)
        return q

    def remove_subscriber(self, q: Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def _publish(self, event: dict[str, Any]) -> None:
        with self._lock:
            dead: list[Queue] = []
            for q in self._subscribers:
                try:
                    q.put_nowait(event)
                except Exception:
                    dead.append(q)
            for q in dead:
                self._subscribers.remove(q)

    # ---------- async implementations ----------

    async def _nuna_connect_and_start(
        self,
        address: Optional[str],
        name_substr: str,
        scan_seconds: float,
        pair: bool = False,
        force_reconnect: bool = False,
        verification_code: str = HARDCODED_VERIFY,
        device_uuid: Optional[str] = None,
        account_code: int = 0,
        handshake_timeout_s: float = 5.0,
    ) -> dict[str, Any]:
        active = next(
            (s for s in self._nuna_sessions.values() if not s.stopped), None
        )
        if active is not None:
            if force_reconnect:
                await self._nuna_stop(force=True)
            else:
                raise RuntimeError(
                    f"a Nuna session is already active ({active.id}). "
                    f"Stop it first, or check 'force reconnect' to clear it."
                )

        def evt(name: str, **kwargs: Any) -> None:
            self._publish({"type": "nuna_event", "name": name, "ts": time.time(), **kwargs})

        evt("build_v5_switch_record")

        if force_reconnect and self._client is not None and self._client.is_connected:
            evt("force_disconnect")
            try:
                await self._client.disconnect()
            except Exception:
                pass
            self._client = None
            self._connected_address = None
            self._connected_name = None
            self._subscribed.clear()
            with self._lock:
                self._notify_callbacks.clear()

        if self._client is None or not self._client.is_connected:
            target: Any = address
            if not target:
                found: dict[str, Any] = {"d": None}
                done = asyncio.Event()

                def cb(d: BLEDevice, adv: AdvertisementData) -> None:
                    n = d.name or adv.local_name or ""
                    if name_substr.lower() in n.lower() and not found["d"]:
                        found["d"] = d
                        done.set()

                scanner = BleakScanner(detection_callback=cb)
                await scanner.start()
                try:
                    await asyncio.wait_for(done.wait(), scan_seconds)
                except asyncio.TimeoutError:
                    pass
                finally:
                    await scanner.stop()
                if found["d"] is None:
                    raise RuntimeError(
                        f"Nuna not found by name~{name_substr!r}. Power-cycle "
                        f"the device, or click Connect first if you already have "
                        f"its address."
                    )
                target = found["d"]

            evt("connecting", pair=pair)
            self._client = BleakClient(target, timeout=20.0, pair=pair)
            await self._client.connect()
            evt("connected", mtu=getattr(self._client, "mtu_size", None))
            self._connected_address = (
                target.address if hasattr(target, "address") else str(target)
            )
            self._connected_name = getattr(target, "name", None) or "nuna"
            self._subscribed.clear()
            with self._lock:
                self._notify_callbacks.clear()
        else:
            evt("reusing_existing_client", address=self._connected_address)

        ts = time.strftime("%Y%m%d-%H%M%S")
        session_id = f"nuna-{ts}-{uuidlib.uuid4().hex[:6]}"
        directory = self.recordings_root / session_id
        nsession = _NunaSession(session_id, directory, verification_code)
        nsession.handshake_event = asyncio.Event()

        publish = self._publish

        def _on_nuna(_uuid: str, payload: bytes) -> None:
            publish({
                "type": "nuna_raw", "uuid": _uuid, "ts": time.time(),
                "hex": payload.hex(), "len": len(payload),
            })
            nsession.feed_notify(_uuid, payload, publish)

        nsession._notify_cb = _on_nuna  # type: ignore[attr-defined]
        with self._lock:
            for u in NUNA_NOTIFY_CHARS:
                self._notify_callbacks.setdefault(_norm(u), []).append(_on_nuna)
            self._nuna_sessions[session_id] = nsession

        # Subscribe to all 3 notify chars in the order the Android app does:
        # STATUS (A001) -> TRANSFER (A002) -> RECORDING (A003).
        for u, label in (
            (NUNA_STATUS, "subscribed_a001_status"),
            (NUNA_TRANSFER, "subscribed_a002_transfer"),
            (NUNA_RECORDING, "subscribed_a003_recording"),
        ):
            try:
                await self._subscribe(u)
                evt(label)
            except Exception as exc:
                evt(f"{label}_err", error=str(exc))

        # 1) HANDSHAKE_REQUEST
        req_pkt = handshake_request_packet(
            verification_code=verification_code,
            device_uuid=device_uuid,
            account_code=account_code,
        )
        evt("handshake_request_send", hex=req_pkt.hex(), code=verification_code)
        try:
            await self._client.write_gatt_char(NUNA_TRANSFER, req_pkt, response=True)
        except Exception as exc:
            evt("handshake_request_err", error=str(exc))
            raise

        # 2) wait for HANDSHAKE_RESPONSE / HANDSHAKE_ERROR
        try:
            await asyncio.wait_for(
                nsession.handshake_event.wait(), timeout=handshake_timeout_s
            )
        except asyncio.TimeoutError:
            evt("handshake_timeout", waited_s=handshake_timeout_s)

        if nsession.handshake_error_code is not None:
            evt(
                "handshake_aborted",
                error_code=nsession.handshake_error_code,
            )
        elif nsession.handshake_response_match:
            # 3) HANDSHAKE_COMPLETED
            done_pkt = handshake_completed_packet()
            try:
                await self._client.write_gatt_char(NUNA_TRANSFER, done_pkt, response=True)
                nsession.handshake_completed_sent = True
                evt("handshake_completed_sent", hex=done_pkt.hex())
            except Exception as exc:
                evt("handshake_completed_err", error=str(exc))
        elif nsession.handshake_response_value is not None:
            evt(
                "handshake_mismatch",
                got=nsession.handshake_response_value,
                want=verification_code,
            )

        # 4) Mirror `HandshakeManager.completeHandshake` exactly: setTime, then
        # read STATUS_CHAR. The official app sends these unconditionally after
        # HANDSHAKE_COMPLETED — skipping them seems to leave the firmware in a
        # state where it accepts switches but never streams audio data.
        await asyncio.sleep(0.1)
        if nsession.handshake_completed_sent:
            cmd_id = nsession.next_command_id()
            ts_ms = int(time.time() * 1000)
            set_time_pkt = nuna_set_time_packet(ts_ms, command_id=cmd_id)
            try:
                await self._client.write_gatt_char(
                    NUNA_TRANSFER, set_time_pkt, response=True
                )
                nsession.set_time_sent = True
                evt("set_time_sent", hex=set_time_pkt.hex(), cmd_id=cmd_id, ts_ms=ts_ms)
            except Exception as exc:
                evt("set_time_err", error=str(exc))

            try:
                status_bytes = bytes(await self._client.read_gatt_char(NUNA_STATUS))
                nsession.status_read_value = status_bytes.hex()
                evt("status_read", hex=status_bytes.hex(), len=len(status_bytes))
            except Exception as exc:
                evt("status_read_err", error=str(exc))

        # 5) NOW enable live audio streaming the way the app does:
        # CONTROL_REQUEST + ControlCommand.SWITCH_RECORD = 3, payload [0x01].
        # (Writing top-level AUDIO_RECORDING_SWITCH = 17 is silently ignored;
        # that opcode is the device->app state echo, not a setter.)
        await asyncio.sleep(0.15)
        cmd_id = nsession.next_command_id()
        switch_pkt = nuna_switch_record_packet(True, command_id=cmd_id)
        try:
            await self._client.write_gatt_char(
                NUNA_TRANSFER, switch_pkt, response=True
            )
            nsession.switch_record_sent = True
            evt("switch_record_on_sent", hex=switch_pkt.hex(), cmd_id=cmd_id)
        except Exception as exc:
            evt("switch_record_err", error=str(exc))

        # heartbeat task (matches the official app cadence)
        async def _heartbeat() -> None:
            while True:
                await asyncio.sleep(5.0)
                if self._client is None or not self._client.is_connected:
                    break
                if nsession.stopped:
                    break
                try:
                    await self._client.write_gatt_char(
                        NUNA_TRANSFER, nuna_heartbeat(), response=False
                    )
                except Exception:
                    break

        nsession._hb_task = asyncio.create_task(_heartbeat())  # type: ignore[attr-defined]
        return nsession.status()

    async def _nuna_try_mmwave(self) -> dict[str, Any]:
        from nuna_protocol import enable_milewave as _enable_mw
        if self._client is None or not self._client.is_connected:
            raise RuntimeError("not connected; click Connect first")

        def evt(name: str, **kwargs: Any) -> None:
            self._publish({"type": "nuna_event", "name": name, "ts": time.time(), **kwargs})

        # ensure A001 is subscribed so any SENSOR_DATA frames hit our SSE
        await self._subscribe(NUNA_NOTIFY)
        evt("mmwave_subscribed_a001")

        bytes_seen_before = 0  # note: this is global notify volume, OK for a probe
        try:
            await self._client.write_gatt_char(NUNA_WRITE, _enable_mw(True), response=True)
            evt("mmwave_enabled", packet_hex=_enable_mw(True).hex())
        except Exception as exc:
            evt("mmwave_enable_err", error=str(exc))
            raise

        await asyncio.sleep(2.0)

        # Read state again
        state = {}
        for u in (
            "0000a001-0000-1000-8000-00805f9b34fb",
            "0000f001-0000-1000-8000-00805f9b34fb",
            "0000f002-0000-1000-8000-00805f9b34fb",
        ):
            try:
                state[u[4:8]] = bytes(await self._client.read_gatt_char(u)).hex()
            except Exception as exc:
                state[u[4:8]] = f"err:{exc}"
        evt("mmwave_post_state", state=state)

        # disable again so we don't leave it streaming
        try:
            await self._client.write_gatt_char(NUNA_WRITE, _enable_mw(False), response=True)
        except Exception:
            pass
        return {"state_after": state}

    async def _nuna_stop(self, force: bool = False) -> dict[str, Any]:
        active = next(
            (s for s in self._nuna_sessions.values() if not s.stopped), None
        )
        if active is None:
            return {"stopped": True, "active": None}

        errors: list[str] = []

        # disable audio (best-effort, bounded). Skipped entirely if force=True
        # so a wedged GATT layer can't keep us from cleaning up.
        if not force and self._client is not None and self._client.is_connected:
            try:
                cmd_id = active.next_command_id()
                off_pkt = nuna_switch_record_packet(False, command_id=cmd_id)
                await asyncio.wait_for(
                    self._client.write_gatt_char(NUNA_WRITE, off_pkt, response=True),
                    timeout=2.0,
                )
            except (Exception, asyncio.CancelledError) as exc:
                errors.append(f"disable_audio: {exc!r}")

        # cancel heartbeat. Note: awaiting a cancelled task re-raises
        # CancelledError, which is BaseException in 3.8+, so a plain
        # `except Exception` will NOT catch it.
        hb = getattr(active, "_hb_task", None)
        if hb is not None:
            hb.cancel()
            try:
                await asyncio.wait_for(hb, timeout=1.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
            except Exception as exc:
                errors.append(f"hb_cancel: {exc!r}")

        cb = getattr(active, "_notify_cb", None)
        if cb is not None:
            with self._lock:
                for u in NUNA_NOTIFY_CHARS:
                    callbacks = self._notify_callbacks.get(_norm(u), [])
                    if cb in callbacks:
                        callbacks.remove(cb)

        manifest = active.close()
        if errors:
            manifest["stop_errors"] = errors
        return manifest

    async def _scan(self, seconds: float) -> list[dict[str, Any]]:
        found: dict[str, dict[str, Any]] = {}

        def _on_detect(device: BLEDevice, adv: AdvertisementData) -> None:
            found[device.address] = {
                "address": device.address,
                "name": device.name or adv.local_name,
                "rssi": adv.rssi,
                "service_uuids": list(adv.service_uuids or []),
                "manufacturer_data": {
                    str(k): v.hex() for k, v in (adv.manufacturer_data or {}).items()
                },
            }

        scanner = BleakScanner(detection_callback=_on_detect)
        await scanner.start()
        try:
            await asyncio.sleep(seconds)
        finally:
            await scanner.stop()
        return list(found.values())

    async def _connect(self, address: str, timeout: float) -> dict[str, Any]:
        if self._client is not None and self._client.is_connected:
            await self._client.disconnect()
        self._client = BleakClient(address, timeout=timeout)
        await self._client.connect()
        self._connected_address = address
        try:
            self._connected_name = getattr(self._client, "_device_info", {}).get(
                "Name"
            )
        except Exception:
            self._connected_name = None
        self._subscribed.clear()
        with self._lock:
            self._notify_callbacks.clear()
        return self.status()

    async def _disconnect(self) -> dict[str, Any]:
        for session in list(self._sessions.values()):
            if not session.stopped:
                try:
                    self.stop_recording(session.id)
                except Exception:
                    pass
        if self._client is not None:
            try:
                for char_uuid in list(self._subscribed):
                    try:
                        await self._client.stop_notify(char_uuid)
                    except Exception:
                        pass
                await self._client.disconnect()
            finally:
                self._client = None
                self._connected_address = None
                self._connected_name = None
                self._subscribed.clear()
                with self._lock:
                    self._notify_callbacks.clear()
        return self.status()

    def _require_client(self) -> BleakClient:
        if self._client is None or not self._client.is_connected:
            raise RuntimeError("Not connected. Call /api/connect first.")
        return self._client

    async def _services(self) -> list[dict[str, Any]]:
        client = self._require_client()
        out: list[dict[str, Any]] = []
        for service in client.services:
            chars: list[dict[str, Any]] = []
            for char in service.characteristics:
                chars.append(
                    {
                        "uuid": char.uuid,
                        "handle": char.handle,
                        "properties": list(char.properties),
                        "descriptors": [
                            {"uuid": d.uuid, "handle": d.handle}
                            for d in char.descriptors
                        ],
                    }
                )
            out.append(
                {
                    "uuid": service.uuid,
                    "handle": service.handle,
                    "description": service.description,
                    "characteristics": chars,
                }
            )
        return out

    async def _read(self, char_uuid: str) -> dict[str, Any]:
        client = self._require_client()
        data = await client.read_gatt_char(char_uuid)
        return {
            "uuid": char_uuid,
            "hex": data.hex(),
            "bytes": list(data),
            "utf8": _safe_utf8(data),
            "len": len(data),
        }

    async def _read_all_readable(self) -> dict[str, Any]:
        """Read every characteristic that advertises the 'read' property.
        Useful for sniffing metadata (file size, format, name, version, etc.).
        """
        client = self._require_client()
        results: list[dict[str, Any]] = []
        for service in client.services:
            for char in service.characteristics:
                if "read" not in char.properties:
                    continue
                entry: dict[str, Any] = {
                    "service": service.uuid,
                    "service_description": service.description,
                    "uuid": char.uuid,
                    "properties": list(char.properties),
                }
                try:
                    data = await client.read_gatt_char(char)
                    entry.update(
                        {
                            "hex": bytes(data).hex(),
                            "len": len(data),
                            "utf8": _safe_utf8(bytes(data)),
                            "le_u16": (
                                int.from_bytes(data[:2], "little") if len(data) >= 2 else None
                            ),
                            "le_u32": (
                                int.from_bytes(data[:4], "little") if len(data) >= 4 else None
                            ),
                        }
                    )
                except Exception as exc:
                    entry["error"] = str(exc)
                results.append(entry)
        return {"count": len(results), "values": results}

    async def _write(
        self, char_uuid: str, data: bytes, response: bool
    ) -> dict[str, Any]:
        client = self._require_client()
        await client.write_gatt_char(char_uuid, data, response=response)
        return {"uuid": char_uuid, "wrote": len(data), "response": response}

    async def _subscribe(self, char_uuid: str) -> dict[str, Any]:
        client = self._require_client()
        u = _norm(char_uuid)
        if u in self._subscribed:
            return {"uuid": u, "subscribed": True, "already": True}

        def _callback(char: BleakGATTCharacteristic, data: bytearray) -> None:
            payload = bytes(data)
            cuuid = _norm(char.uuid)
            self._publish(
                {
                    "type": "notify",
                    "uuid": cuuid,
                    "ts": time.time(),
                    "hex": payload.hex(),
                    "bytes": list(payload),
                    "utf8": _safe_utf8(payload),
                    "len": len(payload),
                }
            )
            with self._lock:
                callbacks = list(self._notify_callbacks.get(cuuid, []))
            for cb in callbacks:
                try:
                    cb(cuuid, payload)
                except Exception:
                    pass

        await client.start_notify(char_uuid, _callback)
        self._subscribed.add(u)
        return {"uuid": u, "subscribed": True}

    async def _unsubscribe(self, char_uuid: str) -> dict[str, Any]:
        client = self._require_client()
        u = _norm(char_uuid)
        if u not in self._subscribed:
            return {"uuid": u, "subscribed": False, "already": True}
        await client.stop_notify(char_uuid)
        self._subscribed.discard(u)
        return {"uuid": u, "subscribed": False}


def _safe_utf8(data: bytes) -> Optional[str]:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any(ord(c) < 9 or (13 < ord(c) < 32) for c in text):
        return None
    return text


# --- OGG-Opus muxer (RFC 7845) -------------------------------------------
# Pure-Python: just enough to wrap raw Opus packets into a playable .ogg.

def _ogg_crc32(data: bytes) -> int:
    """Ogg's CRC-32 polynomial 0x04c11db7, no reflection, no inversion."""
    crc = 0
    for b in data:
        crc ^= b << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = ((crc << 1) ^ 0x04C11DB7) & 0xFFFFFFFF
            else:
                crc = (crc << 1) & 0xFFFFFFFF
    return crc


def _ogg_page(
    *,
    serial: int,
    sequence: int,
    granule: int,
    header_type: int,
    packets: list[bytes],
) -> bytes:
    """Build one Ogg page. Each packet is split into 255-byte lacing values
    with a final value < 255 to mark end-of-packet."""
    segment_table = bytearray()
    body = bytearray()
    for pkt in packets:
        n_full, rem = divmod(len(pkt), 255)
        segment_table.extend(b"\xff" * n_full)
        segment_table.append(rem)
        body.extend(pkt)
        if len(segment_table) > 255:
            raise ValueError("packet group too large for one Ogg page")
    header = bytearray()
    header += b"OggS"                                  # capture pattern
    header.append(0)                                   # version
    header.append(header_type)                         # header type flags
    header += struct.pack("<q", granule)               # granule position (i64)
    header += struct.pack("<I", serial)                # bitstream serial
    header += struct.pack("<I", sequence)              # page sequence
    header += b"\x00\x00\x00\x00"                      # CRC placeholder
    header.append(len(segment_table))                  # number of segments
    header += bytes(segment_table)
    page = bytes(header) + bytes(body)
    crc = _ogg_crc32(page)
    return page[:22] + struct.pack("<I", crc) + page[26:]


def _build_ogg_opus(
    packets: list[bytes],
    *,
    channels: int = 1,
    input_sample_rate: int = 16000,
    samples_per_frame: int = 960,
    serial: int = 0xCAFEBABE,
) -> bytes:
    pre_skip = 0
    output_gain = 0
    mapping_family = 0
    opus_head = (
        b"OpusHead"
        + bytes([1, channels])
        + struct.pack("<H", pre_skip)
        + struct.pack("<I", input_sample_rate)
        + struct.pack("<h", output_gain)
        + bytes([mapping_family])
    )
    vendor = b"ble-api-server / nuna"
    opus_tags = (
        b"OpusTags"
        + struct.pack("<I", len(vendor))
        + vendor
        + struct.pack("<I", 0)
    )

    out = bytearray()
    # BOS page with OpusHead
    out += _ogg_page(
        serial=serial, sequence=0, granule=0, header_type=0x02, packets=[opus_head]
    )
    # Tags page
    out += _ogg_page(
        serial=serial, sequence=1, granule=0, header_type=0x00, packets=[opus_tags]
    )
    # one packet per page (simple, always fits even for jumbo packets)
    granule = 0
    seq = 2
    for i, pkt in enumerate(packets):
        granule += samples_per_frame
        eos = 0x04 if i == len(packets) - 1 else 0x00
        out += _ogg_page(
            serial=serial, sequence=seq, granule=granule,
            header_type=eos, packets=[pkt],
        )
        seq += 1
    return bytes(out)
