"""Flask API server exposing a BLE device over HTTP + SSE.

Endpoints:
  GET  /                       - simple test UI
  GET  /api/status             - connection status
  GET  /api/scan?seconds=5     - scan for nearby BLE devices
  POST /api/connect            - {"address": "..."} connect to device
  POST /api/disconnect         - disconnect
  GET  /api/services           - GATT services + characteristics for connected device
  GET  /api/read?char=UUID     - read a characteristic once
  GET  /api/read-all           - read every readable characteristic (metadata sniffer)
  POST /api/write              - {"char": "UUID", "hex": "..."} or {"char","text"}
  POST /api/subscribe          - {"char": "UUID"} start notifications
  POST /api/unsubscribe        - {"char": "UUID"} stop notifications
  GET  /api/stream             - Server-Sent Events stream of notifications
  POST /api/record/start       - capture notifications from N chars to disk
  GET  /api/record/status?id=  - session stats
  POST /api/record/stop        - stop a session, return manifest
  GET  /api/record/list        - list known sessions
  POST /api/record/wav         - wrap a captured .bin file as PCM WAV
  GET  /api/record/file?path=  - download a captured file
"""

from __future__ import annotations

import json
import logging
import os
import wave
from pathlib import Path
from queue import Empty
from typing import Any

from flask import Flask, Response, jsonify, request, send_file, send_from_directory
from flask_cors import CORS

from ble_manager import BleManager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ble-api")

RECORDINGS_ROOT = Path(os.environ.get("RECORDINGS_DIR", "recordings")).resolve()
RECORDINGS_ROOT.mkdir(parents=True, exist_ok=True)

app = Flask(__name__, static_folder="static", static_url_path="/static")
CORS(app)
ble = BleManager(recordings_root=RECORDINGS_ROOT)


def _err(message: str, status: int = 400) -> Response:
    resp = jsonify({"error": message})
    resp.status_code = status
    return resp


def _under(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


@app.get("/")
def index() -> Response:
    return send_from_directory("static", "index.html")


@app.get("/api/status")
def status() -> Response:
    return jsonify(ble.status())


@app.get("/api/scan")
def scan() -> Response:
    try:
        seconds = float(request.args.get("seconds", "5"))
    except ValueError:
        return _err("seconds must be a number")
    seconds = max(1.0, min(seconds, 30.0))
    try:
        devices = ble.scan(seconds)
        return jsonify({"seconds": seconds, "devices": devices})
    except Exception as exc:
        log.exception("scan failed")
        return _err(f"scan failed: {exc}", 500)


@app.post("/api/connect")
def connect() -> Response:
    body: dict[str, Any] = request.get_json(silent=True) or {}
    address = body.get("address")
    if not address or not isinstance(address, str):
        return _err("address (string) is required")
    try:
        return jsonify(ble.connect(address))
    except Exception as exc:
        log.exception("connect failed")
        return _err(f"connect failed: {exc}", 500)


@app.post("/api/disconnect")
def disconnect() -> Response:
    try:
        return jsonify(ble.disconnect())
    except Exception as exc:
        log.exception("disconnect failed")
        return _err(f"disconnect failed: {exc}", 500)


@app.get("/api/services")
def services() -> Response:
    try:
        return jsonify({"services": ble.services()})
    except Exception as exc:
        return _err(str(exc), 400)


@app.get("/api/read")
def read() -> Response:
    char_uuid = request.args.get("char")
    if not char_uuid:
        return _err("char (UUID) query param required")
    try:
        return jsonify(ble.read(char_uuid))
    except Exception as exc:
        return _err(str(exc), 400)


@app.get("/api/read-all")
def read_all() -> Response:
    try:
        return jsonify(ble.read_all_readable())
    except Exception as exc:
        return _err(str(exc), 400)


@app.post("/api/write")
def write() -> Response:
    body = request.get_json(silent=True) or {}
    char_uuid = body.get("char")
    if not char_uuid:
        return _err("char (UUID) is required")
    response = bool(body.get("response", True))

    if "hex" in body and body["hex"] is not None:
        try:
            data = bytes.fromhex(str(body["hex"]).replace(" ", ""))
        except ValueError as exc:
            return _err(f"invalid hex: {exc}")
    elif "text" in body and body["text"] is not None:
        data = str(body["text"]).encode("utf-8")
    elif "bytes" in body and isinstance(body["bytes"], list):
        try:
            data = bytes(int(b) & 0xFF for b in body["bytes"])
        except (TypeError, ValueError) as exc:
            return _err(f"invalid bytes: {exc}")
    else:
        return _err("provide one of: hex, text, bytes")

    try:
        return jsonify(ble.write(char_uuid, data, response))
    except Exception as exc:
        return _err(str(exc), 400)


@app.post("/api/subscribe")
def subscribe() -> Response:
    body = request.get_json(silent=True) or {}
    char_uuid = body.get("char")
    if not char_uuid:
        return _err("char (UUID) is required")
    try:
        return jsonify(ble.subscribe(char_uuid))
    except Exception as exc:
        return _err(str(exc), 400)


@app.post("/api/unsubscribe")
def unsubscribe() -> Response:
    body = request.get_json(silent=True) or {}
    char_uuid = body.get("char")
    if not char_uuid:
        return _err("char (UUID) is required")
    try:
        return jsonify(ble.unsubscribe(char_uuid))
    except Exception as exc:
        return _err(str(exc), 400)


@app.post("/api/record/start")
def record_start() -> Response:
    body = request.get_json(silent=True) or {}
    uuids = body.get("uuids") or body.get("chars")
    if not isinstance(uuids, list) or not uuids:
        return _err("uuids (non-empty list) is required")
    idle_ms = body.get("idle_ms")
    idle_timeout_s = None if idle_ms in (None, 0, False) else max(0.1, float(idle_ms) / 1000)
    name = body.get("name")
    trigger = body.get("trigger") if isinstance(body.get("trigger"), dict) else None
    try:
        return jsonify(ble.start_recording(uuids, idle_timeout_s, name, trigger))
    except Exception as exc:
        log.exception("record start failed")
        return _err(str(exc), 400)


@app.get("/api/record/status")
def record_status() -> Response:
    session_id = request.args.get("id")
    if not session_id:
        return _err("id query param required")
    try:
        return jsonify(ble.recording_status(session_id))
    except KeyError as exc:
        return _err(str(exc), 404)
    except Exception as exc:
        return _err(str(exc), 400)


@app.post("/api/record/stop")
def record_stop() -> Response:
    body = request.get_json(silent=True) or {}
    session_id = body.get("id") or request.args.get("id")
    if not session_id:
        return _err("id is required")
    try:
        return jsonify(ble.stop_recording(session_id))
    except KeyError as exc:
        return _err(str(exc), 404)
    except Exception as exc:
        return _err(str(exc), 400)


@app.get("/api/record/list")
def record_list() -> Response:
    return jsonify({"sessions": ble.list_recordings()})


@app.post("/api/record/wav")
def record_wav() -> Response:
    """Wrap a raw PCM dump as a .wav file. Best-effort: only valid if the
    payload truly is uncompressed PCM at the given sample rate / width."""
    body = request.get_json(silent=True) or {}
    src = body.get("file")
    if not src:
        return _err("file (path to .bin) is required")
    src_path = Path(src).resolve()
    if not _under(src_path, RECORDINGS_ROOT):
        return _err("file must live inside the recordings directory", 400)
    if not src_path.exists():
        return _err(f"no such file: {src_path}", 404)

    sample_rate = int(body.get("sample_rate", 16000))
    channels = int(body.get("channels", 1))
    sample_width = int(body.get("sample_width", 2))
    if sample_width not in (1, 2, 3, 4):
        return _err("sample_width must be 1, 2, 3, or 4 bytes")
    skip_header = int(body.get("skip_header_bytes", 0))

    out = body.get("out")
    out_path = (
        Path(out).resolve() if out else src_path.with_suffix(".wav")
    )
    if not _under(out_path, RECORDINGS_ROOT):
        return _err("out must live inside the recordings directory", 400)

    raw = src_path.read_bytes()
    if skip_header:
        raw = raw[skip_header:]
    frame_size = sample_width * channels
    if len(raw) % frame_size:
        raw = raw[: (len(raw) // frame_size) * frame_size]

    try:
        with wave.open(str(out_path), "wb") as w:
            w.setnchannels(channels)
            w.setsampwidth(sample_width)
            w.setframerate(sample_rate)
            w.writeframes(raw)
    except Exception as exc:
        return _err(f"wav write failed: {exc}", 500)

    duration = (len(raw) // frame_size) / sample_rate if sample_rate > 0 else 0
    return jsonify(
        {
            "src": str(src_path),
            "out": str(out_path),
            "sample_rate": sample_rate,
            "channels": channels,
            "sample_width": sample_width,
            "frames": len(raw) // frame_size,
            "duration_s": duration,
            "bytes_written": len(raw),
        }
    )


@app.get("/api/record/file")
def record_file() -> Response:
    p = request.args.get("path")
    if not p:
        return _err("path query param required")
    abs_path = Path(p).resolve()
    if not _under(abs_path, RECORDINGS_ROOT):
        return _err("path must be inside recordings dir", 400)
    if not abs_path.exists():
        return _err("not found", 404)
    return send_file(abs_path, as_attachment=True)


@app.post("/api/nuna/start")
def nuna_start() -> Response:
    body = request.get_json(silent=True) or {}
    address = body.get("address")
    name = body.get("name", "nuna")
    scan_seconds = float(body.get("scan_seconds", 12))
    pair = bool(body.get("pair", False))
    force_reconnect = bool(body.get("force_reconnect", False))
    verification_code = body.get("verification_code") or "123456"
    device_uuid = body.get("device_uuid") or None
    account_code = int(body.get("account_code", 0))
    handshake_timeout_s = float(body.get("handshake_timeout_s", 5.0))
    try:
        return jsonify(
            ble.nuna_connect_and_start(
                address=address,
                name_substr=name,
                scan_seconds=scan_seconds,
                pair=pair,
                force_reconnect=force_reconnect,
                verification_code=verification_code,
                device_uuid=device_uuid,
                account_code=account_code,
                handshake_timeout_s=handshake_timeout_s,
            )
        )
    except BaseException as exc:
        log.exception("nuna start failed")
        return _err(f"{type(exc).__name__}: {exc}", 400)


@app.post("/api/nuna/stop")
def nuna_stop() -> Response:
    body = request.get_json(silent=True) or {}
    force = bool(body.get("force", False))
    try:
        return jsonify(ble.nuna_stop(force=force))
    except BaseException as exc:  # CancelledError is BaseException in 3.8+
        log.exception("nuna stop failed")
        return _err(f"{type(exc).__name__}: {exc}", 500)


@app.get("/api/nuna/status")
def nuna_status() -> Response:
    return jsonify(ble.nuna_status())


@app.post("/api/nuna/try-mmwave")
def nuna_try_mmwave() -> Response:
    try:
        return jsonify(ble.nuna_try_mmwave())
    except BaseException as exc:
        log.exception("mmwave probe failed")
        return _err(f"{type(exc).__name__}: {exc}", 400)


@app.post("/api/nuna/ogg")
def nuna_ogg() -> Response:
    """Mux captured raw Opus packets into a playable .ogg (RFC 7845)."""
    body = request.get_json(silent=True) or {}
    session_id = body.get("id")
    if not session_id:
        return _err("id is required")
    try:
        return jsonify(
            ble.nuna_make_ogg(
                session_id,
                channels=int(body.get("channels", 2)),
                input_sample_rate=int(body.get("input_sample_rate", 16000)),
                samples_per_frame=int(body.get("samples_per_frame", 960)),
            )
        )
    except KeyError as exc:
        return _err(str(exc), 404)
    except Exception as exc:
        return _err(str(exc), 400)


@app.route("/api/nuna/hr", methods=["GET"])
def api_nuna_hr() -> Response:
    import urllib.request
    try:
        req = urllib.request.Request("http://localhost:8080/hr")
        with urllib.request.urlopen(req, timeout=2.0) as response:
            return jsonify(json.loads(response.read().decode()))
    except Exception as e:
        return jsonify({"hr": None, "timestamp": None, "error": str(e)})


# Backward-compat: old UI calls /api/nuna/wav, route it to the new ogg muxer.
app.add_url_rule(
    "/api/nuna/wav", view_func=nuna_ogg, methods=["POST"], endpoint="nuna_wav_compat"
)


@app.get("/api/nuna/recorded")
def nuna_recorded() -> Response:
    """List previously-recorded Nuna sessions that have a playable
    audio.ogg on disk. Survives server restarts."""
    return jsonify({"sessions": ble.nuna_list_recorded()})


@app.get("/api/nuna/audio")
def nuna_audio() -> Response:
    """Stream a session's `audio.ogg` directly so the browser <audio>
    element can play it without round-tripping through /api/record/file.
    Set ?download=1 for an attachment download instead of inline playback."""
    session_id = request.args.get("id")
    if not session_id:
        return _err("id query param required")
    try:
        ogg_path = ble.nuna_audio_path(session_id)
    except KeyError as exc:
        return _err(str(exc), 404)
    if not ogg_path.exists():
        return _err(
            "audio.ogg not yet generated for this session — click Stop, "
            "or POST /api/nuna/ogg to mux it now",
            404,
        )
    if not _under(ogg_path, RECORDINGS_ROOT):
        return _err("audio path outside recordings dir", 400)

    as_attachment = request.args.get("download") in ("1", "true", "yes")
    download_name = f"{session_id}.ogg"
    return send_file(
        ogg_path,
        mimetype="audio/ogg",
        as_attachment=as_attachment,
        download_name=download_name,
        conditional=True,  # supports HTTP Range so seeking works
    )


@app.get("/api/stream")
def stream() -> Response:
    def event_source():
        q = ble.add_subscriber()
        # SSE preamble + heartbeat so proxies don't time out
        yield "retry: 2000\n\n"
        try:
            while True:
                try:
                    event = q.get(timeout=15)
                    yield f"data: {json.dumps(event)}\n\n"
                except Empty:
                    yield ": ping\n\n"
        finally:
            ble.remove_subscriber(q)

    return Response(
        event_source(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


def _kill_stale_servers() -> None:
    """Kill any earlier `app.py` instance still alive. Each such zombie keeps
    a BleakClient object around and so squats on the macOS Bluetooth radio,
    preventing fresh scans/connections from this same machine. Belt-and-suspenders.
    """
    import subprocess

    me = os.getpid()
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", "python.*app\\.py"], text=True, stderr=subprocess.DEVNULL
        )
    except Exception:
        return
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            pid = int(line)
        except ValueError:
            continue
        if pid == me:
            continue
        try:
            os.kill(pid, 9)
            log.warning("killed stale app.py pid=%d (was holding BLE radio)", pid)
        except ProcessLookupError:
            pass
        except PermissionError:
            log.warning("could not kill stale app.py pid=%d (permission denied)", pid)


if __name__ == "__main__":
    _kill_stale_servers()
    host = os.environ.get("HOST", "127.0.0.1")
    # Default 5055: macOS AirPlay Receiver squats on 5000 and returns HTTP 403
    # for anything that isn't AirPlay. Override with PORT=… if you've turned it off.
    port = int(os.environ.get("PORT", "5055"))
    if port == 5000:
        log.warning(
            "Port 5000 is used by macOS AirPlay Receiver and will return HTTP 403. "
            "Disable it in System Settings or pick another port via PORT=5055."
        )
    log.info("Open http://%s:%d in your browser", host, port)
    # threaded=True so SSE stream coexists with other requests; debug off because
    # the reloader spawns a second process which would create two BLE loops.
    app.run(host=host, port=port, threaded=True, debug=False)
