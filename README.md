# BLE API Server

A small Flask + [bleak](https://github.com/hbldh/bleak) server that scans, connects, reads, writes,
and **streams notifications** from a BLE peripheral over an HTTP API. Includes a tiny browser UI
at `/` for quick testing.

Works on macOS, Linux, and Windows. On macOS the OS will prompt for Bluetooth permission the first
time you scan — grant it.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5055 — scan, click a device row to connect, refresh services, paste a
characteristic UUID, then Subscribe to start streaming notifications into the page.

Configure with env vars: `HOST` (default `127.0.0.1`), `PORT` (default `5055`).

> **macOS gotcha:** port `5000` is squatted by **AirPlay Receiver** which returns HTTP 403 for
> anything that isn't AirPlay. That's why this server defaults to **5055**. If you'd rather use
> 5000, disable AirPlay Receiver in *System Settings → General → AirDrop & Handoff*.

## API

| Method | Path                | Body / query                             | Notes                                  |
|-------:|---------------------|------------------------------------------|----------------------------------------|
| GET    | `/api/status`       | —                                        | Current connection state               |
| GET    | `/api/scan`         | `?seconds=5` (1–30)                      | Scans for nearby BLE devices           |
| POST   | `/api/connect`      | `{"address":"AA:BB:CC:DD:EE:FF"}`        | macOS uses a CoreBluetooth UUID here   |
| POST   | `/api/disconnect`   | —                                        |                                        |
| GET    | `/api/services`     | —                                        | Lists services + characteristics       |
| GET    | `/api/read`         | `?char=<uuid>`                           | One-shot read                          |
| POST   | `/api/write`        | `{"char":"<uuid>","hex":"01ff"}` or `{"text":"..."}` or `{"bytes":[1,255]}` | optional `"response": false` |
| POST   | `/api/subscribe`    | `{"char":"<uuid>"}`                      | Start GATT notifications               |
| POST   | `/api/unsubscribe`  | `{"char":"<uuid>"}`                      |                                        |
| GET    | `/api/stream`       | —                                        | Server-Sent Events stream of notifies  |

### Stream event shape

```json
{ "type": "notify", "uuid": "0000xxxx-...", "ts": 1718465123.42,
  "hex": "0102ff", "bytes": [1,2,255], "utf8": null, "len": 3 }
```

## curl examples

```bash
curl 'http://127.0.0.1:5000/api/scan?seconds=5'
curl -XPOST -H 'content-type: application/json' \
  -d '{"address":"AA:BB:CC:DD:EE:FF"}' http://127.0.0.1:5000/api/connect
curl http://127.0.0.1:5000/api/services
curl -XPOST -H 'content-type: application/json' \
  -d '{"char":"0000xxxx-0000-1000-8000-00805f9b34fb"}' http://127.0.0.1:5000/api/subscribe
curl -N http://127.0.0.1:5000/api/stream
```

## Capturing an audio / file transfer

For devices that stream audio or a stored file over a vendor characteristic, use the capture
pipeline. It subscribes to one or more notify characteristics, optionally writes a "trigger"
command first, then records every packet to per-characteristic `.bin` files. It auto-stops
after the device goes idle.

### Workflow

1. **Probe metadata.** Click *Read all readable* in the UI (or `GET /api/read-all`). Many
   devices encode file size, sample rate, codec, and model name in read-only characteristics
   — this is the fastest way to find them.

2. **Start a capture.** In the *Capture audio / file* panel, paste the notify UUIDs you want
   to record (defaults are pre-filled with the three on `0000a000-...`). Optionally set a
   trigger command: write `hex` to the device's command characteristic to kick off the
   transfer. Click *Start capture*.

3. **Stop.** Either click *Stop*, or let the idle auto-stop fire after `idle_ms` of silence
   (default 3 s).

4. **Wrap as WAV.** If the data is uncompressed PCM, click a captured file's *Use for WAV*
   button, set sample rate / channels / sample width to match the device, and click *Make
   WAV*. If the device uses a codec (Opus, ADPCM, IMA, etc.) the raw `.bin` is what you want
   — feed it to the appropriate decoder.

### Audio-capture API

```bash
curl -XPOST -H 'content-type: application/json' \
  -d '{
        "uuids": [
          "0000a001-0000-1000-8000-00805f9b34fb",
          "0000a002-0000-1000-8000-00805f9b34fb",
          "0000a003-0000-1000-8000-00805f9b34fb"
        ],
        "idle_ms": 3000,
        "trigger": { "char": "0000a002-0000-1000-8000-00805f9b34fb", "hex": "01" }
      }' \
  http://127.0.0.1:5000/api/record/start

curl 'http://127.0.0.1:5000/api/record/status?id=<session-id>'

curl -XPOST -H 'content-type: application/json' \
  -d '{ "id": "<session-id>" }' \
  http://127.0.0.1:5000/api/record/stop

curl -XPOST -H 'content-type: application/json' \
  -d '{ "file": "/abs/path/recordings/<session-id>/0000a002-...bin",
        "sample_rate": 16000, "channels": 1, "sample_width": 2 }' \
  http://127.0.0.1:5000/api/record/wav
```

Recordings live under `RECORDINGS_DIR` (default `./recordings/<session-id>/`). Every session
also gets a `manifest.json` with byte counts, packet counts, and the open/close timestamps.

### Identifying the right characteristic

Without vendor docs you have to fingerprint the device. Useful heuristics:

- The characteristic whose **packet rate spikes after the trigger write** is the data channel.
- Packets that look like 20-byte chunks at high rate ≈ raw audio frames over MTU=23.
- Packets that look like ASCII headers (`utf8` populated in the SSE stream) are control replies.
- A characteristic that emits one short notify and then goes quiet is likely a status channel.

Subscribe to all candidates at once via the capture panel; whichever file ends up large is the
audio channel. The smaller files alongside it are probably control/ack frames.

## Notes

- Notifications run inside the bleak event loop in a background thread; SSE subscribers receive
  every event via thread-safe queues. Multiple browser tabs can stream simultaneously.
- The Flask reloader is intentionally disabled so we don't spawn two BLE event loops.
- Single-device server. To support multiple peripherals, instantiate one `BleManager` per address.
