"""Nuna pendant BLE protocol — reverse-engineered from Nuna_1.9.1.apk
(`com.xthings.nuna` / `com.things.common.ble`).

GATT layout (ProtocolConfig.SERVICE):
  Service          : 0000A000-0000-1000-8000-00805F9B34FB
  STATUS_CHAR      : 0000A001-...   notify          (status: battery, hw, working state, sensor)
  TRANSFER_CHAR    : 0000A002-...   write + notify  (commands: handshake, control, switches, heartbeat)
  RECORDING_CHAR   : 0000A003-...   notify          (live audio frames)

Outer packet (`MessageBodyCreator.createMessage`, 7-byte header + payload):
  offset 0 : 0xAA                          magic
  offset 1 : type (uint8)                  MessageType
  offset 2 : length (uint16, little-endian)  payload length
  offset 4 : 0x01                          protocol version
  offset 5 : 0x34                          checksum lo (hard-coded 0x1234 LE)
  offset 6 : 0x12                          checksum hi
  offset 7 : payload[length]
  total    : length + 7

Handshake protocol (`HandshakeManager.startHandshake`, payload-side enum):
  HANDSHAKE_REQUEST   = 1 (app -> device)
  HANDSHAKE_RESPONSE  = 2 (device -> app, echoes 6-char verification code)
  HANDSHAKE_COMPLETED = 3 (app -> device, after match)
  HANDSHAKE_ERROR     = 4

  HANDSHAKE_REQUEST body, 27 bytes (`MessageBodyCreatorUtil.encodeHandshakeRequest`):
    [0]      = 0x01 (HANDSHAKE_REQUEST)
    [1..7]   = 6 ASCII bytes verification code, NUL-padded right
    [7..23]  = 16 bytes UUID of phone/client (uuidToBytes of `UUID.nameUUIDFromBytes(deviceId)`)
    [23..27] = uint32 LE accountCode (0)

The verification "code" is hard-coded `"123456"` in the decompiled Kotlin —
the device just echoes it, so any 6 ASCII bytes work as long as we send the
same value we expect back.

Audio frame body (`MessageBodyParserUtil.decodeAudioFrame`, comes inside
AUDIO_RECORDING_DATA messages on RECORDING_CHAR):
  [0..2]  frameId      uint16 LE   (logical "frame group" id; spans many Opus packets)
  [2..4]  frameSize    uint16 LE   (size of EACH individual Opus packet in bytes)
  [4]     chunkId      uint8       (0..totalChunks-1, BLE chunk index)
  [5]     totalChunks  uint8       (BLE chunks per frame group)
  [6..14] timestamp    uint64 LE   (ms epoch from device clock)
  [14..]  body         (payload for this BLE chunk)

The body of each BLE chunk is a sequence of `frameSize` back-to-back Opus
packets — NOT a fragment of one giant packet. Empirically every chunk we've
captured from real Nuna firmware is 480 bytes and `frameSize == 80`, so each
chunk carries 6 self-contained Opus packets of 80 B (CELT-WB 20 ms CBR @
32 kbps, TOC 0xbc). `AudioFrameHandler.saveOpusDataToFile` in the Android
app concatenates the chunk bodies and dumps them into a `*_continuous.opus`
file, which only happens to work because the file is then fed to the system
opus decoder *which auto-resyncs on TOC bytes* — that file is NOT a valid
single Opus packet. Use `extract_opus_packets()` below to slice the chunk
bodies into proper individual Opus packets that can be muxed into Ogg.
"""
from __future__ import annotations

import hashlib
import struct
import uuid
from enum import IntEnum
from typing import NamedTuple

# --- GATT identifiers ----------------------------------------------------

SERVICE_UUID = "0000a000-0000-1000-8000-00805f9b34fb"
CHAR_STATUS = "0000a001-0000-1000-8000-00805f9b34fb"      # notify (status)
CHAR_TRANSFER = "0000a002-0000-1000-8000-00805f9b34fb"    # write + notify (commands)
CHAR_RECORDING = "0000a003-0000-1000-8000-00805f9b34fb"   # notify (audio)

# Backward-compat aliases for code that imported the older names.
CHAR_NOTIFY = CHAR_STATUS
CHAR_WRITE = CHAR_TRANSFER

NOTIFY_CHARS = (CHAR_STATUS, CHAR_TRANSFER, CHAR_RECORDING)

# --- Wire constants ------------------------------------------------------

MAGIC = 0xAA
VERSION = 0x01
HEADER_LEN = 7
CHECKSUM = 0x1234   # MessageBodyCreator hard-codes this; not a real checksum
HARDCODED_VERIFY = "123456"


class MessageType(IntEnum):
    HANDSHAKE = 1
    WORKING_STATE = 2
    BATTERY_LEVEL = 3
    VIBRATION_INTENSITY = 4
    HARDWARE_INFO = 5
    CONTROL_REQUEST = 6
    CONTROL_RESPONSE = 7
    SENSOR_DATA = 8
    VIBRATION_RECORD = 9
    AUDIO_RECORDING_DATA = 16
    AUDIO_RECORDING_SWITCH = 17
    OFFLINE_AUDIO_DATA = 18
    MILE_WAVE_SWITCH = 19
    HEART_BEAT = 21


class HandshakeMessageType(IntEnum):
    HANDSHAKE_REQUEST = 1
    HANDSHAKE_RESPONSE = 2
    HANDSHAKE_COMPLETED = 3
    HANDSHAKE_ERROR = 4


class HandshakeErrorType(IntEnum):
    UNKNOWN = 0
    ALREADY_PAIRED_BY_ANOTHER_DEVICE = 1
    AES_CHECK_FAILED = 2
    INVALID_DATA = 3
    INTERNAL_ERROR = 4
    ALREADY_PAIRED_BY_ANOTHER_ACCOUNT = 5


class ControlMessageType(IntEnum):
    """Inner type byte that lives at the top of a CONTROL_REQUEST/RESPONSE
    payload. Matches `com.things.common.ble.mesaage.ControlMessageType`."""
    CONTROL_COMMAND = 6
    CONTROL_FEEDBACK = 7


class ControlCommand(IntEnum):
    """`com.things.common.ble.mesaage.ControlCommand`."""
    VIBRATE = 1
    SET_VIBRATION_INTENSITY = 2
    SWITCH_RECORD = 3        # <-- this is what actually enables live audio
    SET_TIME = 4
    SWITCH_MILE_WAVE = 5
    DEL_CACHE_DATA = 6
    MUSIC_VIBRATION = 7


# --- Outer packet builder / parser --------------------------------------

def build_packet(mtype: MessageType, payload: bytes = b"") -> bytes:
    if len(payload) > 0xFFFF:
        raise ValueError("payload too large")
    return (
        bytes([MAGIC, int(mtype)])
        + struct.pack("<H", len(payload))
        + bytes([VERSION])
        + struct.pack("<H", CHECKSUM)
        + payload
    )


# --- Handshake helpers --------------------------------------------------

def name_uuid_from_bytes(data: bytes) -> uuid.UUID:
    """Java `UUID.nameUUIDFromBytes`: MD5 + version-3 + variant bits."""
    digest = bytearray(hashlib.md5(data).digest())
    digest[6] = (digest[6] & 0x0F) | 0x30  # v3
    digest[8] = (digest[8] & 0x3F) | 0x80  # RFC 4122 variant
    return uuid.UUID(bytes=bytes(digest))


def encode_handshake_request(
    verification_code: str = HARDCODED_VERIFY,
    device_uuid: uuid.UUID | str | None = None,
    account_code: int = 0,
) -> bytes:
    """Mirror of `MessageBodyCreatorUtil.encodeHandshakeRequest`.

    `device_uuid` is the *client's* (phone's) identity UUID. The official app
    derives it from the Android device-id; we just need 16 stable bytes.
    """
    if device_uuid is None:
        device_uuid = name_uuid_from_bytes(b"ble-api-server")
    if isinstance(device_uuid, str):
        device_uuid = uuid.UUID(device_uuid)

    code = verification_code.encode("utf-8")[:6].ljust(6, b"\x00")
    body = bytearray(27)
    body[0] = HandshakeMessageType.HANDSHAKE_REQUEST
    body[1:7] = code
    body[7:23] = device_uuid.bytes
    struct.pack_into("<I", body, 23, account_code & 0xFFFFFFFF)
    return bytes(body)


def encode_handshake_completed() -> bytes:
    return bytes([HandshakeMessageType.HANDSHAKE_COMPLETED])


def encode_handshake_error() -> bytes:
    return bytes([HandshakeMessageType.HANDSHAKE_ERROR])


def handshake_request_packet(
    verification_code: str = HARDCODED_VERIFY,
    device_uuid: uuid.UUID | str | None = None,
    account_code: int = 0,
) -> bytes:
    return build_packet(
        MessageType.HANDSHAKE,
        encode_handshake_request(verification_code, device_uuid, account_code),
    )


def handshake_completed_packet() -> bytes:
    return build_packet(MessageType.HANDSHAKE, encode_handshake_completed())


# --- Control-request helpers --------------------------------------------
#
# The official app does NOT enable live audio by writing
# `MessageType.AUDIO_RECORDING_SWITCH` (= 17) — that opcode is reserved for
# the *device-to-app* state echo. Instead, `CommandManager.switchRecord(true)`
# writes a `MessageType.CONTROL_REQUEST` (= 6) packet whose payload is built
# by `MessageBodyCreatorUtil.encodeCmdMessage`:
#
#   [0..2] commandId  (uint16 BE — the app uses ByteBuffer's default order)
#   [2]    ControlCommand byte
#   [3..]  command payload
#
# Responses arrive on TRANSFER (A002) or STATUS (A001) wrapped in a
# `MessageType.CONTROL_RESPONSE` (= 7) packet whose body looks symmetric.

def encode_cmd_message(cmd: ControlCommand, command_id: int, payload: bytes = b"") -> bytes:
    """Mirror of `MessageBodyCreatorUtil.encodeCmdMessage` (Java).

    NOTE: the app uses ByteBuffer default order (BIG endian) for the
    command id. We match that byte-for-byte so the device sees exactly
    what the official client sends.
    """
    if not 0 <= command_id <= 0xFFFF:
        raise ValueError(f"command_id out of range: {command_id}")
    return struct.pack(">H", command_id) + bytes([int(cmd)]) + bytes(payload)


def control_request_packet(cmd: ControlCommand, command_id: int, payload: bytes = b"") -> bytes:
    """Build a full outer CONTROL_REQUEST packet for command `cmd`."""
    return build_packet(MessageType.CONTROL_REQUEST, encode_cmd_message(cmd, command_id, payload))


def switch_record_packet(on: bool, command_id: int) -> bytes:
    """`CommandManager.switchRecord(enable)` — toggle live audio streaming."""
    return control_request_packet(
        ControlCommand.SWITCH_RECORD, command_id, bytes([1 if on else 0])
    )


def set_time_packet(timestamp_ms: int, command_id: int) -> bytes:
    """`CommandManager.setTime(timestamp_ms)` — sync device clock.
    Payload is a uint64 LE millisecond epoch."""
    return control_request_packet(
        ControlCommand.SET_TIME, command_id, struct.pack("<Q", int(timestamp_ms) & 0xFFFFFFFFFFFFFFFF)
    )


def switch_milewave_packet(on: bool, command_id: int) -> bytes:
    """`CommandManager.switchMileWave(enable)` — preferred over the legacy
    type-19 single-byte write because real firmware gates it on the cmd id."""
    return control_request_packet(
        ControlCommand.SWITCH_MILE_WAVE, command_id, bytes([1 if on else 0])
    )


# --- Legacy single-byte switches (kept for back-compat / probing) -------

def enable_milewave(on: bool = True) -> bytes:
    """OLD path: top-level MILE_WAVE_SWITCH (= 19) with one byte body. The
    app actually uses `switch_milewave_packet` instead; keep this for
    backward compatibility with our own probing tools."""
    return build_packet(MessageType.MILE_WAVE_SWITCH, bytes([1 if on else 0]))


def enable_audio(on: bool = True) -> bytes:
    """OLD path: top-level AUDIO_RECORDING_SWITCH (= 17) with one byte body.
    THIS DOES NOT WORK on production firmware — it's the device->app echo
    opcode, not a setter. Use `switch_record_packet(on, command_id)` for
    real live-audio enable. Kept here only because old probe scripts import
    it."""
    return build_packet(MessageType.AUDIO_RECORDING_SWITCH, bytes([1 if on else 0]))


def heartbeat() -> bytes:
    return build_packet(MessageType.HEART_BEAT, b"")


def handshake(body: bytes = b"") -> bytes:
    """Backward-compat: build a HANDSHAKE outer packet around `body`."""
    return build_packet(MessageType.HANDSHAKE, body)


# --- Audio frame parser -------------------------------------------------

class AudioFrame(NamedTuple):
    frame_id: int
    frame_size: int
    chunk_id: int
    total_chunks: int
    timestamp_ms: int
    payload: bytes


def parse_audio_frame(body: bytes) -> AudioFrame:
    if len(body) < 14:
        raise ValueError(f"audio frame too short: {len(body)}")
    frame_id, frame_size = struct.unpack_from("<HH", body, 0)
    chunk_id = body[4]
    total_chunks = body[5]
    timestamp_ms = struct.unpack_from("<Q", body, 6)[0]
    return AudioFrame(
        frame_id=frame_id,
        frame_size=frame_size,
        chunk_id=chunk_id,
        total_chunks=total_chunks,
        timestamp_ms=timestamp_ms,
        payload=bytes(body[14:]),
    )


# --- Notify-stream parser (re-syncs to MAGIC, yields whole packets) -----

class Parser:
    """Incremental parser for the notify stream. BLE notifications can split
    a single Nuna packet across multiple events; this buffers and emits
    complete frames as `(MessageType, payload)` tuples (or `(int, payload)`
    for unknown types)."""

    def __init__(self) -> None:
        self.buf = bytearray()

    def feed(self, data: bytes):
        self.buf.extend(data)
        out: list[tuple] = []
        while True:
            if not self.buf:
                break
            if self.buf[0] != MAGIC:
                idx = self.buf.find(MAGIC)
                if idx < 0:
                    self.buf.clear()
                    break
                del self.buf[:idx]
            if len(self.buf) < HEADER_LEN:
                break
            length = struct.unpack_from("<H", self.buf, 2)[0]
            total = HEADER_LEN + length
            if len(self.buf) < total:
                break
            mtype_int = self.buf[1]
            payload = bytes(self.buf[HEADER_LEN:total])
            del self.buf[:total]
            try:
                out.append((MessageType(mtype_int), payload))
            except ValueError:
                out.append((mtype_int, payload))
        return out


# --- Per-chunk Opus packet extractor ------------------------------------

def extract_opus_packets(frame: AudioFrame) -> list[bytes]:
    """Split one AUDIO_RECORDING_DATA chunk into its component Opus packets.

    The Nuna firmware emits CBR-encoded Opus where every packet is exactly
    `frame.frame_size` bytes long, packed back-to-back inside the BLE chunk
    body. We confirmed this by walking the captured BLE traffic: every
    chunk's body of 480 B starts with `0xbc` (CELT-WB 20 ms TOC) at offsets
    0, 80, 160, 240, 320, 400 — exactly 6 × 80-byte Opus packets per chunk.

    If `frame_size` is missing (zero) or doesn't divide the body cleanly,
    we fall back to treating the whole body as one packet so that
    development sessions with unusual firmware still capture *something*.
    """
    body = frame.payload
    pkt_size = frame.frame_size
    if pkt_size <= 0 or pkt_size > len(body):
        return [body] if body else []
    n_full = len(body) // pkt_size
    return [body[i * pkt_size:(i + 1) * pkt_size] for i in range(n_full)]


class AudioReassembler:
    """Backward-compat shim. Earlier versions of this server tried to glue
    BLE chunks into one big "Opus packet" — that's wrong (see the module
    docstring). This class now just yields each chunk's Opus packets one at
    a time; the consumer should treat each yielded packet as a complete,
    decodable Opus frame.

    The yielded shape `(frame_id, timestamp_ms, opus_bytes)` is preserved
    from the older API for callers that haven't migrated yet, but a single
    `add()` may now produce multiple packets — call `add_many()` instead
    to get them all.
    """

    def __init__(self, max_frames: int = 64) -> None:
        self._pending: list[tuple[int, int, bytes]] = []
        # max_frames retained for API compatibility; no buffering needed
        self._max = max_frames

    def add_many(self, frame: AudioFrame) -> list[tuple[int, int, bytes]]:
        out: list[tuple[int, int, bytes]] = []
        for pkt in extract_opus_packets(frame):
            out.append((frame.frame_id, frame.timestamp_ms, pkt))
        return out

    def add(self, frame: AudioFrame):  # legacy single-yield API
        out = self.add_many(frame)
        if not out:
            return None
        # Stash any extras so a caller polling add() in a loop still sees them.
        first, *rest = out
        self._pending.extend(rest)
        return first

    def drain(self) -> list[tuple[int, int, bytes]]:
        out = list(self._pending)
        self._pending.clear()
        return out


# --- Self test ----------------------------------------------------------

if __name__ == "__main__":
    p = enable_milewave(True)
    assert p == bytes([0xAA, 0x13, 0x01, 0x00, 0x01, 0x34, 0x12, 0x01]), p.hex()
    a = enable_audio(True)
    assert a == bytes([0xAA, 0x11, 0x01, 0x00, 0x01, 0x34, 0x12, 0x01]), a.hex()

    h = handshake_request_packet()
    assert len(h) == HEADER_LEN + 27, len(h)
    assert h[0] == 0xAA and h[1] == int(MessageType.HANDSHAKE)
    assert struct.unpack_from("<H", h, 2)[0] == 27
    assert h[4] == 0x01 and struct.unpack_from("<H", h, 5)[0] == 0x1234
    assert h[7] == int(HandshakeMessageType.HANDSHAKE_REQUEST)
    assert bytes(h[8:14]) == b"123456"

    parser = Parser()
    msgs = parser.feed(build_packet(MessageType.AUDIO_RECORDING_DATA, b"\x01\x02\x03\x04"))
    assert msgs and msgs[0][0] == MessageType.AUDIO_RECORDING_DATA

    sr = switch_record_packet(True, command_id=0)
    # outer header (7) + body [00 00 03 01]
    assert sr == bytes([0xAA, 0x06, 0x04, 0x00, 0x01, 0x34, 0x12, 0x00, 0x00, 0x03, 0x01]), sr.hex()
    sr2 = switch_record_packet(True, command_id=1)
    assert sr2[7:11] == bytes([0x00, 0x01, 0x03, 0x01]), sr2.hex()

    st = set_time_packet(0x0102030405060708, command_id=2)
    assert st[7:10] == bytes([0x00, 0x02, 0x04]), st.hex()
    assert st[10:18] == bytes([0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01])

    print("nuna_protocol self-test OK")
    print("switch_record  :", sr.hex(" "))
    print("set_time       :", st.hex(" "))
    print("enable mmWave  :", p.hex(" "))
    print("legacy audio   :", a.hex(" "))
    print("handshake req  :", h.hex(" "))
