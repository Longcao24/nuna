"""Cross-platform helpers for BLE advertisement name extraction.

On Windows the local name often arrives in a scan-response packet after the
initial advertisement. Prefer ``adv.local_name`` over ``device.name``, parse
all advertisement sections, and fall back to the OS Bluetooth cache when needed.
"""

from __future__ import annotations

import asyncio
import re
import sys
import time
from typing import Any, Optional

from bleak import BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from nuna_protocol import SERVICE_UUID as NUNA_SERVICE_UUID

_JUNK_DEVICE_NAMES = frozenset({"", "unknown", "(unknown)", "unnamed"})
_NUNA_SERVICE = NUNA_SERVICE_UUID.lower().strip()
_HEX_ONLY = re.compile(r"^[0-9a-fA-F]+$")
_NUNA_NAME_IN_BYTES = re.compile(rb"nuna\s*device[_\w]*", re.IGNORECASE)
_NUNA_DEVICE_NAME = re.compile(r"^nuna\s+device_[0-9a-fA-F]{4}$", re.IGNORECASE)
_WINDOWS_GENERIC_BT = re.compile(
    r"^bluetooth\s+[0-9a-fA-F:.\-]{11,}$", re.IGNORECASE
)


def _norm_uuid(uuid: str) -> str:
    return uuid.lower().strip()


def _looks_like_device_name(name: str) -> bool:
    if len(name) < 3:
        return False
    if _WINDOWS_GENERIC_BT.match(name):
        return False
    if _NUNA_DEVICE_NAME.match(name):
        return True
    printable = sum(1 for c in name if c.isprintable() and ord(c) < 128)
    if printable < max(3, int(len(name) * 0.85)):
        return False
    if _HEX_ONLY.fullmatch(name) and len(name) >= 6:
        return False
    if re.search(r"[a-zA-Z]", name):
        return True
    return any(ch in name for ch in "_-[](). ")


def _clean_name(candidate: Any) -> Optional[str]:
    if not candidate:
        return None
    cleaned = str(candidate).strip()
    if cleaned.lower() in _JUNK_DEVICE_NAMES:
        return None
    if not _looks_like_device_name(cleaned):
        return None
    return cleaned


def _mac_suffix(address: str) -> Optional[str]:
    parts = address.upper().replace("-", ":").split(":")
    if len(parts) != 6 or not all(len(p) == 2 for p in parts):
        return None
    try:
        int("".join(parts), 16)
    except ValueError:
        return None
    return parts[4] + parts[5]


def infer_nuna_device_name(address: str) -> Optional[str]:
    """Mac/iOS show names like ``nuna device_05D0`` (last MAC bytes)."""
    suffix = _mac_suffix(address)
    if not suffix:
        return None
    return f"nuna device_{suffix}"


def is_nuna_advertisement(adv: AdvertisementData) -> bool:
    """True when the device advertises the Nuna vendor service UUID."""
    if any(_norm_uuid(u) == _NUNA_SERVICE for u in (adv.service_uuids or [])):
        return True
    return _advertisement_bytes_contain_nuna(adv)


def is_nuna_row(row: dict[str, Any]) -> bool:
    if any(_norm_uuid(u) == _NUNA_SERVICE for u in (row.get("service_uuids") or [])):
        return True
    name = row.get("name") or ""
    return "nuna" in name.lower()


def display_label(row: dict[str, Any]) -> str:
    name = row.get("name")
    if name:
        return name
    if is_nuna_row(row):
        inferred = infer_nuna_device_name(row.get("address", ""))
        if inferred:
            return inferred
        return "nuna (no BLE name — click to connect)"
    return "(unnamed)"


def _parse_ad_structures(data: bytes) -> Optional[str]:
    i = 0
    while i + 2 <= len(data):
        length = data[i]
        if length == 0:
            break
        end = i + 1 + length
        if end > len(data):
            break
        ad_type = data[i + 1]
        ad_data = data[i + 2 : end]
        if ad_type in (0x08, 0x09):
            cleaned = _clean_name(ad_data.decode("utf-8", errors="ignore"))
            if cleaned:
                return cleaned
        i = end
    return None


def _name_from_payload_bytes(data: bytes) -> Optional[str]:
    for match in _NUNA_NAME_IN_BYTES.finditer(data):
        cleaned = _clean_name(match.group(0).decode("ascii", errors="ignore"))
        if cleaned:
            return cleaned
    return _parse_ad_structures(data)


def _advertisement_blobs(adv: AdvertisementData) -> list[bytes]:
    blobs: list[bytes] = []
    for value in (adv.manufacturer_data or {}).values():
        blobs.append(bytes(value))
    for value in (adv.service_data or {}).values():
        blobs.append(bytes(value))
    try:
        from bleak.assigned_numbers import AdvertisementDataType

        platform_data = adv.platform_data
        if platform_data and len(platform_data) >= 2:
            raw_data = platform_data[1]
            for event_args in (
                getattr(raw_data, "adv", None),
                getattr(raw_data, "scan", None),
            ):
                if event_args is None:
                    continue
                advertisement = event_args.advertisement
                cleaned = _clean_name(getattr(advertisement, "local_name", None))
                if cleaned:
                    blobs.append(cleaned.encode("utf-8"))
                for section_type in AdvertisementDataType:
                    try:
                        for section in advertisement.get_sections_by_type(
                            section_type
                        ):
                            blobs.append(bytes(section.data))
                    except Exception:
                        continue
    except Exception:
        pass
    return blobs


def _advertisement_bytes_contain_nuna(adv: AdvertisementData) -> bool:
    for blob in _advertisement_blobs(adv):
        if _NUNA_NAME_IN_BYTES.search(blob):
            return True
        if _parse_ad_structures(blob) and "nuna" in (
            _parse_ad_structures(blob) or ""
        ).lower():
            return True
    return False


def _name_from_ad_sections(adv: AdvertisementData) -> Optional[str]:
    try:
        from bleak.assigned_numbers import AdvertisementDataType

        platform_data = adv.platform_data
        if not platform_data or len(platform_data) < 2:
            return None
        raw_data = platform_data[1]
        for event_args in (
            getattr(raw_data, "adv", None),
            getattr(raw_data, "scan", None),
        ):
            if event_args is None:
                continue
            advertisement = event_args.advertisement
            cleaned = _clean_name(getattr(advertisement, "local_name", None))
            if cleaned:
                return cleaned
            for section_type in (
                AdvertisementDataType.COMPLETE_LOCAL_NAME,
                AdvertisementDataType.SHORTENED_LOCAL_NAME,
            ):
                for section in advertisement.get_sections_by_type(section_type):
                    cleaned = _clean_name(
                        bytes(section.data).decode("utf-8", errors="ignore")
                    )
                    if cleaned:
                        return cleaned
    except Exception:
        pass
    return None


def _name_from_adv_blobs(adv: AdvertisementData) -> Optional[str]:
    blobs = _advertisement_blobs(adv)
    for blob in blobs:
        name = _name_from_payload_bytes(blob)
        if name:
            return name
    if blobs:
        return _name_from_payload_bytes(b"".join(blobs))
    return None


def advertisement_name(
    device: BLEDevice, adv: AdvertisementData
) -> Optional[str]:
    """Best-effort local/display name from a scan callback."""
    for candidate in (
        adv.local_name,
        device.name,
        _name_from_ad_sections(adv),
        _name_from_adv_blobs(adv),
    ):
        cleaned = _clean_name(candidate)
        if cleaned:
            return cleaned
    if is_nuna_advertisement(adv):
        return infer_nuna_device_name(device.address)
    return None


def name_matches(
    name_substr: str, device: BLEDevice, adv: AdvertisementData
) -> bool:
    needle = name_substr.lower()
    if needle == "nuna" and is_nuna_advertisement(adv):
        return True
    name = advertisement_name(device, adv)
    if not name:
        return False
    return needle in name.lower()


def merge_device_entry(
    existing: Optional[dict[str, Any]],
    device: BLEDevice,
    adv: AdvertisementData,
) -> dict[str, Any]:
    """Merge a new advertisement into a scan result row."""
    name = advertisement_name(device, adv)
    if existing and not name:
        name = existing.get("name")

    mfg = {
        str(k): v.hex() for k, v in (adv.manufacturer_data or {}).items()
    }
    if existing and not mfg:
        mfg = existing.get("manufacturer_data", {})

    uuids = list(adv.service_uuids or [])
    if existing and not uuids:
        uuids = existing.get("service_uuids", [])

    rssi = adv.rssi
    if existing and existing.get("rssi") is not None:
        if rssi is None:
            rssi = existing.get("rssi")
        else:
            rssi = max(rssi, existing["rssi"])

    row = {
        "name": name,
        "service_uuids": uuids,
    }
    return {
        "address": device.address,
        "name": name,
        "label": display_label({**row, "address": device.address}),
        "likely_nuna": is_nuna_row({**row, "address": device.address}),
        "rssi": rssi,
        "service_uuids": uuids,
        "manufacturer_data": mfg,
    }


def make_scanner(
    detection_callback: Any = None, **kwargs: Any
) -> BleakScanner:
    """Create a BleakScanner tuned for reliable name discovery on Windows."""
    kwargs.setdefault("scanning_mode", "active")
    if detection_callback is not None:
        return BleakScanner(detection_callback=detection_callback, **kwargs)
    return BleakScanner(**kwargs)


def _merge_from_scanner(
    scanner: BleakScanner, found: dict[str, dict[str, Any]]
) -> None:
    for device, adv in scanner.discovered_devices_and_advertisement_data.values():
        found[device.address] = merge_device_entry(
            found.get(device.address), device, adv
        )


def _nuna_unlabeled_count(found: dict[str, dict[str, Any]]) -> int:
    return sum(
        1
        for row in found.values()
        if is_nuna_row(row) and not (row.get("name") or "").lower().startswith("nuna")
    )


async def _wait_for_windows_scan_responses(
    scanner: BleakScanner,
    found: dict[str, dict[str, Any]],
    extra_seconds: float = 5.0,
) -> None:
    """Keep scanning briefly so Windows can receive SCAN_RSP packets."""
    if sys.platform != "win32":
        return
    deadline = time.monotonic() + extra_seconds
    while time.monotonic() < deadline:
        _merge_from_scanner(scanner, found)
        if _nuna_unlabeled_count(found) == 0 and all(
            row.get("name") for row in found.values()
        ):
            break
        await asyncio.sleep(0.2)


async def _resolve_windows_system_names(
    found: dict[str, dict[str, Any]],
) -> None:
    """Ask the Windows Bluetooth stack for cached friendly names."""
    if sys.platform != "win32":
        return
    try:
        from winrt.windows.devices.bluetooth import BluetoothLEDevice
    except ImportError:
        return

    unnamed = [addr for addr, row in found.items() if not row.get("name")]
    if not unnamed:
        return

    sem = asyncio.Semaphore(8)

    async def resolve_one(addr: str) -> None:
        try:
            bdaddr = int(addr.replace(":", ""), 16)
        except ValueError:
            return
        async with sem:
            try:
                device = await BluetoothLEDevice.from_bluetooth_address_async(
                    bdaddr
                )
            except Exception:
                return
        if device is None:
            return
        cleaned = _clean_name(device.name)
        if cleaned:
            found[addr]["name"] = cleaned

    await asyncio.gather(*(resolve_one(addr) for addr in unnamed))


def _finalize_rows(found: dict[str, dict[str, Any]]) -> None:
    for row in found.values():
        if not row.get("name") and is_nuna_row(row):
            inferred = infer_nuna_device_name(row.get("address", ""))
            if inferred:
                row["name"] = inferred
        row["label"] = display_label(row)
        row["likely_nuna"] = is_nuna_row(row)


async def scan_ble_devices(seconds: float) -> list[dict[str, Any]]:
    """Scan for BLE devices and return rows with the best names we can find."""
    found: dict[str, dict[str, Any]] = {}

    def _on_detect(device: BLEDevice, adv: AdvertisementData) -> None:
        found[device.address] = merge_device_entry(
            found.get(device.address), device, adv
        )

    scanner = make_scanner(detection_callback=_on_detect)
    await scanner.start()
    try:
        await asyncio.sleep(seconds)
        await _wait_for_windows_scan_responses(scanner, found)
        _merge_from_scanner(scanner, found)
    finally:
        await scanner.stop()
        _merge_from_scanner(scanner, found)

    await _resolve_windows_system_names(found)
    _finalize_rows(found)
    return list(found.values())


async def find_ble_device_by_name(
    name_substr: str, scan_seconds: float
) -> Optional[BLEDevice]:
    """Scan until a device whose name contains ``name_substr`` is found."""
    found: dict[str, Any] = {"d": None}
    rows: dict[str, dict[str, Any]] = {}
    done = asyncio.Event()

    def _on_detect(device: BLEDevice, adv: AdvertisementData) -> None:
        rows[device.address] = merge_device_entry(
            rows.get(device.address), device, adv
        )
        if name_matches(name_substr, device, adv) and not found["d"]:
            found["d"] = device
            done.set()

    scanner = make_scanner(detection_callback=_on_detect)
    await scanner.start()
    try:
        try:
            await asyncio.wait_for(done.wait(), scan_seconds)
        except asyncio.TimeoutError:
            await _wait_for_windows_scan_responses(scanner, rows, extra_seconds=5.0)
            _merge_from_scanner(scanner, rows)
    finally:
        await scanner.stop()
        _merge_from_scanner(scanner, rows)

    if found["d"] is not None:
        return found["d"]

    await _resolve_windows_system_names(rows)
    _finalize_rows(rows)
    needle = name_substr.lower()
    for addr, row in rows.items():
        by_service = needle == "nuna" and is_nuna_row(row)
        name = row.get("name")
        by_name = bool(name) and needle in name.lower()
        if not by_service and not by_name:
            continue
        for device, _adv in scanner.discovered_devices_and_advertisement_data.values():
            if device.address == addr:
                return device
        return BLEDevice(addr, name or "nuna", None)
    return None


def scan_timeout_budget(seconds: float) -> float:
    """Thread-pool timeout for a scan of ``seconds`` duration."""
    extra = 25.0 if sys.platform == "win32" else 5.0
    return seconds + extra
