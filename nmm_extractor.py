#!/usr/bin/env python3
"""
Decrypt and extract Samsung Memo backups (.nmm) from Kies / Smart Switch.

Two-layer encryption:
  1) Kies container — AES-256-CBC, 272-byte blocks (256 data + 16 pad),
     first 2 blocks are an XML header, rest is zlib-compressed ZIP.
  2) Memo app — AES-128-CBC, key = SHA-256(session_key)[:16],
     IV = first 16 bytes of memo.bk.

Usage: python nmm_extractor.py <input.nmm> [output_dir]
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import logging
import re
import sqlite3
import sys
import xml.etree.ElementTree as ET
import zlib
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
except ImportError:
    sys.exit("Error: pip install cryptography")

# AES-256 key/IV embedded in Kies3.exe (0x47d79c) and SmartSwitchPC.exe (0x782164)
KIES_KEY = bytes.fromhex(
    "65706f767669776c782c64697277713b736f72302d66766b737a2c6572776f67"
)
KIES_IV = bytes.fromhex("616669652c637279776c786f65746b61")

BLOCK_DATA = 256
BLOCK_PAD = 16
BLOCK_SIZE = BLOCK_DATA + BLOCK_PAD  # 272
HEADER_BLOCKS = 2

# Session keys to try for memo.bk (most common first)
KNOWN_SESSION_KEYS = ["RANDOM", "", "SmartSwitchMobile", "Kies4Win", "SmartSwitch"]

log = logging.getLogger("nmm_extractor")


# -- data types --

@dataclass
class KiesHeader:
    version: str = ""
    password: str = ""
    super_key: str = ""
    zip_type: str = ""


@dataclass
class Memo:
    id: int
    uuid: str
    title: str
    content: str
    created_at: Optional[datetime]
    modified_at: Optional[datetime]
    category: str
    attachments: list[str] = field(default_factory=list)


@dataclass
class ExtractionResult:
    memo_count: int = 0
    attachment_count: int = 0
    output_dir: str = ""
    device_info: str = ""
    backup_date: str = ""


# -- crypto --

def aes_cbc_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    return dec.update(data) + dec.finalize()


def strip_pkcs5(data: bytes) -> bytes:
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return data


# -- layer 1: kies container --

def decrypt_kies_block(block: bytes) -> bytes:
    if len(block) != BLOCK_DATA:
        raise ValueError(f"bad block size: {len(block)}")
    return aes_cbc_decrypt(block, KIES_KEY, KIES_IV)


def parse_header(raw: bytes) -> KiesHeader:
    xml_str = raw.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
    start = xml_str.find("<?xml")
    if start == -1:
        start = xml_str.find("<header")
    if start == -1:
        raise ValueError("no XML header found in decrypted data")
    xml_str = xml_str[start:]

    h = KiesHeader()

    # strip XML namespace declarations — they break ET.fromstring
    clean = re.sub(r'\s+xmlns[^"]*"[^"]*"', '', xml_str)

    try:
        root = ET.fromstring(clean)
        h.version = root.findtext("version", "")
        h.password = root.findtext("password", "")
        h.super_key = root.findtext("superKey", "")
        h.zip_type = root.findtext("zipType", "")
    except ET.ParseError:
        # fallback: regex
        for tag, attr in [("version", "version"), ("password", "password"),
                          ("superKey", "super_key"), ("zipType", "zip_type")]:
            m = re.search(f"<{tag}[^>]*>([^<]*)</{tag}>", xml_str)
            if m:
                setattr(h, attr, m.group(1))

    return h


def decrypt_container(path: Path) -> tuple[KiesHeader, bytes]:
    size = path.stat().st_size
    total_blocks = size // BLOCK_SIZE

    if size < BLOCK_SIZE * HEADER_BLOCKS:
        raise ValueError(f"file too small: {size} bytes")
    if size % BLOCK_SIZE != 0:
        log.warning("file size not a multiple of %d — may be truncated", BLOCK_SIZE)

    log.info("%s: %d bytes, %d blocks", path.name, size, total_blocks)

    with open(path, "rb") as f:
        # header: first 2 blocks
        header_raw = bytearray()
        for _ in range(HEADER_BLOCKS):
            header_raw.extend(decrypt_kies_block(f.read(BLOCK_DATA)))
            f.read(BLOCK_PAD)

        header = parse_header(bytes(header_raw))
        log.info("version=%s zipType=%s superKey=%s", header.version, header.zip_type, header.super_key)

        # payload: remaining blocks
        payload = bytearray()
        for i in range(total_blocks - HEADER_BLOCKS):
            chunk = f.read(BLOCK_DATA)
            if len(chunk) < BLOCK_DATA:
                log.warning("truncated block %d", i)
                break
            payload.extend(decrypt_kies_block(chunk))
            f.read(BLOCK_PAD)

    raw = bytes(payload)

    # payload might be a raw ZIP (starts with PK), or zlib/gzip compressed
    if raw[:4] == b"PK\x03\x04":
        return header, raw

    if header.zip_type.lower() == "gzip":
        import gzip
        return header, gzip.decompress(raw)

    try:
        return header, zlib.decompress(raw)
    except zlib.error:
        return header, zlib.decompress(raw, -zlib.MAX_WBITS)


# -- layer 2: memo app encryption --

def decrypt_memo_bk(data: bytes, session_key: str) -> bytes:
    """memo.bk: first 16 bytes = IV, rest = AES-128-CBC(SHA-256(key)[:16])"""
    iv = data[:16]
    key = hashlib.sha256(session_key.encode("UTF-8")).digest()[:16]
    return strip_pkcs5(aes_cbc_decrypt(data[16:], key, iv))


def try_decrypt_memo(data: bytes, session_key: Optional[str] = None) -> bytes:
    keys = [session_key] if session_key else KNOWN_SESSION_KEYS
    for k in keys:
        try:
            out = decrypt_memo_bk(data, k)
            if out[:4] == b"PK\x03\x04":
                log.info("memo.bk decrypted with session key %r", k)
                return out
            pos = out.find(b"PK\x03\x04")
            if 0 < pos < 64:
                log.info("memo.bk decrypted with key %r (ZIP at +%d)", k, pos)
                return out[pos:]
        except Exception:
            continue
    raise RuntimeError(
        "could not decrypt memo.bk — try --session-key with your backup password"
    )


# -- database parsing --

def _ts(ms: Optional[int]) -> Optional[datetime]:
    if not ms:
        return None
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    except (OSError, ValueError):
        return None


def parse_memo_db(db_path: Path) -> list[Memo]:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    categories: dict[str, str] = {}
    try:
        for row in cur.execute("SELECT UUID, _display_name FROM category"):
            if row["UUID"] and row["_display_name"]:
                categories[row["UUID"]] = row["_display_name"]
    except sqlite3.OperationalError:
        pass

    attachments: dict[str, list[str]] = {}
    try:
        for row in cur.execute("SELECT memoUUID, _display_name FROM file WHERE _display_name IS NOT NULL"):
            attachments.setdefault(row["memoUUID"], []).append(row["_display_name"])
    except sqlite3.OperationalError:
        pass

    memos = []
    for row in cur.execute("""
        SELECT _id, UUID, createdAt, lastModifiedAt, title,
               strippedContent, content, categoryUUID
        FROM memo WHERE isDeleted = 0 ORDER BY createdAt
    """):
        uuid = row["UUID"] or ""
        memos.append(Memo(
            id=row["_id"],
            uuid=uuid,
            title=(row["title"] or "").strip(),
            content=(row["strippedContent"] or row["content"] or "").strip(),
            created_at=_ts(row["createdAt"]),
            modified_at=_ts(row["lastModifiedAt"]),
            category=categories.get(row["categoryUUID"] or "", ""),
            attachments=attachments.get(uuid, []),
        ))

    conn.close()
    return memos


def parse_manifest(data: bytes) -> dict[str, str]:
    info: dict[str, str] = {}
    try:
        clean = re.sub(r'\s+xmlns[^"]*"[^"]*"', '', data.decode("utf-8", errors="replace"))
        root = ET.fromstring(clean)
        for elem in root.iter():
            tag = elem.tag.lower()
            if "model" in tag:
                info["model"] = elem.text or ""
            elif "version" in tag and "android" in tag:
                info["android_version"] = elem.text or ""
            elif "date" in tag:
                info["backup_date"] = elem.text or ""
            elif "build" in tag:
                info["build"] = elem.text or ""
    except ET.ParseError:
        for line in data.decode("utf-8", errors="replace").split("\n"):
            for key in ["Model", "AndroidVer", "Date", "Build"]:
                if key in line and "<" in line:
                    s, e = line.find(">") + 1, line.rfind("<")
                    if s < e:
                        info[key.lower()] = line[s:e]
    return info


# -- image detection --

IMAGE_SIGS = [
    (b"\xff\xd8", ".jpg"),
    (b"\x89PNG", ".png"),
    (b"GIF8", ".gif"),
    (b"BM", ".bmp"),
]

def detect_ext(data: bytes) -> Optional[str]:
    for sig, ext in IMAGE_SIGS:
        if data[:len(sig)] == sig:
            return ext
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return ".webp"
    return None


# -- output --

def _fmt_dt(dt: Optional[datetime]) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "Unknown"


def write_text(memos: list[Memo], path: Path, device_info: dict[str, str]) -> None:
    lines = [
        "=" * 72,
        "SAMSUNG MEMO BACKUP",
        "=" * 72, "",
        f"  Total memos:  {len(memos)}",
    ]
    if device_info:
        lines.append(f"  Device:       {device_info.get('model', 'Unknown')}")
        lines.append(f"  Android:      {device_info.get('android_version', device_info.get('androidver', 'Unknown'))}")
        lines.append(f"  Backup date:  {device_info.get('backup_date', device_info.get('date', 'Unknown'))}")
    lines += ["", "=" * 72]

    for m in memos:
        lines.append("")
        lines.append("-" * 72)
        title = f"Memo #{m.id}  |  {m.title}" if m.title else f"Memo #{m.id}"
        lines.append(title)
        lines.append("-" * 72)
        if m.category:
            lines.append(f"  Category:  {m.category}")
        lines.append(f"  Created:   {_fmt_dt(m.created_at)}")
        lines.append(f"  Modified:  {_fmt_dt(m.modified_at)}")
        for att in m.attachments:
            lines.append(f"  Attachment: images/{att}")
        lines.append("")
        lines.append(m.content or "(empty)")
        lines.append("")

    lines += ["=" * 72, ""]
    path.write_text("\n".join(lines), encoding="utf-8")


def write_json(memos: list[Memo], path: Path) -> None:
    data = [{
        "id": m.id, "uuid": m.uuid, "title": m.title, "content": m.content,
        "created_at": m.created_at.isoformat() if m.created_at else None,
        "modified_at": m.modified_at.isoformat() if m.modified_at else None,
        "category": m.category, "attachments": m.attachments,
    } for m in memos]
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")


# -- main pipeline --

def extract_nmm(
    nmm_path: Path,
    output_dir: Path,
    session_key: Optional[str] = None,
    output_format: str = "all",
) -> ExtractionResult:
    result = ExtractionResult(output_dir=str(output_dir))

    # decrypt outer kies container
    log.info("Decrypting Kies container...")
    header, zip_data = decrypt_container(nmm_path)

    # open inner zip (filelist.xml, Manifest.xml, memo.bk)
    log.info("Extracting container...")
    container = zipfile.ZipFile(io.BytesIO(zip_data))
    names = container.namelist()
    log.info("Contents: %s", names)

    device_info: dict[str, str] = {}
    if "Manifest.xml" in names:
        device_info = parse_manifest(container.read("Manifest.xml"))
        result.device_info = device_info.get("model", "")
        result.backup_date = device_info.get("backup_date", device_info.get("date", ""))

    memo_bk = next((n for n in names if n.lower() == "memo.bk"), None)
    if not memo_bk:
        raise RuntimeError(f"no memo.bk in container. files: {names}")

    bk_data = container.read(memo_bk)
    log.info("memo.bk: %d bytes", len(bk_data))

    # decrypt memo.bk
    log.info("Decrypting memo data...")
    memo_zip_data = try_decrypt_memo(bk_data, session_key)

    # extract memos and attachments
    log.info("Extracting memos...")
    output_dir.mkdir(parents=True, exist_ok=True)
    images_dir = output_dir / "images"
    images_dir.mkdir(exist_ok=True)

    memo_zip = zipfile.ZipFile(io.BytesIO(memo_zip_data))

    db_name = next((n for n in memo_zip.namelist() if n.lower() == "memo.db"), None)
    if not db_name:
        raise RuntimeError(f"no memo.db found. contents: {memo_zip.namelist()}")

    db_path = output_dir / "memo.db"
    db_path.write_bytes(memo_zip.read(db_name))

    # extract image blobs
    att_count = 0
    for name in memo_zip.namelist():
        if name.lower() == "memo.db":
            continue
        blob = memo_zip.read(name)
        ext = detect_ext(blob) if len(blob) >= 4 else None
        if ext:
            dest = images_dir / (Path(name).stem + ext)
            dest.write_bytes(blob)
            att_count += 1
            log.info("  %s (%d bytes)", dest.name, len(blob))

    memos = parse_memo_db(db_path)
    result.memo_count = len(memos)
    result.attachment_count = att_count

    # rename blobs to original filenames where possible
    _rename_from_db(db_path, images_dir)

    if output_format in ("text", "all"):
        write_text(memos, output_dir / "memos.txt", device_info)
    if output_format in ("json", "all"):
        write_json(memos, output_dir / "memos.json")

    return result


def _rename_from_db(db_path: Path, images_dir: Path) -> None:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        for row in conn.execute("SELECT _display_name, _data FROM file WHERE _display_name IS NOT NULL"):
            if not row["_data"]:
                continue
            stem = Path(row["_data"]).stem
            for f in images_dir.iterdir():
                if f.stem == stem:
                    target = images_dir / row["_display_name"]
                    if not target.exists():
                        f.rename(target)
                    break
    except sqlite3.OperationalError:
        pass
    finally:
        conn.close()


# -- cli --

def main():
    p = argparse.ArgumentParser(
        prog="nmm-extractor",
        description="Decrypt and extract Samsung Memo backups (.nmm files).",
    )
    p.add_argument("input", type=Path, help="path to .nmm file")
    p.add_argument("output", type=Path, nargs="?", default=None, help="output directory")
    p.add_argument("--session-key", type=str, default=None, help="memo.bk session key (auto-detected if omitted)")
    p.add_argument("--format", choices=["text", "json", "all"], default="all", help="output format (default: all)")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    if not args.input.is_file():
        log.error("not found: %s", args.input)
        sys.exit(1)

    out = args.output or Path(f"{args.input.stem}_extracted")

    try:
        result = extract_nmm(args.input, out, args.session_key, args.format)
    except Exception as e:
        log.error("%s", e)
        if args.verbose:
            import traceback; traceback.print_exc()
        sys.exit(1)

    print(f"\n  Done — {result.memo_count} memos, {result.attachment_count} attachments")
    print(f"  Output: {out}/\n")


if __name__ == "__main__":
    main()
