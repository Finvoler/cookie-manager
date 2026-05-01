from __future__ import annotations

import base64
import ctypes
import json
import os
import secrets
import sys
import uuid
from argparse import ArgumentParser
from ctypes import wintypes
from datetime import datetime
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

APP_NAME = "Cookie Manager"
VAULT_MARKER = "cookie-manager-vault-v1"
APP_DIR = Path(__file__).resolve().parent
VAULT_FILE = APP_DIR / "vault.dat"
REMEMBERED_PASSWORD_FILE = APP_DIR / "remembered_password.dat"
PENDING_DIR = APP_DIR / "pending_key_writes"


class VaultWriterError(Exception):
    pass


class DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob_from_bytes(data: bytes) -> tuple[DataBlob, ctypes.Array]:
    buffer = ctypes.create_string_buffer(data)
    blob = DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    return blob, buffer


def _dpapi_protect(data: bytes) -> bytes:
    if os.name != "nt":
        raise VaultWriterError("自动写入只支持 Windows 当前用户 DPAPI。")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    input_blob, _buffer = _blob_from_bytes(data)
    output_blob = DataBlob()
    ok = crypt32.CryptProtectData(
        ctypes.byref(input_blob),
        ctypes.c_wchar_p(APP_NAME),
        None,
        None,
        None,
        0,
        ctypes.byref(output_blob),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)


def _dpapi_unprotect(data: bytes) -> bytes:
    if os.name != "nt":
        raise VaultWriterError("自动写入只支持 Windows 当前用户 DPAPI。")
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    input_blob, _buffer = _blob_from_bytes(data)
    output_blob = DataBlob()
    ok = crypt32.CryptUnprotectData(ctypes.byref(input_blob), None, None, None, None, 0, ctypes.byref(output_blob))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return ctypes.string_at(output_blob.pbData, output_blob.cbData)
    finally:
        kernel32.LocalFree(output_blob.pbData)


class Vault:
    def __init__(self, path: Path, password: str, salt: bytes, payload: dict):
        self.path = path
        self.salt = salt
        self.payload = payload
        self._fernet = Fernet(self._derive_key(password, salt))

    @property
    def entries(self) -> list[dict]:
        return self.payload.setdefault("entries", [])

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390_000)
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    @classmethod
    def create(cls, path: Path, password: str) -> "Vault":
        salt = os.urandom(16)
        payload = {"marker": VAULT_MARKER, "entries": []}
        vault = cls(path, password, salt, payload)
        vault.save()
        return vault

    @classmethod
    def open(cls, path: Path, password: str) -> "Vault":
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            salt = base64.b64decode(raw["salt"])
            token = raw["token"].encode("utf-8")
            fernet = Fernet(cls._derive_key(password, salt))
            payload = json.loads(fernet.decrypt(token).decode("utf-8"))
        except (OSError, KeyError, json.JSONDecodeError, InvalidToken, ValueError) as exc:
            raise VaultWriterError("主密码不正确，或密钥库文件已损坏。") from exc
        if payload.get("marker") != VAULT_MARKER:
            raise VaultWriterError("密钥库格式不兼容。")
        return cls(path, password, salt, payload)

    def save(self) -> None:
        token = self._fernet.encrypt(json.dumps(self.payload, ensure_ascii=False).encode("utf-8"))
        data = {
            "version": 1,
            "salt": base64.b64encode(self.salt).decode("utf-8"),
            "token": token.decode("utf-8"),
        }
        self.path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def now_text() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def load_remembered_password() -> str | None:
    try:
        raw = json.loads(REMEMBERED_PASSWORD_FILE.read_text(encoding="utf-8"))
        if raw.get("provider") != "windows-dpapi-current-user":
            return None
        encrypted = base64.b64decode(raw["data"])
        return _dpapi_unprotect(encrypted).decode("utf-8")
    except (OSError, KeyError, ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def _pending_path(pending_id: str) -> Path:
    safe_id = "".join(ch for ch in pending_id if ch.isalnum() or ch in "-_")
    if not safe_id:
        raise VaultWriterError("待确认编号无效。")
    return PENDING_DIR / f"{safe_id}.dat"


def _write_pending(pending: dict) -> None:
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(pending, ensure_ascii=False).encode("utf-8")
    protected = _dpapi_protect(payload)
    _pending_path(pending["id"]).write_bytes(protected)


def _read_pending(pending_id: str) -> dict:
    path = _pending_path(pending_id)
    if not path.exists():
        raise VaultWriterError("没有找到这条待确认写入，可能已经写入、取消或过期。")
    try:
        return json.loads(_dpapi_unprotect(path.read_bytes()).decode("utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise VaultWriterError("待确认写入无法读取。") from exc


def normalize_entry(entry: dict) -> dict:
    normalized = {
        "name": str(entry.get("name", "")).strip(),
        "username": str(entry.get("username", "")).strip(),
        "password": str(entry.get("password", "")),
        "note": str(entry.get("note", "")).strip(),
        "cookie": str(entry.get("cookie", "")).strip(),
    }
    if not normalized["name"]:
        raise VaultWriterError("每条记录都必须有名称。")
    if not (normalized["username"] or normalized["password"] or normalized["cookie"] or normalized["note"]):
        raise VaultWriterError(f"{normalized['name']} 没有可保存内容。")
    return normalized


def prepare_entries(entries: list[dict]) -> dict:
    normalized_entries = [normalize_entry(entry) for entry in entries]
    if not normalized_entries:
        raise VaultWriterError("没有可写入的记录。")
    pending_id = datetime.now().strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    pending = {"version": 1, "id": pending_id, "created_at": now_text(), "entries": normalized_entries}
    _write_pending(pending)
    return {"id": pending_id, "count": len(normalized_entries), "entries": normalized_entries}


def commit_pending(pending_id: str) -> dict:
    pending = _read_pending(pending_id)
    password = load_remembered_password()
    if not password:
        raise VaultWriterError("还不能自动写入：请先打开 CookieManager，输入主密码，并勾选“记住密码”。")
    vault = Vault.open(VAULT_FILE, password) if VAULT_FILE.exists() else Vault.create(VAULT_FILE, password)
    timestamp = now_text()
    for entry in pending.get("entries", []):
        vault.entries.append(
            {
                "id": str(uuid.uuid4()),
                "name": entry["name"],
                "username": entry.get("username", ""),
                "password": entry.get("password", ""),
                "note": entry.get("note", ""),
                "cookie": entry.get("cookie", ""),
                "created_at": timestamp,
                "updated_at": timestamp,
            }
        )
    vault.save()
    _pending_path(pending_id).unlink(missing_ok=True)
    return {"id": pending_id, "count": len(pending.get("entries", [])), "vault": str(VAULT_FILE)}


def cancel_pending(pending_id: str) -> dict:
    path = _pending_path(pending_id)
    existed = path.exists()
    path.unlink(missing_ok=True)
    return {"id": pending_id, "cancelled": existed}


def status() -> dict:
    return {
        "vault_exists": VAULT_FILE.exists(),
        "remembered_password_exists": REMEMBERED_PASSWORD_FILE.exists(),
        "pending_count": len(list(PENDING_DIR.glob("*.dat"))) if PENDING_DIR.exists() else 0,
        "vault": str(VAULT_FILE),
    }


def _print_json(data: dict) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2))


def main(argv: list[str] | None = None) -> int:
    parser = ArgumentParser(description="Cookie Manager local vault writer")
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser("prepare")
    prepare_parser.add_argument("--entries-json", required=True)

    commit_parser = subparsers.add_parser("commit")
    commit_parser.add_argument("--pending-id", required=True)

    cancel_parser = subparsers.add_parser("cancel")
    cancel_parser.add_argument("--pending-id", required=True)

    subparsers.add_parser("status")

    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            _print_json(prepare_entries(json.loads(args.entries_json)))
        elif args.command == "commit":
            _print_json(commit_pending(args.pending_id))
        elif args.command == "cancel":
            _print_json(cancel_pending(args.pending_id))
        elif args.command == "status":
            _print_json(status())
    except (VaultWriterError, json.JSONDecodeError) as exc:
        _print_json({"error": str(exc)})
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))