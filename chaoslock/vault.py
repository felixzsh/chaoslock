import json
import random
import datetime
from pathlib import Path
from typing import Dict, Any, Set, List

VAULT_DIR = "vault"
VAULT_METADATA_FILE = "vault_metadata.json"


def _load_metadata() -> Dict[int, Any]:
    metadata_path = Path(VAULT_METADATA_FILE)
    if not metadata_path.exists():
        return {}

    try:
        with open(metadata_path, "r") as f:
            data = json.load(f)
            return {int(k): v for k, v in data.items()}
    except (json.JSONDecodeError, IOError):
        return {}


def _save_metadata(metadata: Dict[int, Any]) -> None:
    import tempfile
    import os

    metadata_path = Path(VAULT_METADATA_FILE)

    with tempfile.NamedTemporaryFile(
        mode="w", dir=metadata_path.parent, delete=False
    ) as tmp:
        json.dump(metadata, tmp, indent=2, default=str)
        tmp.flush()

    os.replace(tmp.name, metadata_path)


def _ensure_vault_dir() -> None:
    """Ensure the vault directory exists"""
    Path(VAULT_DIR).mkdir(exist_ok=True)


def _file_id_to_path(file_id: int) -> Path:
    """Convert file ID to file path with proper 4-digit padding"""
    return Path(VAULT_DIR) / f"{file_id:04d}.enc"


def _scan_existing_ids() -> List[int]:
    vault_path = Path(VAULT_DIR)
    if not vault_path.exists():
        return []

    ids = []
    for file_path in vault_path.glob("*.enc"):
        if len(file_path.stem) == 4:
            try:
                id = int(file_path.stem)
                if 0 <= id <= 9999:
                    ids.append(id)
            except ValueError:
                continue
    return ids


def _sync_metadata_with_files() -> Dict[int, Any]:
    metadata = _load_metadata()
    existing_ids = _scan_existing_ids()

    updated = False

    for file_id in existing_ids:
        if file_id not in metadata:
            file_path = _file_id_to_path(file_id)
            mod_time = datetime.datetime.fromtimestamp(file_path.stat().st_mtime)
            metadata[file_id] = {
                "created_at": mod_time.isoformat(),
                "last_used_at": None,
                "usage_history": [],
            }
            updated = True

    metadata_ids = list(metadata.keys())
    for file_id in metadata_ids:
        if file_id not in existing_ids:
            del metadata[file_id]
            updated = True

    if updated:
        _save_metadata(metadata)

    return metadata


def get_metadata() -> Dict[int, Any]:
    return _sync_metadata_with_files()


def get_file_ids() -> Set[int]:
    existing_ids = _scan_existing_ids()
    return set(existing_ids)


def gen_new_filename() -> str:
    """Generate unique 4-digit filename"""
    existing_ids = get_file_ids()

    if len(existing_ids) >= 10000:
        raise Exception("No available file IDs (all 0000-9999 are in use)")

    while True:
        num = random.randint(0, 9999)
        if num not in existing_ids:
            return f"{num:04d}.enc"


def store(data: bytes) -> int:
    _ensure_vault_dir()

    filename = gen_new_filename()
    file_id = int(filename.split(".")[0])

    file_path = _file_id_to_path(file_id)
    file_path.write_bytes(data)

    metadata = get_metadata()
    created_at = datetime.datetime.now()

    metadata[file_id] = {
        "created_at": created_at.isoformat(),
        "last_used_at": None,
        "usage_history": [],
    }

    _save_metadata(metadata)
    return file_id


def mark_as_used(file_id: int) -> bool:
    metadata = get_metadata()

    if file_id not in metadata:
        return False

    used_at = datetime.datetime.now()

    metadata[file_id]["last_used_at"] = used_at.isoformat()

    usage_history = metadata[file_id].get("usage_history", [])
    usage_history.insert(0, used_at.isoformat())
    metadata[file_id]["usage_history"] = usage_history

    _save_metadata(metadata)
    return True


def file_exists(file_id: int) -> bool:
    file_path = _file_id_to_path(file_id)
    return file_path.exists()
