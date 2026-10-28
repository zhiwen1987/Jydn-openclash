"""Fetch immutable manifest sources; keep verified bytes only in an ignored cache."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import os
from pathlib import Path
import re
import tempfile
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

CACHE = Path(__file__).resolve().parents[1] / ".cache/routing-audit"
MAX_BYTES = 16 * 1024 * 1024


def validate_source(source):
    name = source.get("name", "")
    revision = source.get("revision", "")
    digest = source.get("sha256", "")
    parsed = urlsplit(source.get("url", ""))
    parts = parsed.path.strip("/").split("/")
    if (not name or source.get("status") != "loaded"
            or not re.fullmatch(r"[0-9a-f]{40}", revision)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
            or parsed.scheme != "https" or parsed.netloc != "raw.githubusercontent.com"
            or parsed.query or parsed.fragment or len(parts) < 4
            or parts[2] != revision
            or tuple(parts[:2]) not in {
                ("MetaCubeX", "meta-rules-dat"),
                ("Aethersailor", "Custom_OpenClash_Rules")}):
        raise RuntimeError("invalid pinned source: " + name)


def verified_source(source, cache_dir=None):
    validate_source(source)
    cache = Path(cache_dir) if cache_dir is not None else CACHE
    target = cache / (source["sha256"] + ".raw")
    if target.is_file():
        raw = target.read_bytes()
    else:
        request = Request(source["url"], headers={"User-Agent": "Jydn-routing-audit/2"})
        with urlopen(request, timeout=30) as response:
            raw = response.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES or hashlib.sha256(raw).hexdigest() != source["sha256"]:
        # Do not hide corrupt caches or changed upstream bytes by silently retrying.
        raise RuntimeError("source sha256 mismatch: " + source["name"])
    text = raw.decode("utf-8")
    if not target.exists():
        cache.mkdir(parents=True, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(dir=cache, delete=False) as stream:
                temporary = Path(stream.name)
                stream.write(raw)
            os.replace(temporary, target)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
    return text


def source_texts(manifest, cache_dir=None):
    sources = manifest["sources"]
    names = [source["name"] for source in sources]
    if not names or len(set(names)) != len(names):
        raise RuntimeError("missing or duplicate manifest sources")
    # Validate every source before network access or writing cache files.
    for source in sources:
        validate_source(source)
    with ThreadPoolExecutor(max_workers=8) as pool:
        texts = list(pool.map(lambda source: verified_source(source, cache_dir), sources))
    return dict(zip(names, texts))
