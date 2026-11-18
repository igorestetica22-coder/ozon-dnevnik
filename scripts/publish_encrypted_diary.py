#!/usr/bin/env python3
"""Merge sealed daily reports into a password-encrypted existing Ozon diary."""
import argparse
import base64
import gzip
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def ub64(s):
    return base64.b64decode(s, validate=True)


def b64(b):
    return base64.b64encode(b).decode("ascii")


def decrypt_sealed(path, private_key):
    sealed = json.loads(Path(path).read_text(encoding="utf-8"))
    if sealed.get("version") != 1 or sealed.get("type") != "ozon-daily-report":
        raise ValueError("Invalid sealed report format")
    key = private_key.decrypt(
        ub64(sealed["wrappedKey"]),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    plain = AESGCM(key).decrypt(ub64(sealed["iv"]), ub64(sealed["ct"]), b"ozon-daily-report-v1")
    report = json.loads(plain)
    if not isinstance(report, dict) or not isinstance(report.get("models"), list) or not isinstance(report.get("totals"), dict):
        raise ValueError("Invalid daily report")
    if report.get("entity") not in ("WH", "FX"):
        raise ValueError("Invalid entity")
    import datetime
    datetime.date.fromisoformat(report["date"])
    return report


def derive(password, salt, iterations):
    if not (100000 <= iterations <= 5000000):
        raise ValueError("Unexpected PBKDF2 iterations")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
    return kdf.derive(password.encode("utf-8"))


def decrypt_diary(raw, password):
    env = json.loads(raw)
    key = derive(password, ub64(env["salt"]), int(env["iter"]))
    plain = AESGCM(key).decrypt(ub64(env["iv"]), ub64(env["ct"]), None)
    docs = json.loads(gzip.decompress(plain) if env.get("gz") else plain)
    if not isinstance(docs, list):
        raise ValueError("Existing diary must be an array")
    return docs, int(env["iter"])


def encrypt_diary(docs, password, iterations):
    raw = gzip.compress(json.dumps(docs, ensure_ascii=False, separators=(",", ":")).encode("utf-8"), mtime=0)
    salt, iv = os.urandom(16), os.urandom(12)
    encrypted = AESGCM(derive(password, salt, iterations)).encrypt(iv, raw, None)
    return {"salt": b64(salt), "iv": b64(iv), "iter": iterations, "gz": True, "ct": b64(encrypted)}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--archive", required=True)
    p.add_argument("--inbox", required=True)
    p.add_argument("--output", required=True)
    args = p.parse_args()

    password = os.environ.get("DIARY_PASSWORD", "")
    private_b64 = os.environ.get("INGEST_PRIVATE_KEY_B64", "")
    if not password or not private_b64:
        raise SystemExit("Missing DIARY_PASSWORD or INGEST_PRIVATE_KEY_B64 secrets. No changes made.")

    private = serialization.load_pem_private_key(ub64(private_b64), password=None)
    docs, iterations = decrypt_diary(Path(args.archive).read_bytes(), password)
    existing = {
        (doc.get("date"), doc.get("entity")): i
        for i, doc in enumerate(docs)
        if isinstance(doc, dict) and doc.get("date") and doc.get("entity") and doc.get("kind") != "month"
    }
    paths = sorted(Path(args.inbox).glob("*.sealed.json"))
    if not paths:
        raise SystemExit("No encrypted reports found in inbox")
    imported = []
    for path in paths:
        report = decrypt_sealed(path, private)
        key = (report["date"], report["entity"])
        if key in existing:
            docs[existing[key]] = report
        else:
            existing[key] = len(docs)
            docs.append(report)
        imported.append(report["date"] + " " + report["entity"])
    Path(args.output).write_text(
        json.dumps(encrypt_diary(docs, password, iterations), separators=(",", ":")),
        encoding="utf-8",
    )
    print("Encrypted reports merged:", ", ".join(imported), "; archive items:", len(docs))


if __name__ == "__main__":
    main()
