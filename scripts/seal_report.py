#!/usr/bin/env python3
"""Seal one report with a public key. Never commit plaintext daily report JSON."""
import argparse
import base64
import json
import os
from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def b64(data):
    return base64.b64encode(data).decode("ascii")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--public-key", default="security/ingest-public.pem")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    payload = Path(args.report).read_bytes()
    report = json.loads(payload)
    if not report.get("date") or report.get("entity") not in ("WH", "FX"):
        raise ValueError("Invalid daily report")
    public = serialization.load_pem_public_key(Path(args.public_key).read_bytes())
    key, iv = os.urandom(32), os.urandom(12)
    wrapped = public.encrypt(
        key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    encrypted = AESGCM(key).encrypt(iv, payload, b"ozon-daily-report-v1")
    Path(args.output).write_text(
        json.dumps({
            "version": 1,
            "type": "ozon-daily-report",
            "wrappedKey": b64(wrapped),
            "iv": b64(iv),
            "ct": b64(encrypted),
        }, separators=(",", ":")), encoding="utf-8",
    )
    print("Encrypted report written:", args.output)


if __name__ == "__main__":
    main()
