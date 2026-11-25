"""Verify a signed message with the SENDER's public key.

Usage: python receiver/verify.py [signed-file] [sender-public-key]
Defaults: receiver/checked_message.txt and sender/public_key.txt
Exit code: 0 = valid, 1 = invalid or error.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.rsa_utils import ROOT, read_key, read_signed_file, verify_signature

signed_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "receiver" / "checked_message.txt"
pubkey_path = Path(sys.argv[2]) if len(sys.argv) > 2 else ROOT / "sender" / "public_key.txt"

try:
    e, n = read_key(pubkey_path)
    message, signature = read_signed_file(signed_path)
except FileNotFoundError as exc:
    print(f"❌ Error: file not found: {exc.filename}")
    sys.exit(1)
except ValueError as exc:
    print(f"❌ Error: invalid file format: {exc}")
    sys.exit(1)

if verify_signature(message, signature, e, n):
    print("✅ Signature is valid! Message integrity verified.")
else:
    print("❗ Signature is invalid! Message may have been tampered.")
    sys.exit(1)
