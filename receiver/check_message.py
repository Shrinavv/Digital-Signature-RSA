"""Display the received message and its signature.

Usage: python receiver/check_message.py [path-to-signed-file]
Default file: receiver/checked_message.txt (written by the server).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.rsa_utils import ROOT, read_signed_file

path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "receiver" / "checked_message.txt"
if not path.exists():
    print(f"❌ Error: {path} not found. Send a message first (python sender/transmit.py).")
    sys.exit(1)

try:
    message, signature = read_signed_file(path)
except ValueError as exc:
    print(f"❌ Error: invalid file format: {exc}")
    sys.exit(1)

print(f"📨 Received Message: {message}")
print(f"✍️ Signature: {signature}")
