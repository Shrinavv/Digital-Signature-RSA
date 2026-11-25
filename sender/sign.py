"""Sign a message with the sender's private key (RSA, PKCS#1 v1.5, SHA-256)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.rsa_utils import ROOT, read_key, sign_message

message = input("✍️ Enter the message to be signed: ").strip()
if not message:
    print("❌ Error: message cannot be empty.")
    sys.exit(1)

try:
    d, n = read_key(ROOT / "sender" / "private_key.txt")
except FileNotFoundError:
    print("❌ Error: sender/private_key.txt not found. Run: python sender/keygen.py")
    sys.exit(1)

(ROOT / "sender" / "message.txt").write_text(message)
print("📩 Message saved to sender/message.txt")

signature = sign_message(message, d, n)
(ROOT / "sender" / "signed_message.txt").write_text(f"{message}\n{signature}")
print("✅ Message signed and saved to sender/signed_message.txt")
