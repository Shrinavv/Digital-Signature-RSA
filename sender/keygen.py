"""Generate the sender's RSA key pair (default 2048 bits)."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.rsa_utils import ROOT, DEFAULT_KEY_BITS, generate_keys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--bits", type=int, default=DEFAULT_KEY_BITS, help="modulus size in bits (default 2048)")
args = parser.parse_args()

generate_keys(ROOT / "sender", bits=args.bits)
print(f"✅ Sender's {args.bits}-bit keys generated in sender/")
