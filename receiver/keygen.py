"""Generate the receiver's RSA key pair (reserved for future encryption)."""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.rsa_utils import ROOT, DEFAULT_KEY_BITS, generate_keys

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--bits", type=int, default=DEFAULT_KEY_BITS)
args = parser.parse_args()

generate_keys(ROOT / "receiver", bits=args.bits)
print(f"✅ Receiver's {args.bits}-bit keys generated in receiver/")
