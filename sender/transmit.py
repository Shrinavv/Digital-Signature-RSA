"""POST sender/signed_message.txt to the server over HTTPS.

Usage:
    python sender/transmit.py                      # local server (self-signed cert)
    python sender/transmit.py --url https://my-app.onrender.com/api/receive
Works from any directory.
"""
import argparse
import os
import sys
from pathlib import Path
from urllib.parse import urlparse

import requests
import urllib3

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from utils.rsa_utils import ROOT

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--url", default=os.environ.get("SIGNATURE_SERVER_URL", "https://127.0.0.1:5000/api/receive"))
parser.add_argument("--file", default=str(ROOT / "sender" / "signed_message.txt"))
args = parser.parse_args()

path = Path(args.file)
if not path.exists():
    print("❌ Error: signed message not found. Run: python sender/sign.py")
    sys.exit(1)

# The local dev server uses a self-signed certificate, so skip verification ONLY for localhost.
host = urlparse(args.url).hostname
is_local = host in ("127.0.0.1", "localhost", "::1")
if is_local:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

try:
    response = requests.post(
        args.url,
        data={"signed_message": path.read_text()},
        verify=not is_local,
        timeout=15,
    )
except requests.exceptions.RequestException as exc:
    print(f"❌ Error: {exc}")
    sys.exit(1)

if response.status_code == 200:
    print("📡 Message successfully transmitted to the receiver via HTTPS!")
else:
    print(f"❌ Error: server returned {response.status_code}: {response.text.strip()}")
    sys.exit(1)
