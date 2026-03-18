#!/usr/bin/env python3
"""Upload a TLS certificate and private key to an AMI MegaRAC BMC.

The BMC web UI uses a legacy REST API that is separate from Redfish.
Authentication is form-encoded POST to /api/session; upload is multipart
POST to /api/settings/ssl/certificate.

Credentials may be supplied directly or fetched from HashiCorp Vault (KV v2).
When --username/--password are omitted the script calls the 'vault' CLI using
VAULT_ADDR from the environment and a token read from
/etc/vault/oob-cert-installer-token.  The secret path defaults to:
  VAULT_BMC_PATH/<hostname>      (hostname derived from --bmc-url, see global)
Override with --vault-path.

Examples:
    # Explicit credentials
    ./ami-bmc-cert-upload.py \\
        --bmc-url https://server-oob.example.com/ \\
        --username admin --password secretsquirrel \\
        --cert-file server-oob.example.com-fullchain.pem \\
        --key-file  server-oob.example.com-key.pem

    # Credentials from Vault
    export VAULT_ADDR=https://vault.example.com
    ./ami-bmc-cert-upload.py \\
        --bmc-url https://server-oob.example.com/ \\
        --cert-file server-oob.example.com-fullchain.pem \\
        --key-file  server-oob.example.com-key.pem
"""

# pylint: disable=invalid-name  # filename uses hyphens per project convention
import argparse
import json
import os
import subprocess
import sys
import urllib.request
import urllib.parse
import urllib.error
import ssl
import http.cookiejar

VAULT_TOKEN_FILE = "/etc/vault.d/oob-cert-installer-token"
VAULT_BMC_PATH = "my-infra/oob"


def die(msg):
    """Print an error message to stderr and exit with code 1."""
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def fetch_vault_credentials(vault_path):
    """Return (username, password) from Vault KV v2 using the vault CLI."""
    vault_addr = os.environ.get("VAULT_ADDR", "").rstrip("/")
    if not vault_addr:
        die("VAULT_ADDR environment variable is not set")

    try:
        with open(VAULT_TOKEN_FILE, encoding="utf-8") as fh:
            token = fh.read().strip()
    except OSError as e:
        die(f"Cannot read Vault token from {VAULT_TOKEN_FILE}: {e}")

    env = {**os.environ, "VAULT_TOKEN": token, "VAULT_ADDR": vault_addr}
    try:
        result = subprocess.run(
            ["vault", "kv", "get", "-format=json", vault_path],
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except FileNotFoundError:
        die(
            "'vault' command not found — install the Vault CLI or provide --username/--password"
        )
    except subprocess.TimeoutExpired:
        die("vault command timed out")

    if result.returncode != 0:
        die(f"vault kv get failed: {result.stderr.strip()}")

    try:
        data = json.loads(result.stdout)
        secret = data["data"]["data"]
        username = secret["username"]
        password = secret["password"]
    except (KeyError, json.JSONDecodeError) as e:
        die(f"Unexpected vault output parsing {vault_path!r}: {e}")

    print(f"Credentials fetched from Vault: {vault_path}")
    return username, password


def build_session(bmc_url, username, password, ctx):
    """Login and return (csrf_token, opener).

    The opener retains the session cookie in its CookieJar and must be
    reused for all subsequent requests so the cookie is sent automatically.
    """
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(cj),
    )

    body = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = urllib.request.Request(
        bmc_url.rstrip("/") + "/api/session",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with opener.open(req, timeout=30) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        die(f"Login failed: HTTP {e.code} {e.reason}")
    except (urllib.error.URLError, OSError) as e:
        die(f"Login request failed: {e}")

    csrf = data.get("CSRFToken")
    if not csrf:
        die(f"No CSRFToken in login response: {data}")

    if not any(c.name == "QSESSIONID" for c in cj):
        die("No QSESSIONID cookie in login response")

    return csrf, opener


def logout(bmc_url, csrf_token, opener):
    """Send DELETE /api/session to close the BMC session; best-effort, ignores errors."""
    req = urllib.request.Request(
        bmc_url.rstrip("/") + "/api/session",
        headers={"X-CSRFTOKEN": csrf_token},
        method="DELETE",
    )
    try:
        opener.open(req, timeout=10)
    except (urllib.error.URLError, OSError):
        pass  # Best-effort logout


def upload_certificate(
    bmc_url, csrf_token, cert_file, key_file, opener
):  # pylint: disable=too-many-locals
    """Upload cert + key as multipart/form-data using the established session opener."""
    boundary = "----BMCCertUploadBoundary"

    def field(name, filename, data):
        return (
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + data
            + b"\r\n"
        )

    with open(cert_file, "rb") as f:
        cert_data = f.read()
    with open(key_file, "rb") as f:
        key_data = f.read()

    body = (
        field("new_certificate", "certificate.pem", cert_data)
        + field("new_private_key", "private_key.pem", key_data)
        + f"--{boundary}--\r\n".encode()
    )

    req = urllib.request.Request(
        bmc_url.rstrip("/") + "/api/settings/ssl/certificate",
        data=body,
        headers={
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "X-CSRFTOKEN": csrf_token,
        },
        method="POST",
    )
    try:
        with opener.open(req, timeout=60) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        body_text = e.read().decode(errors="replace")
        die(f"Upload failed: HTTP {e.code} {e.reason} — {body_text}")
    except (urllib.error.URLError, OSError) as e:
        die(f"Upload request failed: {e}")

    if data.get("cc") != 0:
        die(f"Upload rejected by BMC: {data}")

    return data


def main():
    """Parse arguments and orchestrate the cert upload."""
    parser = argparse.ArgumentParser(
        description="Upload a TLS certificate and key to an AMI MegaRAC BMC."
    )
    parser.add_argument(
        "--bmc-url", required=True, help="BMC base URL, e.g. https://192.168.1.10/"
    )
    parser.add_argument(
        "--username", default=None, help="BMC username (omit to fetch from Vault)"
    )
    parser.add_argument(
        "--password", default=None, help="BMC password (omit to fetch from Vault)"
    )
    parser.add_argument(
        "--vault-path",
        default=None,
        help="Vault KV v2 path (default: VAULT_BMC_PATH/<hostname>)",
    )
    parser.add_argument(
        "--cert-file", required=True, help="PEM certificate file (leaf or full-chain)"
    )
    parser.add_argument("--key-file", required=True, help="PEM private key file")
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip TLS verification (use when BMC has self-signed cert)",
    )
    args = parser.parse_args()

    username = args.username
    password = args.password

    if not username or not password:
        hostname = urllib.parse.urlparse(args.bmc_url).hostname
        vault_path = args.vault_path or f"{VAULT_BMC_PATH}/{hostname}"
        username, password = fetch_vault_credentials(vault_path)

    ctx = ssl.create_default_context()
    if args.no_verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    print(f"Logging in to {args.bmc_url} ...")
    csrf_token, opener = build_session(args.bmc_url, username, password, ctx)

    try:
        print(f"Uploading {args.cert_file} + {args.key_file} ...")
        result = upload_certificate(
            args.bmc_url,
            csrf_token,
            args.cert_file,
            args.key_file,
            opener,
        )
        print(
            f"Success (cc={result.get('cc')})."
            " BMC will use the new certificate on next TLS handshake."
        )
    finally:
        logout(args.bmc_url, csrf_token, opener)
        print("Session closed.")


if __name__ == "__main__":
    main()
