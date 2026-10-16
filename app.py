
import base64
import binascii
import zlib
import os
import re

import dash
import dash_bootstrap_components as dbc
from dash import dcc, html
from dash.dependencies import Input, Output, State
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# ============================================================
# CONFIGURATION
# ============================================================

APP_TITLE = "File Encryption & Decryption Dashboard"

KEY_SIZE = 32
NONCE_SIZE = 12
TAG_SIZE = 16

app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.DARKLY],
    title="SecureVault | File Security",
    suppress_callback_exceptions=False
)

server = app.server

# Deployment-safe limits. Override MAX_FILE_SIZE_MB in Render environment variables.
MAX_FILE_SIZE = max(1, int(os.getenv("MAX_FILE_SIZE_MB", "8"))) * 1024 * 1024
MAX_DECOMPRESSED_SIZE = max(8, int(os.getenv("MAX_DECOMPRESSED_SIZE_MB", "64"))) * 1024 * 1024
# Dash uploads are base64 encoded, so allow room for encoding overhead.
server.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE * 2


# ============================================================
# CUSTOM CSS
# ============================================================

app.index_string = """
<!DOCTYPE html>
<html>
<head>
    {%metas%}
    <title>{%title%}</title>
    {%favicon%}
    {%css%}
    <style>
        :root {
            --bg: #080b14;
            --panel: #101625;
            --panel-light: #151d30;
            --border: rgba(148, 163, 184, 0.15);
            --text: #eef2ff;
            --muted: #8995ad;
            --blue: #5b8cff;
            --cyan: #46e6e1;
            --purple: #a78bfa;
            --green: #46e6a0;
            --red: #ff718b;
        }

        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            background: var(--bg);
            color: var(--text);
            font-family: Inter, "Segoe UI", sans-serif;
        }

        .app-shell {
            min-height: 100vh;
            background:
                radial-gradient(
                    ellipse at 10% 0%,
                    rgba(59, 130, 246, 0.13),
                    transparent 38%
                ),
                radial-gradient(
                    ellipse at 90% 20%,
                    rgba(139, 92, 246, 0.11),
                    transparent 35%
                ),
                var(--bg);
            padding: 26px 0 42px;
        }

        .main-container {
            max-width: 1250px;
            margin: auto;
            padding: 0 24px;
        }

        .topbar {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 18px;
            padding: 8px 0 28px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 35px;
        }

        .brand {
            display: flex;
            align-items: center;
            gap: 13px;
        }

        .brand-icon {
            width: 48px;
            height: 48px;
            border-radius: 15px;
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 24px;
            background: linear-gradient(135deg, #3267f5, #8b5cf6);
            box-shadow: 0 0 30px rgba(91, 140, 255, 0.25);
        }

        .brand-name {
            font-weight: 800;
            font-size: 21px;
            letter-spacing: 0.3px;
            color: var(--text);
        }

        .brand-subtitle {
            font-size: 12px;
            color: var(--muted);
            margin-top: 3px;
        }

        .security-badge {
            border: 1px solid rgba(70, 230, 160, 0.25);
            color: var(--green);
            background: rgba(70, 230, 160, 0.07);
            padding: 9px 14px;
            border-radius: 30px;
            font-size: 12px;
            white-space: nowrap;
        }

        .hero {
            text-align: center;
            padding: 18px 0 35px;
        }

        .eyebrow {
            color: var(--cyan);
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 2.8px;
            text-transform: uppercase;
            margin-bottom: 17px;
        }

        .hero h1 {
            color: var(--text);
            font-weight: 850;
            letter-spacing: -1.4px;
            font-size: clamp(30px, 4.5vw, 48px);
            margin-bottom: 14px;
        }

        .gradient-text {
            background: linear-gradient(90deg, #66a3ff, #b79bff, #46e6e1);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
        }

        .hero-description {
            max-width: 650px;
            margin: auto;
            color: var(--muted);
            font-size: 15px;
            line-height: 1.8;
        }

        .feature-row {
            display: flex;
            justify-content: center;
            gap: 10px;
            flex-wrap: wrap;
            margin-top: 24px;
        }

        .feature-pill {
            border: 1px solid var(--border);
            background: rgba(255,255,255,0.025);
            color: #bac5dc;
            border-radius: 30px;
            padding: 8px 13px;
            font-size: 12px;
        }

        .section-label {
            color: #9aa8c2;
            font-size: 11px;
            font-weight: 800;
            letter-spacing: 2px;
            text-transform: uppercase;
            margin: 8px 0 17px;
        }

        .glass-card {
            background: linear-gradient(
                150deg,
                rgba(20, 29, 47, 0.98),
                rgba(12, 17, 30, 0.98)
            );
            border: 1px solid var(--border) !important;
            border-radius: 20px !important;
            box-shadow: 0 16px 45px rgba(0, 0, 0, 0.16);
            height: 100%;
            overflow: hidden;
            transition: border-color 0.2s, transform 0.2s;
        }

        .glass-card:hover {
            border-color: rgba(91, 140, 255, 0.4) !important;
            transform: translateY(-2px);
        }

        .card-top {
            padding: 24px 24px 19px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            gap: 14px;
        }

        .card-icon {
            width: 45px;
            height: 45px;
            flex-shrink: 0;
            border-radius: 13px;
            display: flex;
            justify-content: center;
            align-items: center;
            font-size: 22px;
        }

        .icon-blue {
            background: rgba(91, 140, 255, 0.13);
            border: 1px solid rgba(91, 140, 255, 0.2);
        }

        .icon-purple {
            background: rgba(167, 139, 250, 0.13);
            border: 1px solid rgba(167, 139, 250, 0.2);
        }

        .card-heading {
            font-size: 17px;
            font-weight: 750;
            color: var(--text);
            margin: 0;
        }

        .card-subheading {
            color: var(--muted);
            font-size: 12px;
            margin-top: 5px;
        }

        .card-content {
            padding: 23px 24px 25px;
        }

        .upload-zone {
            min-height: 160px;
            border: 1.5px dashed rgba(91, 140, 255, 0.45);
            border-radius: 15px;
            background: rgba(91, 140, 255, 0.045);
            display: flex;
            justify-content: center;
            align-items: center;
            text-align: center;
            padding: 20px;
            cursor: pointer;
            transition: all 0.2s;
        }

        .upload-zone:hover {
            background: rgba(91, 140, 255, 0.1);
            border-color: var(--blue);
        }

        .upload-symbol {
            font-size: 29px;
            margin-bottom: 12px;
        }

        .upload-title {
            font-weight: 700;
            color: var(--text);
            font-size: 14px;
        }

        .upload-hint {
            color: var(--muted);
            font-size: 12px;
            margin-top: 7px;
        }

        .file-info {
            min-height: 42px;
            margin: 12px 0 17px;
            padding: 10px 12px;
            background: rgba(255,255,255,0.025);
            border: 1px solid var(--border);
            border-radius: 10px;
            color: #aab7cf;
            font-size: 12px;
            overflow-wrap: anywhere;
        }

        .action-button {
            width: 100%;
            border: none !important;
            border-radius: 11px !important;
            padding: 13px 16px !important;
            color: white !important;
            font-weight: 750 !important;
            font-size: 13px !important;
            transition: all 0.2s !important;
        }

        .encrypt-button {
            background: linear-gradient(100deg, #386cf6, #7556ed) !important;
            box-shadow: 0 8px 22px rgba(75, 104, 240, 0.18);
        }

        .decrypt-button {
            background: linear-gradient(100deg, #087e8b, #159e9b) !important;
            box-shadow: 0 8px 22px rgba(21, 158, 155, 0.15);
        }

        .action-button:hover {
            filter: brightness(1.15);
            transform: translateY(-1px);
        }

        .action-button:disabled {
            opacity: 0.5;
            cursor: not-allowed;
        }

        .result-box {
            margin-top: 16px;
            overflow-wrap: anywhere;
            font-size: 13px;
        }

        .download-link {
            display: flex;
            justify-content: center;
            align-items: center;
            text-align: center;
            gap: 8px;
            width: 100%;
            text-decoration: none;
            color: #c3d7ff !important;
            background: rgba(91, 140, 255, 0.09);
            border: 1px solid rgba(91, 140, 255, 0.24);
            border-radius: 10px;
            padding: 12px;
            margin-top: 10px;
            font-weight: 650;
            font-size: 12px;
        }

        .download-link:hover {
            background: rgba(91, 140, 255, 0.17);
        }

        .form-label {
            color: #c6d1e6;
            font-size: 12px;
            font-weight: 700;
            margin-bottom: 9px;
        }

        .custom-input {
            background: #0b1120 !important;
            color: var(--text) !important;
            border: 1px solid var(--border) !important;
            border-radius: 10px !important;
            padding: 11px 12px !important;
            font-size: 13px !important;
        }

        .custom-input:focus {
            border-color: var(--blue) !important;
            box-shadow: 0 0 0 3px rgba(91, 140, 255, 0.1) !important;
        }

        .stats-section {
            margin-top: 32px;
        }

        .stats-card {
            background: rgba(16, 22, 37, 0.85);
            border: 1px solid var(--border);
            border-radius: 15px;
            padding: 20px;
            height: 100%;
        }

        .stat-label {
            color: var(--muted);
            font-size: 11px;
            margin-bottom: 10px;
        }

        .stat-value {
            font-size: 22px;
            font-weight: 800;
            color: var(--text);
            overflow-wrap: anywhere;
        }

        .stat-note {
            color: var(--muted);
            font-size: 11px;
            margin-top: 6px;
        }

        .notice {
            margin-top: 24px;
            padding: 16px 18px;
            border-radius: 13px;
            border: 1px solid rgba(70, 230, 225, 0.16);
            background: rgba(70, 230, 225, 0.035);
            color: #a9cbd3;
            font-size: 12px;
            line-height: 1.8;
        }

        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            gap: 12px;
            flex-wrap: wrap;
            color: var(--muted);
            font-size: 11px;
        }

        .footer strong {
            color: #b6c5df;
        }

        @media (max-width: 767px) {
            .main-container {
                padding: 0 15px;
            }

            .topbar {
                align-items: flex-start;
            }

            .security-badge {
                font-size: 10px;
                padding: 7px 9px;
            }

            .brand-name {
                font-size: 18px;
            }

            .card-content, .card-top {
                padding-left: 18px;
                padding-right: 18px;
            }

            .hero h1 {
                letter-spacing: -0.6px;
            }
        }
    </style>
</head>
<body>
    {%app_entry%}
    <footer>
        {%config%}
        {%scripts%}
        {%renderer%}
    </footer>
</body>
</html>
"""


# ============================================================
# SECURITY AND FILE UTILITIES
# ============================================================

def format_size(size):
    """Return a human-readable file size."""
    size = float(size)

    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{size:.2f} {unit}"
        size /= 1024

    return f"{size:.2f} GB"


def decode_upload(contents):
    """Decode a Dash upload data URI and enforce a size limit."""
    if not contents or "," not in contents:
        raise ValueError("Please upload a valid file.")

    try:
        encoded = contents.split(",", 1)[1]
        # Reject oversized payloads before allocating decoded bytes.
        if len(encoded) > ((MAX_FILE_SIZE + 2) // 3) * 4 + 8:
            raise ValueError("File exceeds the upload limit.")
        data = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("The uploaded file is invalid or exceeds the upload limit.") from exc

    if len(data) > MAX_FILE_SIZE:
        raise ValueError(f"Files must be {MAX_FILE_SIZE // (1024 * 1024)} MB or smaller.")
    return data


def decode_key(contents):
    """Accept the current hex-text key format and legacy raw 32-byte keys."""
    key_data = decode_upload(contents)
    if len(key_data) == KEY_SIZE:
        return key_data
    try:
        key_text = key_data.decode("ascii").strip()
        key = bytes.fromhex(key_text)
        if len(key) == KEY_SIZE:
            return key
    except (UnicodeDecodeError, ValueError):
        pass
    raise ValueError("The key file must contain a valid 256-bit key.")


def compress_data(data):
    return zlib.compress(data)


def decompress_data(data):
    """Decompress with an output limit to reduce decompression-bomb risk."""
    try:
        decompressor = zlib.decompressobj()
        result = decompressor.decompress(data, MAX_DECOMPRESSED_SIZE + 1)
        if len(result) > MAX_DECOMPRESSED_SIZE or decompressor.unconsumed_tail:
            raise ValueError("Decompressed file exceeds the allowed size limit.")
        result += decompressor.flush(MAX_DECOMPRESSED_SIZE + 1 - len(result))
        if len(result) > MAX_DECOMPRESSED_SIZE:
            raise ValueError("Decompressed file exceeds the allowed size limit.")
        if not decompressor.eof:
            raise ValueError("Compressed data is incomplete or invalid.")
        return result
    except zlib.error as exc:
        raise ValueError("Compressed data is invalid.") from exc


def encrypt_data(data, key):
    """Encrypt using AES-256-GCM."""
    if len(key) != KEY_SIZE:
        raise ValueError("The encryption key must be 32 bytes.")

    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Compatible with the previous version:
    # nonce + authentication tag + ciphertext
    return nonce + tag + ciphertext


def decrypt_data(encrypted_data, key):
    """Authenticate and decrypt the existing file format."""
    if len(key) != KEY_SIZE:
        raise ValueError("The encryption key must be 32 bytes.")

    if len(encrypted_data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("The encrypted file is incomplete.")

    nonce = encrypted_data[:NONCE_SIZE]
    tag = encrypted_data[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = encrypted_data[NONCE_SIZE + TAG_SIZE:]

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def download_link(data, filename, label):
    """Create a browser download link."""
    encoded = base64.b64encode(data).decode("ascii")

    return html.A(
        [html.Span("↓"), html.Span(label)],
        href=f"data:application/octet-stream;base64,{encoded}",
        download=filename,
        className="download-link"
    )


def stat_card(label, value, note=""):
    return dbc.Col(
        html.Div(
            [
                html.Div(label, className="stat-label"),
                html.Div(value, className="stat-value"),
                html.Div(note, className="stat-note")
            ],
            className="stats-card"
        ),
        xs=6,
        lg=3,
        className="mb-3"
    )


def upload_zone(upload_id, title, hint, symbol):
    return dcc.Upload(
        id=upload_id,
        children=html.Div(
            [
                html.Div(symbol, className="upload-symbol"),
                html.Div(title, className="upload-title"),
                html.Div(hint, className="upload-hint")
            ]
        ),
        className="upload-zone",
        multiple=False
    )


# ============================================================
# DASHBOARD LAYOUT
# ============================================================

app.layout = html.Div(
    className="app-shell",
    children=[
        html.Div(
            className="main-container",
            children=[
                # Header
                html.Div(
                    className="topbar",
                    children=[
                        html.Div(
                            className="brand",
                            children=[
                                html.Div("🔐", className="brand-icon"),
                                html.Div(
                                    [
                                        html.Div(
                                            "SECUREVAULT",
                                            className="brand-name"
                                        ),
                                        html.Div(
                                            "PERSONAL FILE SECURITY",
                                            className="brand-subtitle"
                                        )
                                    ]
                                )
                            ]
                        ),
                        html.Div(
                            "●  AES-256 GCM",
                            className="security-badge"
                        )
                    ]
                ),

                # Hero section
                html.Div(
                    className="hero",
                    children=[
                        html.Div(
                            "PRIVACY • PROTECTION • CONTROL",
                            className="eyebrow"
                        ),
                        html.H1(
                            [
                                "Your Files. ",
                                html.Span(
                                    "Your Security.",
                                    className="gradient-text"
                                )
                            ]
                        ),
                        html.P(
                            "Compress, encrypt, and decrypt your files "
                            "with authenticated AES-256 encryption. "
                            "Simple workflow, powerful protection.",
                            className="hero-description"
                        ),
                        html.Div(
                            [
                                html.Span(
                                    "✦ AES-256-GCM",
                                    className="feature-pill"
                                ),
                                html.Span(
                                    "↗ Zlib Compression",
                                    className="feature-pill"
                                ),
                                html.Span(
                                    "✓ Tamper Detection",
                                    className="feature-pill"
                                ),
                                html.Span(
                                    "◈ Separate Key File",
                                    className="feature-pill"
                                )
                            ],
                            className="feature-row"
                        )
                    ]
                ),

                html.Div(
                    "01  /  ENCRYPT YOUR FILE",
                    className="section-label"
                ),

                dbc.Row(
                    [
                        # Encryption panel
                        dbc.Col(
                            dbc.Card(
                                [
                                    html.Div(
                                        [
                                            html.Div(
                                                "↗",
                                                className="card-icon icon-blue"
                                            ),
                                            html.Div(
                                                [
                                                    html.H2(
                                                        "Encrypt & Compress",
                                                        className="card-heading"
                                                    ),
                                                    html.Div(
                                                        "Protect a file with a "
                                                        "new encryption key",
                                                        className="card-subheading"
                                                    )
                                                ]
                                            )
                                        ],
                                        className="card-top"
                                    ),
                                    html.Div(
                                        [
                                            upload_zone(
                                                "upload-file",
                                                "Drop your file here",
                                                "or click to browse · max 8 MB",
                                                "⇧"
                                            ),
                                            html.Div(
                                                "No file selected yet",
                                                id="file-info",
                                                className="file-info"
                                            ),
                                            dbc.Button(
                                                "🔒  Encrypt & Compress",
                                                id="encrypt-btn",
                                                n_clicks=0,
                                                className=(
                                                    "action-button "
                                                    "encrypt-button"
                                                )
                                            ),
                                            html.Div(
                                                id="encrypt-result",
                                                className="result-box"
                                            ),
                                            html.Div(
                                                id="download-encrypted",
                                                className="result-box"
                                            ),
                                            html.Div(
                                                id="download-key",
                                                className="result-box"
                                            )
                                        ],
                                        className="card-content"
                                    )
                                ],
                                className="glass-card"
                            ),
                            md=6,
                            className="mb-4"
                        ),

                        # Decryption panel
                        dbc.Col(
                            dbc.Card(
                                [
                                    html.Div(
                                        [
                                            html.Div(
                                                "↙",
                                                className="card-icon icon-purple"
                                            ),
                                            html.Div(
                                                [
                                                    html.H2(
                                                        "Decrypt & Restore",
                                                        className="card-heading"
                                                    ),
                                                    html.Div(
                                                        "Restore your original "
                                                        "file using its key",
                                                        className="card-subheading"
                                                    )
                                                ]
                                            )
                                        ],
                                        className="card-top"
                                    ),
                                    html.Div(
                                        [
                                            upload_zone(
                                                "upload-encrypted",
                                                "Drop encrypted file",
                                                "select your .aes file · max 8 MB",
                                                "▣"
                                            ),
                                            html.Div(
                                                "No encrypted file selected",
                                                id="encrypted-info",
                                                className="file-info"
                                            ),
                                            upload_zone(
                                                "upload-key",
                                                "Drop your key file",
                                                "select your key file · max 8 MB",
                                                "⚿"
                                            ),
                                            html.Div(
                                                "No key file selected",
                                                id="key-info",
                                                className="file-info"
                                            ),
                                            html.Label(
                                                "Output filename",
                                                className="form-label"
                                            ),
                                            dcc.Input(
                                                id="output-filename",
                                                type="text",
                                                value="decrypted.txt",
                                                className="form-control custom-input",
                                                debounce=True
                                            ),
                                            html.Div(style={"height": "17px"}),
                                            dbc.Button(
                                                "🔓  Decrypt & Decompress",
                                                id="decrypt-btn",
                                                n_clicks=0,
                                                className=(
                                                    "action-button "
                                                    "decrypt-button"
                                                )
                                            ),
                                            html.Div(
                                                id="decrypt-result",
                                                className="result-box"
                                            ),
                                            html.Div(
                                                id="download-decrypted",
                                                className="result-box"
                                            )
                                        ],
                                        className="card-content"
                                    )
                                ],
                                className="glass-card"
                            ),
                            md=6,
                            className="mb-4"
                        )
                    ]
                ),

                # Statistics
                html.Div(
                    className="stats-section",
                    children=[
                        html.Div(
                            "02  /  ENCRYPTION INSIGHTS",
                            className="section-label"
                        ),
                        dbc.Row(
                            [
                                stat_card(
                                    "ORIGINAL SIZE",
                                    "—",
                                    "Size before compression"
                                ),
                                stat_card(
                                    "COMPRESSED SIZE",
                                    "—",
                                    "Before encryption"
                                ),
                                stat_card(
                                    "ENCRYPTED SIZE",
                                    "—",
                                    "Final downloadable file"
                                ),
                                stat_card(
                                    "SIZE REDUCTION",
                                    "—",
                                    "Compression result"
                                )
                            ],
                            id="stats-row"
                        )
                    ]
                ),

                html.Div(
                    [
                        html.Strong("Security note: "),
                        "Your encryption key is essential for recovery. "
                        "Save it somewhere safe and separate from the "
                        "encrypted file. Losing the key means the original "
                        "data cannot be recovered. This app processes "
                        "uploads in server memory; it does not guarantee "
                        "that files never leave your device."
                    ],
                    className="notice"
                ),

                html.Div(
                    [
                        html.Div(
                            [
                                html.Strong("SECUREVAULT"),
                                "  ·  File Protection Suite"
                            ]
                        ),
                        html.Div("Designed by R. Harsha Kyle")
                    ],
                    className="footer"
                )
            ]
        )
    ]
)


# ============================================================
# FILE INFORMATION CALLBACKS
# ============================================================

@app.callback(
    Output("file-info", "children"),
    Input("upload-file", "contents"),
    State("upload-file", "filename")
)
def show_file_info(contents, filename):
    if not contents:
        return "No file selected yet"

    try:
        data = decode_upload(contents)
        return f"📄  {filename or 'Selected file'}  ·  {format_size(len(data))}"
    except ValueError:
        return "⚠ Invalid upload"


@app.callback(
    Output("encrypted-info", "children"),
    Input("upload-encrypted", "contents"),
    State("upload-encrypted", "filename")
)
def show_encrypted_info(contents, filename):
    if not contents:
        return "No encrypted file selected"

    try:
        data = decode_upload(contents)
        return (
            f"🔐  {filename or 'Encrypted file'}  ·  "
            f"{format_size(len(data))}"
        )
    except ValueError:
        return "⚠ Invalid encrypted file upload"


@app.callback(
    Output("key-info", "children"),
    Input("upload-key", "contents"),
    State("upload-key", "filename")
)
def show_key_info(contents, filename):
    if not contents:
        return "No key file selected"

    try:
        decode_key(contents)
        return f"🔑  {filename or 'Key file'}  ·  Valid AES-256 key"
    except ValueError:
        return "⚠ Invalid key — expected a 256-bit key in hex or raw format"


# ============================================================
# ENCRYPTION CALLBACK
# ============================================================

@app.callback(
    [
        Output("encrypt-result", "children"),
        Output("download-encrypted", "children"),
        Output("download-key", "children"),
        Output("stats-row", "children")
    ],
    Input("encrypt-btn", "n_clicks"),
    State("upload-file", "contents"),
    prevent_initial_call=True
)
def encrypt_file(n_clicks, file_contents):
    empty_stats = [
        stat_card("ORIGINAL SIZE", "—", "Size before compression"),
        stat_card("COMPRESSED SIZE", "—", "Before encryption"),
        stat_card("ENCRYPTED SIZE", "—", "Final downloadable file"),
        stat_card("SIZE REDUCTION", "—", "Compression result")
    ]

    if not file_contents:
        return (
            dbc.Alert(
                "Please choose a file before encrypting.",
                color="warning"
            ),
            "",
            "",
            empty_stats
        )

    try:
        file_data = decode_upload(file_contents)

        # Compression happens before encryption
        compressed_data = compress_data(file_data)
        key = get_random_bytes(KEY_SIZE)
        encrypted_data = encrypt_data(compressed_data, key)

        original_size = len(file_data)
        compressed_size = len(compressed_data)
        encrypted_size = len(encrypted_data)

        reduction = (
            (original_size - compressed_size) / original_size * 100
            if original_size else 0
        )

        stats = [
            stat_card(
                "ORIGINAL SIZE",
                format_size(original_size),
                "Size before compression"
            ),
            stat_card(
                "COMPRESSED SIZE",
                format_size(compressed_size),
                "Before encryption"
            ),
            stat_card(
                "ENCRYPTED SIZE",
                format_size(encrypted_size),
                "Includes nonce and authentication tag"
            ),
            stat_card(
                "SIZE REDUCTION",
                f"{reduction:.1f}%",
                "Positive means smaller; negative means larger"
            )
        ]

        status = dbc.Alert(
            [
                html.Strong("✓  Encryption completed"),
                html.Div(
                    "Your file is compressed and encrypted. "
                    "Download both files below."
                )
            ],
            color="success"
        )

        encrypted_link = download_link(
            encrypted_data,
            "encrypted.aes",
            "↓  Download Encrypted File (.aes)"
        )

        key_link = download_link(
            key.hex().encode("ascii"),
            "encryption_key.txt",
            "⚿  Download Encryption Key (.txt)"
        )

        return status, encrypted_link, key_link, stats

    except (ValueError, zlib.error, TypeError, binascii.Error):
        return (
            dbc.Alert(
                "Encryption failed. Check the uploaded file and try again.",
                color="danger"
            ),
            "",
            "",
            empty_stats
        )

    except Exception:
        return (
            dbc.Alert(
                "An unexpected error occurred during encryption.",
                color="danger"
            ),
            "",
            "",
            empty_stats
        )


# ============================================================
# DECRYPTION CALLBACK
# ============================================================

@app.callback(
    [
        Output("decrypt-result", "children"),
        Output("download-decrypted", "children")
    ],
    Input("decrypt-btn", "n_clicks"),
    State("upload-encrypted", "contents"),
    State("upload-key", "contents"),
    State("output-filename", "value"),
    prevent_initial_call=True
)
def decrypt_file(
    n_clicks,
    encrypted_contents,
    key_contents,
    output_filename
):
    if not encrypted_contents or not key_contents:
        return (
            dbc.Alert(
                "Upload both the encrypted file and its encryption key.",
                color="warning"
            ),
            ""
        )

    try:
        encrypted_data = decode_upload(encrypted_contents)
        key = decode_key(key_contents)

        # Authentication is checked before decompression
        decrypted_data = decrypt_data(encrypted_data, key)
        decompressed_data = decompress_data(decrypted_data)

        # Sanitize output name to prevent path traversal
        filename = (output_filename or "").strip()
        filename = filename.replace("\\", "/").split("/")[-1]

        if not filename or filename in (".", ".."):
            filename = "decrypted.txt"

        status = dbc.Alert(
            [
                html.Strong("✓  Decryption completed"),
                html.Div(
                    f"File authenticated and restored successfully "
                    f"({format_size(len(decompressed_data))})."
                )
            ],
            color="success"
        )

        link = download_link(
            decompressed_data,
            filename,
            f"↓  Download Restored File ({filename})"
        )

        return status, link

    except ValueError:
        return (
            dbc.Alert(
                "Decryption failed. The key or encrypted file is invalid.",
                color="danger"
            ),
            ""
        )

    except (zlib.error, binascii.Error):
        return (
            dbc.Alert(
                "Decryption failed. The file may be corrupted or invalid.",
                color="danger"
            ),
            ""
        )

    except Exception:
        return (
            dbc.Alert(
                "Decryption failed due to an unexpected error.",
                color="danger"
            ),
            ""
        )


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":
    # Local laptop access. For LAN access, use host="0.0.0.0".
    app.run(
        host="0.0.0.0",
        port=int(os.getenv("PORT", "8050")),
        debug=False
    )
