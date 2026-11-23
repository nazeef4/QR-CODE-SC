"""QR image rendering (Pillow + qrcode)."""
from __future__ import annotations

import io

import qrcode
from qrcode.constants import ERROR_CORRECT_M


def render_qr(payload: str, *, size: int = 512) -> bytes:
    """Render an SCQR1 payload to a PNG byte string.

    ECC level M gives ~15% recovery — a practical default for printed
    packaging; the payload itself is integrity-protected by signature, so
    error correction only needs to survive print wear, not forgery.
    """
    qr = qrcode.QRCode(
        error_correction=ERROR_CORRECT_M,
        box_size=max(1, size // 60),
        border=2,
    )
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()
