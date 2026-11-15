"""Shared sanitiser for text that comes from outside (RFCs, Wikipedia, .unl names): remove characters that can hide or spoof content.

Removed: C0/C1 controls except tab and newline, soft hyphen, combining grapheme joiner, Arabic letter mark, Hangul/Khmer/Mongolian fillers
and selectors, zero-width and bidi marks and overrides (U+200B-200F, U+2028-202E, U+2060-206F), variation selectors (FE00-FE0F, E0100-E01EF),
lone surrogates, BOM, interlinear annotation marks, Unicode TAG characters (U+E0000-E0FFF), invisible musical/shorthand format characters, and the remaining Unicode format (Cf) characters: Arabic/Syriac number and end-of-ayah marks, Kaithi number signs, Egyptian hieroglyph format controls (review H2-6).
This lowers the chance of hidden instructions reaching a model; it does not make untrusted text trustworthy.
"""
import re

_HIDDEN = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2028-\u202e\u2060-\u206f"
    "\u0600-\u0605\u06dd\u070f\u0890\u0891\u08e2\U000110bd\U000110cd\U00013430-\U0001343f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff\ud800-\udfff]")


def strip_hidden(text) -> str:
    return _HIDDEN.sub("", str(text))


def flatten(text) -> str:
    """strip_hidden plus tab/newline/carriage return turned into spaces: for names and titles that must stay on one line."""
    return re.sub(r"[\t\n\r]+", " ", strip_hidden(text))
