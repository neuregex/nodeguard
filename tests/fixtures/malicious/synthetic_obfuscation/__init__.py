"""TEST FIXTURE — SYNTHETIC OBFUSCATION. NOT REAL MALWARE.

Exercises the obfuscation detectors added in v0.5. Every construct lives
inside an `if False:` block so importing this fixture does nothing; the
AST visitor still sees the structures.
"""

# Cyrillic 'е' (U+0435) in an otherwise-Latin identifier (homoglyph attack).
еval_lookalike = None

# Confusable identifier salad.
_o0o = 1
_l1l = 2
_1lI = 3

# Underscore-prefixed short consonant clusters.
_qq = 4
_zz = 5

# All-underscore name.
__ = 6

if False:
    # Char-code chain spelling "eval"
    _kw = chr(101) + chr(118) + chr(97) + chr(108)
    # String split-concat spelling "system"
    _cmd = "s" + "y" + "s" + "t" + "e" + "m"
    # Nested decoder chain: zlib.decompress(b64decode(...))
    import base64
    import zlib

    _payload = zlib.decompress(base64.b64decode("eJxLSi0qSk0EAA=="))
    # High-entropy literal that's clearly an encoded blob
    _blob = "aB7c+xZ9pQ/L3mNoR4tFhKvWj1eXr2sUoY5Tn9pZqXkH3vEcRfDmA7tKgWuPbNiO==xZ9pQ"


def innocuous():
    return (еval_lookalike, _o0o, _l1l, _1lI, _qq, _zz, __)
