"""Safe cell/paragraph/code-block helpers for the CSV and Markdown exports (pure: unit-tested).

Text in a finding can be influenced by the scanned host (a banner) via the AI. In a spreadsheet a cell starting with = + - @ is a FORMULA
("CSV injection": =HYPERLINK(...), =cmd|...), in Markdown a | breaks a table and <...>/[..](..) become HTML or links, and ``` ends a code block early.
"""
from __future__ import annotations

import re
from typing import Optional

_FORMULA_START = ("=", "+", "-", "@")


def _ws(v: object) -> str:
    return re.sub(r"\s+", " ", "" if v is None else str(v)).strip()


def csv_cell(v: object) -> str:
    """One line of text that a spreadsheet will show as text, never evaluate."""
    s = _ws(v)
    return "'" + s if s.lstrip()[:1] in _FORMULA_START or s[:1] in ("\t", "\r") else s


def md_inline(v: object) -> str:
    """For table cells and headings: one line, no table breakage, no raw HTML, no accidental links."""
    s = _ws(v)
    for a, b in (("\\", "\\\\"), ("|", "\\|"), ("<", "&lt;"), (">", "&gt;"), ("[", "\\["), ("]", "\\]"), ("`", "'")):
        s = s.replace(a, b)
    return s


def md_block(v: object) -> str:
    """For paragraphs: keeps line breaks, neutralises HTML and links."""
    s = "" if v is None else str(v).replace("\r", "")
    for a, b in (("<", "&lt;"), (">", "&gt;"), ("[", "\\["), ("]", "\\]")):
        s = s.replace(a, b)
    return s.strip()


def md_fence(text: object, max_lines: int = 60, max_chars: int = 6000) -> str:
    """A code block that cannot be ended early by the text and is cut at a LINE boundary with an explicit note (never mid-line)."""
    s = "" if text is None else str(text).replace("\r", "")
    lines = s.split("\n")
    kept, size = [], 0
    for ln in lines:
        if len(kept) >= max_lines or size + len(ln) > max_chars:
            break
        kept.append(ln)
        size += len(ln) + 1
    note = f"\n… [{len(lines) - len(kept)} more line(s) not shown]" if len(kept) < len(lines) else ""
    body = "\n".join(kept) + note
    longest = max([len(m.group(0)) for m in re.finditer(r"`+", body)] or [0])
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{body}\n{fence}"
