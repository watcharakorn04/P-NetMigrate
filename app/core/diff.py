"""Line-by-line comparison (proposal §2.3.1 module 5.3: compare before/after per line).

* `source_aligned()` — before (source vendor) vs after (target vendor). A cross-vendor diff
  of raw text is meaningless (every line differs), so rows are aligned through each output
  line's `source_line` provenance link instead.
* `text_diff()` — classic `difflib` comparison of two texts of the SAME vendor, e.g. two
  conversions of the same device, or a converted file vs. an edited copy.
"""

from __future__ import annotations

import difflib
from typing import Iterable, Optional, TypedDict


class DiffRow(TypedDict):
    tag: str  # equal | replace | delete | insert
    left_no: Optional[int]
    left: Optional[str]
    right_no: Optional[int]
    right: Optional[str]


def text_diff(left: str, right: str) -> dict:
    """difflib.SequenceMatcher opcodes expanded into side-by-side rows + summary counts."""
    a, b = left.splitlines(), right.splitlines()
    rows: list[DiffRow] = []
    matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                rows.append(DiffRow(tag="equal", left_no=i1 + k + 1, left=a[i1 + k], right_no=j1 + k + 1, right=b[j1 + k]))
            continue
        span = max(i2 - i1, j2 - j1)
        for k in range(span):
            li, rj = i1 + k, j1 + k
            has_l, has_r = li < i2, rj < j2
            rows.append(DiffRow(
                tag="replace" if has_l and has_r else ("delete" if has_l else "insert"),
                left_no=li + 1 if has_l else None, left=a[li] if has_l else None,
                right_no=rj + 1 if has_r else None, right=b[rj] if has_r else None,
            ))
    counts = {t: sum(1 for r in rows if r["tag"] == t) for t in ("equal", "replace", "delete", "insert")}
    unified = "\n".join(difflib.unified_diff(a, b, "left", "right", lineterm=""))
    return {"rows": rows, "counts": counts, "ratio": round(matcher.ratio(), 4), "unified": unified}


def source_aligned(source_text: str, lines: Iterable[dict]) -> list[dict]:
    """Group output lines under the source line they came from.

    `lines`: dicts with at least text / provenance / source_line. Output lines without a
    source line (e.g. system-generated BGP activation) are attached after the last row seen.
    Returns [{"no", "source", "outputs": [line, ...]}] in source order, including source
    lines that produced no output (blank / separators).
    """
    src = source_text.splitlines()
    rows = [{"no": i + 1, "source": text, "outputs": []} for i, text in enumerate(src)]
    extra: list[dict] = []
    last = None
    for line in lines:
        no = line.get("source_line")
        if no and 0 < no <= len(rows):
            rows[no - 1]["outputs"].append(line)
            last = no
        elif last is not None:
            rows[last - 1]["outputs"].append(line)
        else:
            extra.append(line)
    if extra:
        rows.insert(0, {"no": None, "source": "", "outputs": extra})
    return rows
