"""Combo cleaning and split / per-VPS (1-1) assignment helpers."""

from __future__ import annotations


def clean_combos(raw_text: str) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for ln in (raw_text or "").splitlines():
        s = ln.strip()
        if not s or s.startswith("#") or s in seen:
            continue
        seen.add(s)
        out.append(s)
    return out


def split_combos(lines: list[str], vps_weights: dict[str, int]) -> dict[str, list[str]]:
    targets = [(vid, max(1, int(w))) for vid, w in vps_weights.items() if vid]
    if not targets:
        return {}
    total = len(lines)
    total_w = sum(w for _, w in targets)
    out: dict[str, list[str]] = {}
    pos = 0
    for idx, (vid, w) in enumerate(targets):
        if idx == len(targets) - 1:
            out[vid] = lines[pos:]
        else:
            cnt = int(round(total * (w / total_w)))
            cnt = max(0, min(cnt, total - pos))
            out[vid] = lines[pos : pos + cnt]
            pos += cnt
    return out


def assign_per_vps(per_vps_text: dict[str, str]) -> dict[str, list[str]]:
    return {vid: clean_combos(txt) for vid, txt in per_vps_text.items() if vid}
