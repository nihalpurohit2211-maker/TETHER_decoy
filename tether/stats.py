"""Statistics helpers for the v2 evaluation (stdlib only).

Everything here is a pure function of the measured vectors. No number in this
module is fitted to a target: wilson_ci is the standard interval, and the
percentile helpers are the definitions declared in PREREG.md section 3.
"""
from __future__ import annotations

import math
from typing import Iterable


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """Wilson score interval for k successes out of n, returned in PERCENT.

    Used instead of a normal approximation because detection rates sit at 0 %
    and 100 %, where the normal interval is degenerate.
    """
    if n <= 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1.0 + (z * z) / n
    centre = (p + (z * z) / (2.0 * n)) / denom
    half = (z * math.sqrt(p * (1.0 - p) / n + (z * z) / (4.0 * n * n))) / denom
    lo = max(0.0, centre - half)
    hi = min(1.0, centre + half)
    return (round(100.0 * lo, 2), round(100.0 * hi, 2))


def percentile(values: Iterable[float], p: float) -> float:
    """Nearest-rank percentile, p in [0,1]. Returns 0.0 for an empty vector."""
    s = sorted(values)
    if not s:
        return 0.0
    idx = min(len(s) - 1, max(0, int(round(p * (len(s) - 1)))))
    return round(s[idx], 3)


def median(values: Iterable[float]) -> float:
    s = sorted(values)
    n = len(s)
    if n == 0:
        return 0.0
    if n % 2:
        return round(s[n // 2], 3)
    return round((s[n // 2 - 1] + s[n // 2]) / 2.0, 3)


def cdf_points(values: Iterable[float], points: int = 100) -> list[list[float]]:
    """(value, cumulative share) pairs for plotting a CDF, downsampled."""
    s = sorted(values)
    n = len(s)
    if n == 0:
        return []
    if n <= points:
        return [[round(v, 3), round(100.0 * (i + 1) / n, 2)] for i, v in enumerate(s)]
    step = max(1, n // points)
    out = []
    for i in range(0, n, step):
        out.append([round(s[i], 3), round(100.0 * (i + 1) / n, 2)])
    if out[-1][0] != round(s[-1], 3):
        out.append([round(s[-1], 3), 100.0])
    return out


def rate_with_ci(k: int, n: int) -> dict:
    lo, hi = wilson_ci(k, n)
    return {
        "pct": round(100.0 * k / n, 1) if n else 0.0,
        "ci95": [lo, hi],
        "k": k,
        "n": n,
    }
