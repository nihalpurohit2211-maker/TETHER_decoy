"""One-off calibration of the drift CUSUM decision interval h on NULL traffic.

Null model = the deployment's stated send pattern (1-2 emails per session,
~30% portal / 70% internal, ~1 record each). We pick the smallest h whose
null trip rate is at most 1 per 1000 sessions, then report whatever the
attacks do against it. This is false-alarm-rate calibration on the null,
the same discipline the text gate's <=1% rule uses; it is not tuning to a
detection target.
"""
import random

from tether.detectors import DriftBudget

ANCHOR = {
    "mail.internal": {"mu_records": 1.0, "sigma_records": 0.7},
    "supplier-portal.example": {"mu_records": 0.5, "sigma_records": 0.6},
}


def null_session_records(rng: random.Random) -> dict[str, int]:
    out = {"mail.internal": 0, "supplier-portal.example": 0}
    for _ in range(rng.randint(1, 2)):
        dest = "supplier-portal.example" if rng.random() < 0.3 else "mail.internal"
        out[dest] += 1
    return out


def trip_rate(h: float, seeds: int, sessions: int) -> float:
    trips = 0
    total = 0
    for s in range(seeds):
        rng = random.Random(1000 + s)
        budget = DriftBudget(ANCHOR, h=h)
        for _ in range(sessions):
            for dest, recs in null_session_records(rng).items():
                budget.accumulate(dest, recs)
            before = set(budget.latched)
            budget.end_session()
            trips += len(budget.latched - before)
            total += 1
    return trips / total * 1000.0


if __name__ == "__main__":
    for h in (5.0, 6.0, 8.0, 10.0, 12.0, 15.0):
        rate = trip_rate(h, seeds=30, sessions=1000)
        print(f"h={h:4.1f}  null trips per 1000 sessions: {rate:.2f}")
