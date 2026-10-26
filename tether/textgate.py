"""Simple stand-in TEXT gate, not an LLM judge.

TF-IDF cosine between a tool-call statement and the contract purpose. The idf
comes from the benign statement corpus of the simulation (it is the world
model, not test-set tuning). Threshold was picked from data structure before
any run and the measured false-alarm rate will be reported as measured.
Label everywhere: simple stand-in, never the gate inside Tether mode.
"""
from __future__ import annotations

import math
import re
from collections import Counter

WORD_RE = re.compile(r"[a-z]+")

# Small standard English stopword set (stand-in gate, stdlib only).
STOPWORDS = frozenset(
    """a an and are as at be but by for from has have i in is it its of on or
    that the their then there these they this to was we were will with you your
    now all about into per via""".split()
)

# Chosen a priori from the vocabulary structure of the scripted world.
COSINE_THRESHOLD = 0.10


def _tokens(text: str) -> Counter:
    return Counter(w for w in WORD_RE.findall(text.lower()) if w not in STOPWORDS)


class TextGate:
    def __init__(self, corpus: list[str], contract_purpose: str) -> None:
        self.docs = [d for d in corpus if d]
        self.purpose_tokens = _tokens(contract_purpose)
        df: Counter = Counter()
        for doc in self.docs:
            df.update(set(_tokens(doc)))
        self.n_docs = max(1, len(self.docs))
        self.idf = {t: math.log((self.n_docs + 1) / (c + 1)) + 1.0 for t, c in df.items()}

    def _vec(self, text: str) -> dict[str, float]:
        tf = _tokens(text)
        vec: dict[str, float] = {}
        for tok, cnt in tf.items():
            if tok in self.idf:
                vec[tok] = (1.0 + math.log(cnt)) * self.idf[tok]
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {t: v / norm for t, v in vec.items()}

    def cosine(self, text: str) -> float:
        """Stated purpose overlap in [0,1]; low = off declared purpose."""
        purpose = self._vec(" ".join(self.purpose_tokens))
        query = self._vec(text)
        overlap = set(purpose) & set(query)
        return sum(purpose[t] * query[t] for t in overlap)

    def score_offpurpose(self, text: str) -> float:
        """Advisory detector score in [0,1]: high = off-purpose."""
        return max(0.0, 1.0 - self.cosine(text))
