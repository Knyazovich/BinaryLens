"""Shannon entropy calculation for raw byte data.

Entropy is expressed in bits per byte (0.0 - 8.0). High entropy regions
often correlate with compression, encryption, or packing, but entropy
alone is never proof of anything malicious -- it is one indicator among
many, and is presented as such everywhere in BinaryLens.
"""

from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: bytes) -> float:
    """Compute the Shannon entropy of a byte string, in bits per byte."""
    if not data:
        return 0.0

    length = len(data)
    counts = Counter(data)

    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy
