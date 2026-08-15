from binarylens.analysis.entropy import shannon_entropy


def test_entropy_empty_data():
    assert shannon_entropy(b"") == 0.0


def test_entropy_uniform_byte_is_zero():
    # A single repeated byte value has zero entropy.
    assert shannon_entropy(b"\x41" * 1000) == 0.0


def test_entropy_random_data_is_high():
    import os

    data = os.urandom(4096)
    entropy = shannon_entropy(data)
    assert entropy > 7.0  # random data should be close to 8.0 bits/byte


def test_entropy_is_between_0_and_8():
    data = bytes(range(256)) * 4
    entropy = shannon_entropy(data)
    assert 0.0 <= entropy <= 8.0
    # Perfectly uniform distribution over all 256 byte values => exactly 8.0
    assert abs(entropy - 8.0) < 0.001


def test_entropy_two_symbol_alternating():
    data = b"\x00\xff" * 500
    entropy = shannon_entropy(data)
    # Two equally likely symbols => exactly 1.0 bit of entropy
    assert abs(entropy - 1.0) < 0.001
