from binarylens.analysis.strings import extract_strings


def test_extract_ascii_strings():
    data = b"\x00\x00" + b"HelloWorld" + b"\x00\x00\x01\x02" + b"AnotherString" + b"\x00"
    strings, truncated = extract_strings(data, min_length=4)
    assert "HelloWorld" in strings
    assert "AnotherString" in strings
    assert not truncated


def test_extract_strings_respects_min_length():
    data = b"\x00ab\x00cdef\x00"
    strings, _ = extract_strings(data, min_length=4)
    assert "ab" not in strings
    assert "cdef" in strings


def test_extract_wide_unicode_strings():
    wide = "kernel32.dll".encode("utf-16-le")
    data = b"\x00\x00" + wide + b"\x00\x00"
    strings, _ = extract_strings(data, min_length=4)
    assert "kernel32.dll" in strings


def test_extract_strings_respects_max_count():
    # Build many distinct short strings.
    chunks = [f"STRING{i:04d}".encode("ascii") for i in range(50)]
    data = b"\x00".join(chunks)
    strings, truncated = extract_strings(data, min_length=4, max_strings=10)
    assert len(strings) <= 10
    assert truncated is True


def test_extract_strings_no_duplicates():
    data = b"\x00REPEATED\x00" * 5
    strings, _ = extract_strings(data, min_length=4)
    assert strings.count("REPEATED") == 1
