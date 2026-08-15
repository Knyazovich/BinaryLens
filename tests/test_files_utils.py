from binarylens.utils.files import clean_dropped_path, human_readable_size


def test_clean_dropped_path_double_quoted_windows():
    raw = '"C:\\Users\\User\\Desktop\\program.exe"'
    assert clean_dropped_path(raw) == "C:\\Users\\User\\Desktop\\program.exe"


def test_clean_dropped_path_single_quoted():
    raw = "'/home/user/Desktop/program.exe'"
    assert clean_dropped_path(raw) == "/home/user/Desktop/program.exe"


def test_clean_dropped_path_unix_escaped_spaces():
    raw = r"/home/user/My\ Programs/app.exe"
    assert clean_dropped_path(raw) == "/home/user/My Programs/app.exe"


def test_clean_dropped_path_plain_no_quotes():
    raw = "/home/user/app.exe"
    assert clean_dropped_path(raw) == "/home/user/app.exe"


def test_clean_dropped_path_windows_path_with_spaces_in_quotes():
    raw = '"C:\\Program Files\\App\\app.exe"'
    assert clean_dropped_path(raw) == "C:\\Program Files\\App\\app.exe"


def test_human_readable_size_bytes():
    assert human_readable_size(500) == "500 B"


def test_human_readable_size_kb():
    assert human_readable_size(2048) == "2.00 KB"


def test_human_readable_size_mb():
    size = 1.42 * 1024 * 1024
    assert human_readable_size(int(size)) == "1.42 MB"
