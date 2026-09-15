from src.webshield import validate_target


def test_adds_https_scheme():
    assert validate_target("example.com") == "https://example.com"


def test_rejects_credentials():
    try:
        validate_target("https://user:pass@example.com")
    except ValueError:
        return
    assert False
