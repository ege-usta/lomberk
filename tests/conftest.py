import pytest


@pytest.fixture(scope="session", autouse=True)
def _pro_license():
    """Tests exercise Pro features without calling Polar; test_license.py covers the real check."""
    try:
        import rowback.ee.license as lic
    except ImportError:  # the core-without-ee CI job
        yield
        return
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("ROWBACK_LICENSE_KEY", "test-license")
        mp.setattr(lic, "validate_key", lambda key: "granted")
        yield
