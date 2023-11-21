import pytest

from src.ADGS.adgs_station_mock import create_app


@pytest.fixture
def client():
    """Docstring to be added."""
    app = create_app()
    with app.test_client() as client:
        yield client
