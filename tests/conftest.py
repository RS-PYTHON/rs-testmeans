import pytest

from src.CADIP.cadipStationMock import create_app


@pytest.fixture
def client():
    """Docstring to be added."""
    app = create_app()
    with app.test_client() as client:
        yield client
