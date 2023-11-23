"""Docstring to be added."""
import pytest

from src.ADGS.adgs_station_mock import create_adgs_app
from src.CADIP.cadipStationMock import create_cadip_app


@pytest.fixture
def cadip_client():
    """Docstring to be added."""
    app = create_cadip_app()
    with app.test_client() as client:
        yield client

@pytest.fixture
def adgs_client():
    """Docstring to be added."""
    app = create_adgs_app()
    with app.test_client() as client:
        yield client
