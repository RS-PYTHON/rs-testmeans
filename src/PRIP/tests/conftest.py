import pytest
from prip_station_mock import create_prip_app
import json
import pathlib

@pytest.fixture
def prip_client():
    """Docstring to be added."""
    app = create_prip_app()
    with app.test_client() as client:
        yield client

PATH_TO_CONFIG = pathlib.Path(__file__).parent.parent.resolve() / "config"

with open(PATH_TO_CONFIG / "Catalog" / "GETFileResponse.json") as bdata:
    data = json.loads(bdata.read())['Data']

PRIP_PRODUCT = data[0]
