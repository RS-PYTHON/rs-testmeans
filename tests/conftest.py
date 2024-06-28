"""Docstring to be added."""
import os

import pytest
import yaml

from src.ADGS.adgs_station_mock import create_adgs_app
from src.CADIP.cadip_station_mock import create_cadip_app
from src.LTA.lta_station_mock import create_lta_app


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


@pytest.fixture
def lta_client():
    """LTA app comm."""
    app = create_lta_app()
    with app.test_client() as client:
        yield client


def export_aws_credentials():
    """Export AWS credentials as environment variables for testing purposes."""
    with open("tests/resources/s3.yml", "r", encoding="utf-8") as f:
        s3_config = yaml.safe_load(f)
        os.environ.update(s3_config["s3"])


@pytest.fixture
def lta_response():  # noqa: D103
    return {
        "Id": "2b17b57d-fff4-4645-b539-91f305c27c69",
        "Name": "S1A_IW_SLC__1SDV_20160117T103451_20160117T103518_009533_0094_D46A.SAFE.zip",
        "ContentType": "application/octet-stream",
        "ContentLength": "4737286945",
        "OriginDate": "2018-01-17T12:56:05.232Z",
        "PublicationDate": "2018-01-17T14:46:03.788Z",
        "ModificationDate": "2018-01-19T18:00:00.000Z",
        "Online": "true",
        "EvictionDate": "2018-01-22T18:00:00.000Z",
    }