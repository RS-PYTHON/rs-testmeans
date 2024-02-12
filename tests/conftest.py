"""Docstring to be added."""
import os

import pytest
import yaml

from src.ADGS.adgs_station_mock import create_adgs_app
from src.CADIP.cadip_station_mock import create_cadip_app


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


def export_aws_credentials():
    """Export AWS credentials as environment variables for testing purposes."""
    with open("tests/resources/s3.yml", "r", encoding="utf-8") as f:
        s3_config = yaml.safe_load(f)
        os.environ.update(s3_config["s3"])
