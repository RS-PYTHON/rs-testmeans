# Copyright 2023-2026 Airbus, CS Group
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import pathlib

import pytest
from prip_station_mock import create_prip_app


@pytest.fixture(name="app_header")
def get_station_request_headers():
    return {"Content-Type": "application/x-www-form-urlencoded"}


@pytest.fixture(name="external_auth_config")
def get_external_auth_config():
    return {
        "client_id": "client_id",
        "client_secret": "client_secret",
        "grant_type": "password",
        "username": "test",
        "password": "test",
    }


@pytest.fixture
def prip_client():
    """Docstring to be added."""
    app = create_prip_app()
    with app.test_client() as client:
        yield client


@pytest.fixture(name="prip_client_with_auth")
def prip_client_with_auth(prip_client, external_auth_config, app_header):
    """Fixture to return a client with automatic auth header handling."""
    # Create a session from the test client
    client = prip_client

    # Get new credentials by providing valid authentication configuration
    # and then use these credentials for the following data requests
    data_to_send = external_auth_config
    token_response = client.post("/oauth2/token", data=data_to_send, headers=app_header)
    token_info = json.loads(token_response.text)
    client.environ_base["HTTP_AUTHORIZATION"] = f"Token {token_info['access_token']}"

    return client


PATH_TO_CONFIG = pathlib.Path(__file__).parent.parent.resolve() / "config"

with open(PATH_TO_CONFIG / "Catalog" / "GETFileResponse.json") as bdata:
    data = json.loads(bdata.read())["Data"]

PRIP_PRODUCTS = data
PRIP_PRODUCT = data[0]
