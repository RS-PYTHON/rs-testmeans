# Copyright 2023-2026 CS Group
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
import shutil
from pathlib import Path

import pytest
from adgs_station_mock import create_adgs_app

CONFIG_DIR = Path(__file__).resolve().parents[1] / "config"
AUTH_PATH = CONFIG_DIR / "auth.json"
AUTH_TEMPLATE_PATH = CONFIG_DIR / "auth_tmp.json"


def reset_auth_file() -> None:
    shutil.copyfile(AUTH_TEMPLATE_PATH, AUTH_PATH)


@pytest.fixture(scope="session", autouse=True)
def reset_auth_after_tests():
    reset_auth_file()
    yield
    reset_auth_file()


@pytest.fixture(name="external_auth_config")
def get_external_auth_config():
    return {
        "client_id": "client_id",
        "client_secret": "client_secret",
        "grant_type": "password",
        "username": "test",
        "password": "test",
    }


@pytest.fixture(name="app_header")
def get_station_request_headers():
    return {"Content-Type": "application/x-www-form-urlencoded"}


@pytest.fixture
def adgs_client():
    app = create_adgs_app()
    ctx = app.app_context()
    ctx.push()
    app.testing = True
    with app.test_client() as client:
        yield client
    ctx.pop()


@pytest.fixture(name="adgs_client_with_auth")
def get_adgs_client_with_auth(adgs_client, external_auth_config, app_header):
    client = adgs_client
    token_response = client.post("/oauth2/token", data=external_auth_config, headers=app_header)
    token_info = json.loads(token_response.text)
    client.environ_base["HTTP_AUTHORIZATION"] = f"Token {token_info['access_token']}"
    return client
