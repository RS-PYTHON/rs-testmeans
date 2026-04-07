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

import datetime
import json
from io import StringIO

import pytest
from lta_station_mock import create_lta_app


@pytest.fixture
def lta_client():
    app = create_lta_app()
    with app.test_client() as client:
        yield client


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


mock_queued_order_data = {
    "orders": [
        {
            "Id": "test_order",
            "Status": "queued",
            "StatusMessage": "request is queued",
            "OrderSize": 1716,
            "SubmissionDate": str(datetime.datetime.now()),
            "EstimatedDate": str(datetime.datetime.now() + datetime.timedelta(seconds=30)),
            "CompletedDate": "None",
            "EvictionDate": "None",
            "Priority": 1,
        },
    ],
}


@pytest.fixture
def mock_open_queued_feature(monkeypatch):
    file_content = json.dumps(mock_queued_order_data)

    def mock_file_open(path, *args, **kwargs):
        path_str = str(path)
        if path_str.endswith("orders.json"):
            if args[0] == "r":
                file = StringIO(file_content)
                file.seek(0)
                return file
            if args[0] == "w":
                file = StringIO()

                def write(data):
                    nonlocal file_content
                    file_content = data

                file.write = write
                file.getvalue = lambda: file_content
                return file

    monkeypatch.setattr("builtins.open", mock_file_open)
    monkeypatch.setattr("pathlib.Path.open", mock_file_open)
    return mock_queued_order_data


mock_completed_order_data = {
    "orders": [
        {
            "Id": "test_order_completed",
            "Status": "completed",
            "StatusMessage": "requested product is available",
            "OrderSize": 1716,
            "SubmissionDate": "2024-06-28 16:31:09.632384",
            "EstimatedDate": "2024-06-28 16:33:00.632528",
            "CompletedDate": "2024-06-28 17:01:46.706597",
            "EvictionDate": "2024-07-01 17:01:46.706610",
            "Priority": 1,
        },
    ],
}


@pytest.fixture
def mock_open_completed_feature(monkeypatch):
    file_content = json.dumps(mock_completed_order_data)

    def mock_file_open(path, *args, **kwargs):
        path_str = str(path)
        if path_str.endswith("orders.json"):
            if args[0] == "r":
                file = StringIO(file_content)
                file.seek(0)
                return file
            if args[0] == "w":
                file = StringIO()

                def write(data):
                    nonlocal file_content
                    file_content = data

                file.write = write
                file.getvalue = lambda: file_content
                return file

    monkeypatch.setattr("builtins.open", mock_file_open)
    monkeypatch.setattr("pathlib.Path.open", mock_file_open)
    return mock_completed_order_data
