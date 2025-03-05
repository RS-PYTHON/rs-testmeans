"""Docstring to be added."""
import datetime
import json
import os
from io import StringIO
import pathlib

import pytest
import yaml

from src.ADGS.adgs_station_mock import create_adgs_app
from src.CADIP.cadip_station_mock import create_cadip_app
from src.LTA.lta_station_mock import create_lta_app
from src.common.common_routes import EMPTY_AUTH_CONFIG

@pytest.fixture(name="empty_token_dict")
def get_empty_token_dict():
    return {
        "client_id": "client_id",
        "client_secret": "client_secret",
        "username": "test",
        "password": "test",
        "grant_type": "password",
        "access_token_list": [],
        "access_token_creation_date": [],
        "expires_in_list": [],
        "refresh_token_list": [],
        "refresh_token_creation_date": [],
        "refresh_expires_in_list": []
    }

@pytest.fixture(scope="session", name="path_to_config")
def get_path_to_config():
    return pathlib.Path(__file__).parent.resolve() / "resources" / "auth.json"


@pytest.fixture(scope="session", autouse=True)
def reset_json_after_tests(path_to_config):
    """Fixture to reset the json file containing the token dictionary at the end of the tests"""
    
    def reset_file():
        """Réinitialise auth.json après la fin des tests."""
        with open(path_to_config, "w") as f:
            json.dump(EMPTY_AUTH_CONFIG, f, indent=4)
    
    yield 
    reset_file()



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
    return{"Content-Type": "application/x-www-form-urlencoded"}

@pytest.fixture
def cadip_client():
    """Docstring to be added."""
    app = create_cadip_app()
    
    # We create and activate an application context to keep the application running 
    # during all requests of the current pytest
    ctx = app.app_context()  
    ctx.push() 
    app.testing = True
    with app.test_client() as client:
        yield client
    # Deactivate the application context
    ctx.pop() 



@pytest.fixture
def adgs_client():
    """Docstring to be added."""
    app = create_adgs_app()
    
    # We create and activate an application context to keep the application running 
    # during all requests of the current pytest
    ctx = app.app_context()  
    ctx.push() 
    with app.test_client() as client:
        yield client
    # Deactivate the application context
    ctx.pop() 


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


## Fixture to mock internal LTA orders.json file.


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
    """Fixture to mock the open function."""
    file_content = json.dumps(mock_queued_order_data)

    def mock_file_open(path, *args, **kwargs):
        path_str = str(path)  # Convert Path object to string
        if path_str.endswith("orders.json"):
            if args[0] == "r":
                file = StringIO(file_content)
                file.seek(0)  # Ensure we're at the start of the file
                return file
            elif args[0] == "w":
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
    """Fixture to mock the open function."""
    file_content = json.dumps(mock_completed_order_data)

    def mock_file_open(path, *args, **kwargs):
        path_str = str(path)  # Convert Path object to string
        if path_str.endswith("orders.json"):
            if args[0] == "r":
                file = StringIO(file_content)
                file.seek(0)  # Ensure we're at the start of the file
                return file
            elif args[0] == "w":
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


@pytest.fixture(name="adgs_token")
def valid_adgs_header_with_token():
    return {"Authorization": "Token P4JSuo3gfQxKo0gfbQTb7nDn5OkzWP3umdGvy7G3CcI"}

@pytest.fixture(name="cadip_token")
def valid_cadip_header_with_token():
    return {"Authorization": "Token P4JSuo3gfQxKo0gfbQTb7nDn5OkzWP3umdGvy7G3CcI"}


@pytest.fixture(name="adgs_client_with_auth")
def adgs_client_with_auth(adgs_client, adgs_token, external_auth_config, app_header):
    """Fixture to return a client with automatic auth header handling."""
    # Create a session from the test client
    client = adgs_client

    # Get new credentials by providing valid authentication configuration
    # and then use these credentials for the following data requests
    data_to_send = external_auth_config
    token_response = client.post("/oauth2/token", data=data_to_send, headers = app_header)
    token_info = json.loads(token_response.text)
    client.environ_base["HTTP_AUTHORIZATION"] = f"Token {token_info['access_token']}"
    
    return client


@pytest.fixture(name="cadip_client_with_auth")
def cadip_client_with_auth(cadip_client, external_auth_config, app_header):
    """Fixture to return a client with automatic auth header handling."""
    # Create a session from the test client
    client = cadip_client

    # Get new credentials by providing valid authentication configuration
    # and then use these credentials for the following data requests
    data_to_send = external_auth_config
    token_response = client.post("/oauth2/token", data=data_to_send, headers = app_header)
    token_info = json.loads(token_response.text)
    client.environ_base["HTTP_AUTHORIZATION"] = f"Token {token_info['access_token']}"

    return client
