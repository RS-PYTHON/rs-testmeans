"""Docstring to be added."""
import base64
import filecmp
import json
import os
import pytest
from src.CADIP.cadip_station_mock import PATH_TO_CONFIG
from src.COMMON.common_routes import EMPTY_AUTH_CONFIG
from http import HTTPStatus


@pytest.fixture(scope="function", autouse=True)
def reset_json():
    """ Fixture to reset the authentication configuration file at the end of each pytest"""
    
    # First execute the pytest
    yield  
    
    # At the end of the pytest, reset the configuration file
    auth_path = str(PATH_TO_CONFIG / "auth.json")
    with open(auth_path, "w") as f:
        json.dump(EMPTY_AUTH_CONFIG, f, indent=4)


@pytest.mark.unit
def test_basic_auth(cadip_client, auth_config, app_header):
    """Method used to test endpoint access with token."""
    data_to_send = auth_config

    # ----------- Test if we can get new credentials by providing valid authentication configuration
    token_response = cadip_client.post("/oauth2/token", data=data_to_send, headers = app_header)
    assert token_response.status_code == HTTPStatus.OK
    token_info = json.loads(token_response.text)
    assert token_info["access_token"]
    
    # ----------- Test if the new credentials are valid on get method
    # test credentials on get methods with auth required.
    hello_response = cadip_client.get("/", headers={"Authorization": f"Token {token_info['access_token']}"})
    assert hello_response.status_code == HTTPStatus.OK
    
    # ----------- Test if the new credentials are valid on get method
    wrong_token_info = token_info.copy()
    wrong_token_info["access_token"] = "WrongAccessToken"
    assert cadip_client.get("/", headers={"Authorization": f"Token {wrong_token_info['access_token']}"}).status_code == HTTPStatus.UNAUTHORIZED
    
    # ----------- Test a broken endpoint route
    assert cadip_client.get("incorrectRoute/").status_code == HTTPStatus.NOT_FOUND


@pytest.mark.unit
@pytest.mark.parametrize(
    "session_response20230216",
    [
        (
            {
                "Id": "a5e9d3b8-7c4f-4a92-b76a-fa09e1e1b59c",
                "SessionId": "S1A_20200105072204051312",
                "NumChannels": 2,
                "PublicationDate": "2020-01-05T18:52:26.165Z",
                "Satellite": "S1A",
                "StationUnitId": "01",
                "DownlinkOrbit": 53186,
                "AcquisitionId": "53186_1",
                "AntennaId": "MSP21",
                "FrontEndId": "01",
                "Retransfer": False,
                "AntennaStatusOK": True,
                "FrontEndStatusOK": True,
                "PlannedDataStart": "2020-01-05T07:22:04.051Z",
                "PlannedDataStop": "2020-01-05T07:31:04.051Z",
                "DownlinkStart": "2020-01-05T07:22:04.051Z",
                "DownlinkStop": "2020-01-05T07:42:04.051Z",
                "DownlinkStatusOK": True,
                "DeliveryPushOK": True
            }
        ),
    ],
)
def test_query_sessions(cadip_client_with_auth, session_response20230216):
    """Docstring to be added."""
    
    # test without args
    assert cadip_client_with_auth.get("Sessions").status_code == HTTPStatus.OK # Should return all sessions
    # test with an incorrect filter
    assert cadip_client_with_auth.get("Sessions?$filter=Incorrect_filter").status_code == HTTPStatus.BAD_REQUEST
    # Response containing more than 1 result, since there are more products matching
    response = cadip_client_with_auth.get("Sessions?$filter=PublicationDate gt 2019-01-01T12:00:00.000Z")
    assert len(json.loads(response.text)["value"]) > 1
    # Response containing exactly one item, since explicit date is mentioned.
    response = cadip_client_with_auth.get("Sessions?$filter=PublicationDate eq 2020-01-05T18:52:26.165Z")
    assert isinstance(json.loads(response.text), dict)
    # Check response content with test-defined one.
    response = cadip_client_with_auth.get("Sessions?$filter=PublicationDate eq 2020-01-05T18:52:26.165Z")
    assert json.loads(response.text)['value'][0].keys() == session_response20230216.keys()
    assert json.loads(response.text)['value'][0] == session_response20230216
    # Empty json response since there are no products older than 1999.
    response = cadip_client_with_auth.get("Sessions?$filter=PublicationDate lt 1999-01-01T12:00:00.000Z")
    assert bool(response.text)
    # Test with sattelite - pos
    # Test status code - 200 HTTPStatus.OK, test that reponse exists and it's not empty
    assert cadip_client_with_auth.get("Sessions?$filter=Satellite eq S1A").status_code == HTTPStatus.OK
    assert len(cadip_client_with_auth.get("Sessions?$filter=Satellite eq 'S1A'").get_data().decode())
    # Test with sattelite - neg
    # Test status code - 200 HTTPStatus.OK, test that reponse is empty as per ICD
    assert cadip_client_with_auth.get("Sessions?$filter=Satellite eq INCORRECT").status_code == HTTPStatus.OK
    assert cadip_client_with_auth.get("Sessions?$filter=Satellite eq INCORRECT").get_data() == b'[]'
    # Test with Downlink - pos - status 200 and valid content
    assert cadip_client_with_auth.get("Sessions?$filter=DownlinkOrbit eq 53186").status_code == HTTPStatus.OK
    assert len(cadip_client_with_auth.get("Sessions?$filter=DownlinkOrbit eq 53186").get_data().decode())
    # Test with Downlink - neg - status 200 and invalid content
    assert cadip_client_with_auth.get("Sessions?$filter=DownlinkOrbit eq INCORRECT").status_code == HTTPStatus.BAD_REQUEST
    assert not len(cadip_client_with_auth.get("Sessions?$filter=DownlinkOrbit eq INCORRECT").get_data().decode())
    # Test with aditional filtering operator <<AND>>
    query = (
        "Sessions?$filter=PublicationDate gt 2020-02-11T12:00:00.000Z and PublicationDate lt 2020-02-20T12:00:00.000Z"
    )
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    assert len(cadip_client_with_auth.get(query).get_data().decode())
    # Test with aditional filtering operator <<OR>>
    query = "Sessions?$filter=PublicationDate gt 2020-02-11T12:00:00.000Z or Satellite eq S1A"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    assert len(cadip_client_with_auth.get(query).get_data().decode())
    # Test with 3 valid filters
    query = "Sessions?$filter=Satellite in ('S1A', 'S2B') and PublicationDate gt 2014-03-12T08:00:00.000Z and PublicationDate lt 2024-03-12T12:00:00.000Z"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    # Incorrect downlink, status HTTPStatus.OK but empty result
    query = "Sessions?$filter=DownlinkOrbit eq '53186' and PublicationDate gt 2014-03-12T08:00:00.000Z and PublicationDate lt 2024-03-12T12:00:00.000Z"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    #@@@assert not json.loads(cadip_client.get(query, headers=auth_header).text)
    # Test with 2 valid filters and 1 invalid, should raise 404 not found
    query = "Sessions?$filter=Satellite eq 'S3' and PublicationDate gt 2014-03-12T08:00:00.000Z and PublicationDate lt 2024-03-12T12:00:00.000Z"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    assert json.loads(cadip_client_with_auth.get(query).text)['value'] == []
    # Test with sattelite in (invalid, valid) and 2 other filters valid
    query = "Sessions?$filter=Satellite in ('S1', invalid) and PublicationDate gt 2014-03-12T08:00:00.000Z and PublicationDate lt 2024-03-12T12:00:00.000Z"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    assert json.loads(cadip_client_with_auth.get(query).text)['value'] == []
    query = "Sessions?$filter=Satellite in ('invalid', invalid) and PublicationDate gt 2014-03-12T08:00:00.000Z and PublicationDate lt 2024-03-12T12:00:00.000Z"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    assert json.loads(cadip_client_with_auth.get(query).text)['value'] == []
    # Test with 2 invalid date filters
    query = "Sessions?$filter=Satellite in ('S1', invalid) and PublicationDate gt 2025-03-12T08:00:00.000Z and PublicationDate lt 2030-03-12T12:00:00.000Z"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    assert not json.loads(cadip_client_with_auth.get(query).text)['value']
    # Test with incorrect filter
    query = "Sessions?$filter=IncorrectField eq true"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.BAD_REQUEST
    query = "Sessions?$filter=NumChannels eq 2"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    query = "Sessions?$filter=NumChannels gt 1"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    query = "Sessions?$filter=NumChannels lt 0"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    # Eodagspecific request tests
    dag_filter = [
        "SessionId%20in%20('S2B_20231117033237234567,%20S1A_20231120061537234567%20&$top=20",
        "SessionId%20in%20('S1A_20231120061537234567')%20&$top=20",
        "SessionId%20in%20('S1A_20231120061537234567')%20and%20Satellite%20in%20('S1A')%22&$top=20",
        "SessionId in ('S1A_20231120061537234567', 'S2B_20231117033237234567') and Satellite in ('S1A', 'S2B')&$top=20&$expand=Files"
    ] 
    for query in dag_filter:
        endpoint = f"Sessions?$filter={query}"
        assert cadip_client_with_auth.get(endpoint).status_code == HTTPStatus.OK
        assert json.loads(cadip_client_with_auth.get(endpoint).text)

    time_filters = [
        "Sessions?$filter=PublicationDate eq 2020-01-05T18:52:26.165Z",
        "Sessions?$filter=PublicationDate lte 2020-01-05T18:52:26.165Z",
        "Sessions?$filter=PublicationDate gte 2020-01-05T18:52:26.165Z"
    ]
    for query in time_filters:
        resp = cadip_client_with_auth.get(query)
        assert resp.status_code == HTTPStatus.OK
        resp_data = json.loads(resp.text)
        assert ("value" in resp_data and session_response20230216 in resp_data["value"]) or resp_data == json.loads(resp.text)

@pytest.mark.unit
def test_query_files(cadip_client_with_auth):
    """Docstring to be added."""
    # test without args
    assert cadip_client_with_auth.get("Files").status_code == HTTPStatus.BAD_REQUEST
    # test with an incorrect filter
    assert cadip_client_with_auth.get("Files?$filter=Incorrect_filter").status_code == HTTPStatus.BAD_REQUEST
    # Response containing more than 1 result, since there are more products matching
    response = cadip_client_with_auth.get("Files?$filter=PublicationDate gt 2019-01-01T12:00:00.000Z")
    assert len(json.loads(response.text)["value"]) > 1
    # Response containing exactly one item, since explicit date is mentioned.
    response = cadip_client_with_auth.get("Files?$filter=Id eq e4d17d2f-29eb-4c18-bc1f-bf2769a3a16d")
    assert isinstance(json.loads(response.text), dict)
    response = cadip_client_with_auth.get("Files?$filter=PublicationDate lt 1999-01-01T12:00:00.000Z")
    assert bool(response.text)
    # Test with aditional filtering operator <<AND>>
    query = "Files?$filter=PublicationDate gt 2019-02-11T12:00:00.000Z and PublicationDate lt 2019-02-20T12:00:00.000Z"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    assert len(cadip_client_with_auth.get(query).get_data())
    # Test with name contains
    query = "Files?$filter=contains(Name, 'DCS_01_S1A')"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    assert len(cadip_client_with_auth.get(query).get_data())
    # Test with name startwith
    query = "Files?$filter=startswith(Name, 'DCS')"
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    assert len(cadip_client_with_auth.get(query).get_data())
    # Test top pagination element, this query should return 10 elements, top should display only first 3. top&filter
    top_pagination_nr = "3"
    query = f'Files?$top={top_pagination_nr}&$filter="PublicationDate%20gt%202014-01-01T12:00:00.000Z%20and%20PublicationDate%20lt%202023-12-30T12:00:00.000Z'
    data = cadip_client_with_auth.get(query)
    assert len(json.loads(data.text)['value']) == int(top_pagination_nr)
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK
    # Test top pagination element, this query should return 10 elements, top should display only first 3. filter&top
    top_pagination_nr = "3"
    query = f'Files?$filter="PublicationDate%20gt%202014-01-01T12:00:00.000Z%20and%20PublicationDate%20lt%202023-12-30T12:00:00.000Z&$top={top_pagination_nr}'
    data = cadip_client_with_auth.get(query)
    assert len(json.loads(data.text)['value']) == int(top_pagination_nr)
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK

    # Test skip pagination element, this query should return 201 elements, skip should display only 194. (07.06.24 update)
    skip_pagination_nr = "7"
    query = f'Files?$skip={skip_pagination_nr}&$filter="PublicationDate%20gt%202014-01-01T12:00:00.000Z%20and%20PublicationDate%20lt%202023-12-30T12:00:00.000Z'
    data = cadip_client_with_auth.get(query)
    assert len(json.loads(data.text)['value']) == 201 - int(skip_pagination_nr)
    assert cadip_client_with_auth.get(query).status_code == HTTPStatus.OK


def test_query_quality_info():
    """Docstring to be added."""
    pass


@pytest.mark.parametrize(
    "local_path, download_path",
    [
        # to be changed after deploy / pipeline
        (
            ("tests/data/", "S1A.raw"),
            ("tests/S3MockTest/", "S1A_test.raw")
        ),
    ],
)
def test_download_file(cadip_client_with_auth, local_path, download_path):
    """Docstring to be added."""
    # Remove artifacts if any
    original_path, original_file = local_path
    download_path, download_file = download_path
    if os.path.exists(os.path.join(download_path, download_file)):
        os.remove(os.path.join(download_path, download_file))
    else:
        os.makedirs(download_path, exist_ok=True)

    # fail if there is not original file to compare with, tbd
    if not os.path.exists(os.path.join(original_path, original_file)):
        assert False
    # Test download for an inexistent file (404 expected)
    api_route = "Files(some_inexistent_ID)/$value"
    assert cadip_client_with_auth.get(api_route).status_code == HTTPStatus.NOT_FOUND
    # Test existing file
    api_route = "Files(e4d17d2f-29eb-4c18-bc1f-bf2769a3a16d)/$value"
    response = cadip_client_with_auth.get(api_route)
    assert response.status_code == HTTPStatus.OK
    # Dump response to file (python-request limitation, server is automatically downloading file in accepted brows)
    with open(os.path.join(download_path, download_file), "wb+") as df:
        df.write(response.get_data())
    # test file content
    assert filecmp.cmp(
        os.path.join(original_path, original_file),
        os.path.join(download_path, download_file),
    )
    # clean downloaded file
    os.remove(os.path.join(download_path, download_file))
    os.removedirs(download_path)


@pytest.mark.unit
def test_expand(cadip_client_with_auth):
    # Test with a simple query, should return 1 expanded session
    endpoint = "Sessions?$filter=SessionId eq 'S1A_20200105072204051312'&$expand=files"
    assert cadip_client_with_auth.get(endpoint).status_code == HTTPStatus.OK
    assert json.loads(cadip_client_with_auth.get(endpoint).text)
    # Check that the "Files" list is not empty
    assert len(json.loads(cadip_client_with_auth.get(endpoint).text)["value"][0]['Files'])


    # Test with a complex query that returns multiple expanded sessions
    endpoint = "Sessions?$filter=DownlinkOrbit eq '53186' and PublicationDate gt 2014-03-12T08:00:00.000Z and PublicationDate lt 2024-03-12T12:00:00.000Z&$expand=files"
    assert cadip_client_with_auth.get(endpoint).status_code == HTTPStatus.OK
    assert json.loads(cadip_client_with_auth.get(endpoint).text)
    # Check that each sessions files list is not empty
    for session in json.loads(cadip_client_with_auth.get(endpoint).text)['value']:
        assert len(session['Files'])