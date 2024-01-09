"""Docstring to be added."""
import base64
import filecmp
import json
import os

import pytest

OK = 200
BAD_REQUEST = 400
UNAUTHORIZED = 401
NOT_FOUND = 404


#
# {'Authorization': 'Basic test:test'}
# (Pdb) type(auth_header)
# <class 'dict'>
#
# python3.11 -m pytest cadipStationMockTest.py -vv
@pytest.mark.unit
@pytest.mark.parametrize(
    "correct_login, incorrect_login",
    [
        (("test:test"), ("notTest:notTest")),
    ],
)
def test_basic_auth(cadip_client, correct_login: str, incorrect_login: str):
    """Docstring to be added."""
    # test credentials on get methods with auth required.
    correct_login = base64.b64encode(str.encode(correct_login)).decode("utf-8")
    incorrect_login = base64.b64encode(str.encode(incorrect_login)).decode("utf-8")
    assert cadip_client.get("/", headers={"Authorization": "Basic {}".format(correct_login)}).status_code == OK
    assert (
        cadip_client.get("/", headers={"Authorization": "Basic {}".format(incorrect_login)}).status_code == UNAUTHORIZED
    )
    # test a broken endpoint route
    assert cadip_client.get("incorrectRoute/").status_code == NOT_FOUND


@pytest.mark.unit
@pytest.mark.parametrize(
    "session_response20230216, login",
    [
        (
            {
                "AcquisitionId": "415_01",
                "AntennaId": "SIV",
                "AntennaStatusOK": True,
                "DeliveryPushOK": True,
                "DownlinkOrbit": "62343",
                "DownlinkStart": "2023-05-01T12:15:34Z",
                "DownlinkStatusOK": True,
                "DownlinkStop": "2023-05-01T12:31:57Z",
                "FrontEndId": "FEP_identifier",
                "FrontEndStatusOK": True,
                "Id": "another_session_id",
                "NumChannels": "1",
                "PlannedDataStart": "some_date",
                "PlannedDataStop": "some_date",
                "PublicationDate": "2023-02-16T12:00:00.000Z",
                "Retransfer": False,
                "Satellite": "S3A",
                "SessionID": "S3OLCI1",
                "StationUnitId": "00",
            },
            ("test:test"),
        ),
    ],
)
def test_query_sessions(cadip_client, session_response20230216, login):
    """Docstring to be added."""
    # conftest to be updated, in order to support session-client to persist login
    login = base64.b64encode(str.encode(login)).decode("utf-8")
    auth_header = {"Authorization": f"Basic {login}"}
    # test without args
    assert cadip_client.get("Sessions", headers=auth_header).status_code == BAD_REQUEST
    # test with an incorrect filter
    assert cadip_client.get("Sessions?$filter=Incorrect_filter", headers=auth_header).status_code == BAD_REQUEST
    # Response containing more than 1 result, since there are more products matching
    response = cadip_client.get("Sessions?$filter=PublicationDate gt 2019-01-01T12:00:00.000Z", headers=auth_header)
    assert len(json.loads(response.text)["responses"]) > 1
    # Response containing exactly one item, since explicit date is mentioned.
    response = cadip_client.get("Sessions?$filter=PublicationDate eq 2023-02-16T12:00:00.000Z", headers=auth_header)
    assert isinstance(json.loads(response.text), dict)
    # Check response content with test-defined one.
    response = cadip_client.get("Sessions?$filter=PublicationDate eq 2023-02-16T12:00:00.000Z", headers=auth_header)
    assert json.loads(response.text).keys() == session_response20230216.keys()
    assert json.loads(response.text) == session_response20230216
    # Empty json response since there are no products older than 1999.
    response = cadip_client.get("Sessions?$filter=PublicationDate lt 1999-01-01T12:00:00.000Z", headers=auth_header)
    assert not response.text
    # Test with sattelite - pos
    # Test status code - 200 OK, test that reponse exists and it's not empty
    assert cadip_client.get("Sessions?$filter=Satellite eq S1A", headers=auth_header).status_code == OK
    assert len(cadip_client.get("Sessions?$filter=Satellite eq 'S1A'", headers=auth_header).get_data())
    # Test with sattelite - neg
    # Test status code - 200 OK, test that reponse is empty as per ICD
    assert cadip_client.get("Sessions?$filter=Satellite eq INCORRECT", headers=auth_header).status_code == OK
    assert not cadip_client.get("Sessions?$filter=Satellite eq INCORRECT", headers=auth_header).get_data()
    # Test with Downlink - pos - status 200 and valid content
    assert cadip_client.get("Sessions?$filter=DownlinkOrbit eq 62343", headers=auth_header).status_code == OK
    assert len(cadip_client.get("Sessions?$filter=DownlinkOrbit eq 62343", headers=auth_header).get_data())
    # Test with Downlink - neg - status 200 and invalid content
    assert cadip_client.get("Sessions?$filter=DownlinkOrbit eq INCORRECT", headers=auth_header).status_code == OK
    assert not cadip_client.get("Sessions?$filter=DownlinkOrbit eq INCORRECT", headers=auth_header).get_data()
    # Test with aditional filtering operator <<AND>>
    query = (
        "Sessions?$filter=PublicationDate gt 2020-02-11T12:00:00.000Z and PublicationDate lt 2020-02-20T12:00:00.000Z"
    )
    assert cadip_client.get(query, headers=auth_header).status_code == OK
    assert len(cadip_client.get(query, headers=auth_header).get_data())
    # Test with aditional filtering operator <<OR>>
    query = "Sessions?$filter=PublicationDate gt 2020-02-11T12:00:00.000Z or Satellite eq S1A"
    assert cadip_client.get(query, headers=auth_header).status_code == OK
    assert len(cadip_client.get(query, headers=auth_header).get_data())


@pytest.mark.unit
@pytest.mark.parametrize(
    "login",
    [
        ("test:test"),
    ],
)
def test_query_files(cadip_client, login):
    """Docstring to be added."""
    login = base64.b64encode(str.encode(login)).decode("utf-8")
    auth_header = {"Authorization": f"Basic {login}"}
    # test without args
    assert cadip_client.get("Files", headers=auth_header).status_code == BAD_REQUEST
    # test with an incorrect filter
    assert cadip_client.get("Files?$filter=Incorrect_filter", headers=auth_header).status_code == BAD_REQUEST
    # Response containing more than 1 result, since there are more products matching
    response = cadip_client.get("Files?$filter=PublicationDate gt 2019-01-01T12:00:00.000Z", headers=auth_header)
    assert len(json.loads(response.text)["responses"]) > 1
    # Response containing exactly one item, since explicit date is mentioned.
    response = cadip_client.get("Files?$filter=Id eq 2b17b57d-fff4-4645-b539-91f305c27c69", headers=auth_header)
    assert isinstance(json.loads(response.text), dict)
    response = cadip_client.get("Files?$filter=PublicationDate lt 1999-01-01T12:00:00.000Z", headers=auth_header)
    assert not response.text
    # Test with aditional filtering operator <<AND>>
    query = "Files?$filter=PublicationDate gt 2019-02-11T12:00:00.000Z and PublicationDate lt 2019-02-20T12:00:00.000Z"
    assert cadip_client.get(query, headers=auth_header).status_code == OK
    assert len(cadip_client.get(query, headers=auth_header).get_data())
    # Test with name contains
    query = "Files?$filter=contains(Name, 'DCS_01_S1A')"
    assert cadip_client.get(query, headers=auth_header).status_code == OK
    assert len(cadip_client.get(query, headers=auth_header).get_data())
    # Test with name startwith
    query = "Files?$filter=startswith(Name, 'DCS')"
    assert cadip_client.get(query, headers=auth_header).status_code == OK
    assert len(cadip_client.get(query, headers=auth_header).get_data())


def test_query_quality_info():
    """Docstring to be added."""
    pass


@pytest.mark.parametrize(
    "local_path, download_path, login",
    [
        # to be changed after deploy / pipeline
        (
            ("tests/data/", "S1A.raw"),
            ("tests/S3MockTest/", "S1A_test.raw"),
            ("test:test"),
        ),
    ],
)
def test_download_file(cadip_client, local_path, download_path, login):
    """Docstring to be added."""
    # Remove artifacts if any
    original_path, original_file = local_path
    download_path, download_file = download_path
    login = base64.b64encode(str.encode(login)).decode("utf-8")
    auth_header = {"Authorization": f"Basic {login}"}
    if os.path.exists(os.path.join(download_path, download_file)):
        os.remove(os.path.join(download_path, download_file))
    else:
        os.makedirs(download_path)

    # fail if there is not original file to compare with, tbd
    if not os.path.exists(os.path.join(original_path, original_file)):
        assert False
    # Test download for an inexistent file (404 expected)
    api_route = "Files(some_inexistent_ID)/$value"
    assert cadip_client.get(api_route, headers=auth_header).status_code == NOT_FOUND
    # Test existing file
    api_route = "Files(some_id_2)/$value"
    response = cadip_client.get(api_route, headers=auth_header)
    assert response.status_code == OK
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
