import base64
import filecmp
import json
import os

import pytest


# python3.11 -m pytest cadipStationMockTest.py -vv
@pytest.mark.unit
@pytest.mark.parametrize(
    "correct_login, incorrect_login",
    [
        (("test:test"), ("notTest:notTest")),
    ],
)
def testAuth(client, correct_login: str, incorrect_login: str):
    # test credentials on get methods with auth required.
    correct_login = base64.b64encode(str.encode(correct_login)).decode("utf-8")
    incorrect_login = base64.b64encode(str.encode(incorrect_login)).decode("utf-8")
    assert client.get("/", headers={"Authorization": "Basic {}".format(correct_login)}).status_code == 200
    assert client.get("/", headers={"Authorization": "Basic {}".format(incorrect_login)}).status_code == 401
    # test a broken endpoint route
    assert client.get("incorrectRoute/").status_code == 404


@pytest.mark.unit
@pytest.mark.parametrize(
    "sessionResponse20230216",
    [
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
    ],
)
def testQuerrySessions(client, sessionResponse20230216):
    # test without args
    assert client.get("Sessions").status_code == 400
    # test with an incorrect filter
    assert client.get("Sessions?$filter=Incorrect_filter").status_code == 400
    # Response containing more than 1 result, since there are more products matching
    response = client.get("Sessions?$filter=PublicationDate gt 2019")
    assert len(json.loads(response.text)["responses"]) > 1
    # Response containing exactly one item, since explicit date is mentioned.
    response = client.get("Sessions?$filter=PublicationDate eq 2023-02-16")
    assert isinstance(json.loads(response.text), dict)
    # Check response content with test-defined one.
    response = client.get("Sessions?$filter=PublicationDate eq 2023-02-16")
    assert json.loads(response.text).keys() == sessionResponse20230216.keys()
    assert json.loads(response.text) == sessionResponse20230216
    # Empty json response since there are no products older than 1999.
    response = client.get("Sessions?$filter=PublicationDate lt 1999")
    assert not response.text
    # Test with sattelite - pos
    # Test status code - 200 OK, test that reponse exists and it's not empty
    assert client.get("Sessions?$filter=Satellite eq S1A").status_code == 200
    assert len(client.get("Sessions?$filter=Satellite eq 'S1A'").get_data())
    # Test with sattelite - neg
    # Test status code - 200 OK, test that reponse is empty as per ICD
    assert client.get("Sessions?$filter=Satellite eq INCORRECT").status_code == 200
    assert not client.get("Sessions?$filter=Satellite eq INCORRECT").get_data()
    # Test with Downlink - pos - status 200 and valid content
    assert client.get("Sessions?$filter=DownlinkOrbit eq 62343").status_code == 200
    assert len(client.get("Sessions?$filter=DownlinkOrbit eq 62343").get_data())
    # Test with Downlink - neg - status 200 and invalid content
    assert client.get("Sessions?$filter=DownlinkOrbit eq INCORRECT").status_code == 200
    assert not client.get("Sessions?$filter=DownlinkOrbit eq INCORRECT").get_data()


def testQuerryFiles():
    pass


def test_querryQualityInfo():
    pass


@pytest.mark.parametrize(
    "original_path, download_path, original_file, download_file",
    [
        # to be changed after deploy / pipeline
        (
            (
                "tests/data/",
                "tests/S3MockTest/",
                "S1A.raw",
                "S1A_test.raw",
            )
        ),
    ],
)
def testDownloadFile(client, original_path, download_path, original_file, download_file):
    # Remove artifacts if any
    if os.path.exists(os.path.join(download_path, download_file)):
        os.remove(os.path.join(download_path, download_file))
    else:
        os.makedirs(download_path)

    # fail if there is not original file to compare with, tbd
    if not os.path.exists(os.path.join(original_path, original_file)):
        assert False
    # Test download for an inexistent file (404 expected)
    api_route = "Files(some_inexistent_ID)/$value"
    assert client.get(api_route).status_code == 404
    # Test existing file
    api_route = "Files(some_id_2)/$value"
    response = client.get(api_route)
    assert response.status_code == 200
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
