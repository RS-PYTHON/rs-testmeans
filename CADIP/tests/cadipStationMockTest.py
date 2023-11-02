import requests
import json
import pytest
import os
import filecmp


# python3.11 -m pytest cadipStationMockTest.py -vv
@pytest.mark.unit
@pytest.mark.parametrize(
    "correct_login, incorrect_login",
    [
        (("test", "test"), ("notTest", "notTest")),
    ],
)
def testAuth(correct_login, incorrect_login):
    # test credentials on get methods with auth required.
    assert (
        requests.get("http://127.0.0.1:5000/", auth=incorrect_login).status_code == 401
    )
    assert requests.get("http://127.0.0.1:5000/", auth=correct_login).status_code == 200


@pytest.mark.unit
@pytest.mark.parametrize(
    "sessionResponse20230216",
    [
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
            }
        ],
    ],
)
def testQuerrySessions(sessionResponse20230216):
    # Response containing more than 1 result, since there are more products matching
    data = requests.get("http://127.0.0.1:5000/Sessions?filter=PublicationDate gt 2019")
    assert len(json.loads(data.text)) > 1
    # Response containing exactly one item, since explicit date is mentioned.
    data = requests.get(
        "http://127.0.0.1:5000/Sessions?filter=PublicationDate eq 2023-02-16"
    )

    assert len(json.loads(data.text)) == 1
    # Check response content with test-defined one.
    data = requests.get(
        "http://127.0.0.1:5000/Sessions?filter=PublicationDate eq 2023-02-16"
    )
    assert json.loads(data.text) == sessionResponse20230216

    # Empty json response since there are no products older than 1999.
    data = requests.get("http://127.0.0.1:5000/Sessions?filter=PublicationDate lt 1999")
    assert not len(json.loads(data.text))


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
                "/Users/ovidiu/work/RS/RSMocks/CADIP/S3Mock/",
                "/Users/ovidiu/work/RS/RSMocks/CADIP/S3MockTest/",
                "S1A.raw",
                "S1A_test.raw",
            )
        ),
    ],
)
def testDownloadFile(original_path, download_path, original_file, download_file):
    # Remove artifacts if any
    if os.path.exists(os.path.join(download_path, download_file)):
        os.remove(os.path.join(download_path, download_file))
    else:
        os.makedirs(download_path)

    # fail if there is not original file to compare with, tbd
    if not os.path.exists(os.path.join(original_path, original_file)):
        assert False
    # Test download for an inexistent file (404 expected)
    data = requests.get("http://127.0.0.1:5000/Files(some_inexistent_ID)")
    assert data.status_code == 404
    # Test existing file
    data = requests.get("http://127.0.0.1:5000/Files(some_id_2)")
    assert data.status_code == 200
    # Dump response to file (python-request limitation, server is automatically downloading file in accepted brows)
    with open(os.path.join(download_path, download_file), "wb+") as df:
        df.write(data.content)
    # test file content
    assert filecmp.cmp(
        os.path.join(original_path, original_file),
        os.path.join(download_path, download_file),
    )
    # clean downloaded file
    os.remove(os.path.join(download_path, download_file))
    os.removedirs(download_path)
