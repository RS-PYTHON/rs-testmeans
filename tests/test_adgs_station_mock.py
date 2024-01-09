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


@pytest.mark.unit
@pytest.mark.parametrize(
    "correct_login, incorrect_login",
    [
        (("test:test"), ("notTest:notTest")),
    ],
)
def test_basic_auth(adgs_client, correct_login: str, incorrect_login: str):
    """Docstring to be added."""
    # test credentials on get methods with auth required.
    correct_login = base64.b64encode(str.encode(correct_login)).decode("utf-8")
    incorrect_login = base64.b64encode(str.encode(incorrect_login)).decode("utf-8")
    assert adgs_client.get("/", headers={"Authorization": "Basic {}".format(correct_login)}).status_code == OK
    assert (
        adgs_client.get("/", headers={"Authorization": "Basic {}".format(incorrect_login)}).status_code == UNAUTHORIZED
    )
    # test a broken endpoint route
    assert adgs_client.get("incorrectRoute/").status_code == NOT_FOUND


@pytest.mark.unit
@pytest.mark.parametrize(
    "products_response, login",
    [
        (
            {
                "Id": "2b17b57d-fff4-4645-b539-91f305c27c69",
                "Name": "S2__OPER_AUX_ECMWFD_PDMC_20190216T120000_V20190217T090000_20190217T210000.TGZ",
                "ContentType": "application/octet-stream",
                "ContentLength": "8326253",
                "OriginDate": "2018-01-17T12:56:05.232Z",
                "PublicationDate": "2019-02-16T12:00:00.000Z",
                "EvictionDate": "2019-02-23T12:00:00.000Z",
                "Checksum": [
                    {
                        "Algorithm": "MD5",
                        "Value": "E8A303BF3D85200514F727DB60E7DB65",
                        "ChecksumDate": "2019-02-16T12:00:00.000Z",
                    },
                ],
                "ContentDate": {"Start": "2019-02-17T09:00:00.000Z", "End": "2019-02-17T21:00:00.000Z"},
            },
            ("test:test"),
        ),
    ],
)
def test_query_products(adgs_client, products_response, login):
    """Docstring to be added."""
    # conftest to be updated, in order to support session-client to persist login
    login = base64.b64encode(str.encode(login)).decode("utf-8")
    auth_header = {"Authorization": f"Basic {login}"}
    # test without args
    assert adgs_client.get("Products", headers=auth_header).status_code == BAD_REQUEST
    # test with an incorrect filter
    assert adgs_client.get("Products?$filter=Incorrect_filter", headers=auth_header).status_code == BAD_REQUEST
    # Response containing more than 1 result, since there are more products matching
    response = adgs_client.get("Products?$filter=PublicationDate gt 2019", headers=auth_header)
    assert len(json.loads(response.text)["responses"]) > 1
    # Response containing exactly one item, since explicit date is mentioned.
    response = adgs_client.get("Products?$filter=PublicationDate eq 2023-02-16", headers=auth_header)
    assert isinstance(json.loads(response.text), dict)
    # Check response content with test-defined one.
    response = adgs_client.get("Products?$filter=PublicationDate eq 2019-02-16", headers=auth_header)
    assert json.loads(response.text).keys() == products_response.keys()
    assert json.loads(response.text) == products_response
    # Name contains.
    response = adgs_client.get(
        "Products?$filter=contains(Name, S2__OPER_AUX_ECMWFD_PDMC_20190216T120)",
        headers=auth_header,
    )
    assert json.loads(response.text).keys() == products_response.keys()
    assert json.loads(response.text) == products_response
    # Name contains enclosed with ''.
    response = adgs_client.get(
        "Products?$filter=contains(Name, 'S2__OPER_AUX_ECMWFD_PDMC_20190216T1')",
        headers=auth_header,
    )
    assert json.loads(response.text).keys() == products_response.keys()
    assert json.loads(response.text) == products_response
    # name startwith
    response = adgs_client.get("Products?$filter=startswith(Name, S2__OPER_AUX_ECMWFD_PDMC_2019)", headers=auth_header)
    assert json.loads(response.text).keys() == products_response.keys()
    assert json.loads(response.text) == products_response
    # Empty json response since there are no products older than 1999.
    response = adgs_client.get("Products?$filter=PublicationDate lt 1999", headers=auth_header)
    assert not response.text


@pytest.mark.parametrize(
    "local_path, download_path, login",
    [
        (
            # to be changed after deploy / pipeline
            ("tests/data/", "S2__OPER_AUX_ECMWFD_PDMC_20190216T120000_V20190217T090000_20190217T210000.TGZ"),
            ("tests/S3MockTest/", "S2__OPER_AUX_ECMWFD_PDMC_20190216T120000_V20190217T090000_20190217T210000_test.TGZ"),
            ("test:test"),
        ),
    ],
)
def test_download_file(adgs_client, local_path, download_path, login):
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
    api_route = "Products(some_inexistent_ID)/$value"
    assert adgs_client.get(api_route, headers=auth_header).status_code == NOT_FOUND
    # Test existing file
    api_route = "Products(2b17b57d-fff4-4645-b539-91f305c27c69)/$value"
    response = adgs_client.get(api_route, headers=auth_header)
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
