"""Docstring to be added."""

import filecmp
import json
from pathlib import Path
import pytest

OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404


@pytest.mark.unit
def test_basic_auth(adgs_client, adgs_token):
    """Method used to test endpoint access with token."""
    # test credentials on get methods with auth required.
    assert adgs_client.get("/", headers=adgs_token).status_code == OK
    assert adgs_client.get("/", headers={"Authorization": "Token invalid_value"}).status_code == FORBIDDEN
    # test a broken endpoint route
    assert adgs_client.get("incorrectRoute/").status_code == NOT_FOUND


@pytest.mark.unit
@pytest.mark.parametrize(
    "products_response",
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
            }
        ),
    ],
)
def test_query_products(adgs_client_with_auth, products_response):
    """Docstring to be added."""
    # test without args
    assert adgs_client_with_auth.get("Products").status_code == OK # Should return all products
    # test with an incorrect filter
    assert adgs_client_with_auth.get("Products?$filter=Incorrect_filter").status_code == BAD_REQUEST
    # Response containing more than 1 result, since there are more products matching
    response = adgs_client_with_auth.get("Products?$filter=PublicationDate gt 2019-01-01T00:00:00.000Z")
    assert len(json.loads(response.text)["value"]) > 1
    # Response containing exactly one item, since explicit date is mentioned.
    response = adgs_client_with_auth.get("Products?$filter=PublicationDate eq 2023-02-16T12:00:00.000Z")
    assert isinstance(json.loads(response.text), dict)
    # Check response content with test-defined one.
    response = adgs_client_with_auth.get("Products?$filter=PublicationDate eq 2019-02-16T12:00:00.000Z")
    assert json.loads(response.text).keys() == products_response.keys()
    assert json.loads(response.text) == products_response
    # Name contains.
    adgs_client_with_auth.get("Products?$filter=contains(Name, 'S2__OPER_AUX_ECMWFD_PDMC_20190216T120')")

    assert json.loads(response.text).keys() == products_response.keys()
    assert json.loads(response.text) == products_response
    # Name contains enclosed with ''.
    response = adgs_client_with_auth.get("Products?$filter=contains(Name, 'S2__OPER_AUX_ECMWFD_PDMC_20190216T1')")
    assert json.loads(response.text).keys() == products_response.keys()
    assert json.loads(response.text) == products_response
    # name startwith
    response = adgs_client_with_auth.get("Products?$filter=startswith(Name, S2__OPER_AUX_ECMWFD_PDMC_2019)")
    assert json.loads(response.text).keys() == products_response.keys()
    assert json.loads(response.text) == products_response
    # Empty json response since there are no products older than 1999.
    response = adgs_client_with_auth.get("Products?$filter=PublicationDate lt 1999-05-15T00:00:00.000Z")
    assert not response.text
    # Test with AND operator
    q1 = "PublicationDate gt 2018-05-15T00:00:00.000Z"
    q2 = "PublicationDate lt 2023-05-15T00:00:00.000Z"
    endpoint = f"Products?$filter={q1} and {q2}"
    response = adgs_client_with_auth.get(endpoint)
    assert json.loads(response.text).keys()
    top_pagination = "3"
    # filter&top
    endpoint = f'Products?$filter="PublicationDate gt 2014-01-01T12:00:00.000Z and PublicationDate lt 2023-12-30T12:00:00.000Z&$top={top_pagination}'
    response = adgs_client_with_auth.get(endpoint)
    print(response)
    assert len(json.loads(response.text)["value"]) == int(top_pagination)
    # top&filter
    endpoint = f'Products?$top={top_pagination}&$filter="PublicationDate gt 2014-01-01T12:00:00.000Z and PublicationDate lt 2023-12-30T12:00:00.000Z'
    response = adgs_client_with_auth.get(endpoint)
    assert len(json.loads(response.text)["value"]) == int(top_pagination)

@pytest.mark.unit
@pytest.mark.parametrize(
    "query, is_valid",
    [
        (
            "Products?$filter=contains(Name, 'S2__OPER_AUX_ECMWFD_PDMC_20190216T120000_V20190217T090000_20190217T210000.TGZ') and Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'OPER_AUX_ECMWFD_PDMC')",
            True
        ),
        (
            "Products?$filter=contains(Name, 'NOT_FOUND.TGZ') and Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'OPER_AUX_ECMWFD_PDMC')",
            False
        ),
        (
            "Products?$filter=contains(Name, 'S2__OPER_AUX_ECMWFD_PDMC_20190216T120000_V20190217T090000_20190217T210000.TGZ') and Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'INVALID_TYPE')",
            False
        ),
        (
            "Products?$filter=Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'OPER_AUX_ECMWFD_PDMC') and contains(Name, 'S2__OPER_AUX_ECMWFD_PDMC_20190216T120000_V20190217T090000_20190217T210000.TGZ')",
            True
        ),
        (
            "Products?$filter=PublicationDate gt 2014-01-01T12:00:00.000Z and PublicationDate lt 2023-12-30T12:00:00.000Z and Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'OPER_AUX_ECMWFD_PDMC')",
            True
        ),
        # Invalid publicationdate
        (
            "Products?$filter=PublicationDate gt 2030-01-01T12:00:00.000Z and PublicationDate lt 2023-12-30T12:00:00.000Z and Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'OPER_AUX_ECMWFD_PDMC')",
            False
        ),
        # Reverse order
        (
            "Products?$filter=Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'OPER_AUX_ECMWFD_PDMC') and PublicationDate gt 2014-01-01T12:00:00.000Z and PublicationDate lt 2023-12-30T12:00:00.000Z",
            True
        ),
        (
            "Products?$filter=contains(Name,%20'S1A_OPER_MPL_ORBSCT_20210902T150704_99999999T999999_0025.EOF')%20and%20PublicationDate%20gt%202020-01-01T00:00:00.000Z%20and%20PublicationDate%20lt%202024-01-01T00:00:00.000Z",
            True
        )
    ],
)
def test_complex_query(adgs_client_with_auth, query, is_valid):
    # Name and attrs
    resp = adgs_client_with_auth.get(query)
    assert resp.status_code == OK
    if is_valid:
        assert json.loads(resp.data)
    else:
        assert json.loads(resp.data) == []

@pytest.mark.parametrize(
    "local_path, download_path",
    [
        (
            # to be changed after deploy / pipeline
            ("data/", "S2__OPER_AUX_ECMWFD_PDMC_20190216T120000_V20190217T090000_20190217T210000.TGZ"),
            ("S3MockTest/", "S2__OPER_AUX_ECMWFD_PDMC_20190216T120000_V20190217T090000_20190217T210000_test.TGZ"),
        ),
    ],
)
def test_download_file(adgs_client_with_auth, local_path, download_path):
    """Test downloading a file and comparing its content with the original."""
    # Convert paths to pathlib Path objects
    original_dir = Path(local_path[0])
    original_file = local_path[1]
    download_dir = Path(download_path[0])
    download_file = download_path[1]

    download_file_path = download_dir / download_file  # Combine directory and file

    # Remove artifacts if any
    if download_file_path.exists():
        download_file_path.unlink()  # Remove the file
    else:
        download_dir.mkdir(parents=True, exist_ok=True)  # Create the directory if it doesn't exist

    # Fail if the original file to compare with doesn't exist
    original_file_path = Path(__file__).parent.resolve() / original_dir / original_file
    if not original_file_path.exists():
        assert False, f"Original file {original_file} does not exist in {original_dir}"

    # Test download for a nonexistent file (404 expected)
    api_route = "Products(some_inexistent_ID)/$value"
    assert adgs_client_with_auth.get(api_route).status_code == NOT_FOUND

    # Test existing file download
    api_route = "Products(2b17b57d-fff4-4645-b539-91f305c27c69)/$value"
    response = adgs_client_with_auth.get(api_route)
    assert response.status_code == OK

    # Dump response to file
    with download_file_path.open("wb+") as df:
        df.write(response.get_data())

    # Test file content using filecmp
    assert filecmp.cmp(original_file_path, download_file_path), "Downloaded file differs from the original file"

    # Clean up the downloaded file and directory
    download_file_path.unlink()  # Remove the file
    if not any(download_dir.iterdir()):  # If the directory is empty, remove it
        download_dir.rmdir()
