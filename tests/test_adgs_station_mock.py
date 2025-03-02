"""Docstring to be added."""

import filecmp
import json
from pathlib import Path
import pytest
from http import HTTPStatus

@pytest.mark.unit
def test_basic_auth(adgs_client, external_auth_config, app_header):
    """Method used to test endpoint access with token."""
    data_to_send = external_auth_config

    # ----------- Test if we can get new credentials by providing valid authentication configuration
    token_response = adgs_client.post("/oauth2/token", data=data_to_send, headers = app_header)
    assert token_response.status_code == HTTPStatus.OK
    token_info = json.loads(token_response.text)
    assert token_info["access_token"]
    
    # ----------- Test if the new credentials are valid on get method
    # test credentials on get methods with auth required.
    hello_response = adgs_client.get("/", headers={"Authorization": f"Token {token_info['access_token']}"})
    assert hello_response.status_code == HTTPStatus.OK
    
    # ----------- Test if the new credentials are valid on get method
    wrong_token_info = token_info.copy()
    wrong_token_info["access_token"] = "WrongAccessToken"
    assert adgs_client.get("/", headers={"Authorization": f"Token {wrong_token_info['access_token']}"}).status_code == HTTPStatus.UNAUTHORIZED
    
    # ----------- Test a broken endpoint route
    assert adgs_client.get("incorrectRoute/").status_code == HTTPStatus.NOT_FOUND

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
                "PublicationDate": "2019-02-16T18:29:37.522Z",
                "EvictionDate": "2019-02-16T18:29:37.522Z",
                "Checksum": [
                    {
                        "Algorithm": "MD5",
                        "Value": "E8A303BF3D85200514F727DB60E7DB65",
                        "ChecksumDate": "2019-02-16T12:00:00.000Z",
                    },
                ],
                "ContentDate": {"Start": "2019-02-16T18:29:37.522Z", "End": "2019-02-16T18:29:47.522Z"},
            }
        ),
    ],
)
def test_query_products(adgs_client_with_auth, products_response):
    """Docstring to be added."""
    # test without args
    assert adgs_client_with_auth.get("Products").status_code == HTTPStatus.OK # Should return all products
    # test with an incorrect filter
    assert adgs_client_with_auth.get("Products?$filter=Incorrect_filter").status_code == HTTPStatus.BAD_REQUEST
    # Response containing more than 1 result, since there are more products matching
    response = adgs_client_with_auth.get("Products?$filter=PublicationDate gt 2019-01-01T00:00:00.000Z")
    assert len(json.loads(response.text)["value"]) > 1
    # Response containing exactly one item, since explicit date is mentioned.
    response = adgs_client_with_auth.get("Products?$filter=PublicationDate eq 2023-02-16T12:00:00.000Z")
    assert isinstance(json.loads(response.text), dict)
    # Check response content with test-defined one.
    response = adgs_client_with_auth.get("Products?$filter=PublicationDate eq 2019-02-16T18:29:37.522Z")
    assert json.loads(response.text)['value'][0].keys() == products_response.keys()
    assert json.loads(response.text)['value'][0] == products_response
    # Name contains.
    adgs_client_with_auth.get("Products?$filter=contains(Name, 'S2__OPER_AUX_ECMWFD_PDMC_20190216T120')")

    assert json.loads(response.text)['value'][0].keys() == products_response.keys()
    assert json.loads(response.text)['value'][0] == products_response
    # Name contains enclosed with ''.
    response = adgs_client_with_auth.get("Products?$filter=contains(Name, 'S2__OPER_AUX_ECMWFD_PDMC_20190216T1')")
    assert json.loads(response.text)['value'][0].keys() == products_response.keys()
    assert json.loads(response.text)['value'][0] == products_response
    # name startwith
    response = adgs_client_with_auth.get("Products?$filter=startswith(Name, S2__OPER_AUX_ECMWFD_PDMC_2019)")
    assert json.loads(response.text)['value'][0].keys() == products_response.keys()
    assert json.loads(response.text)['value'][0] == products_response
    # Empty json response since there are no products older than 1999.
    response = adgs_client_with_auth.get("Products?$filter=PublicationDate lt 1999-05-15T00:00:00.000Z")
    assert not json.loads(response.text)['value']
    # Test with AND operator
    q1 = "PublicationDate gt 2018-05-15T00:00:00.000Z"
    q2 = "PublicationDate lt 2023-05-15T00:00:00.000Z"
    endpoint = f"Products?$filter={q1} and {q2}"
    response = adgs_client_with_auth.get(endpoint)
    assert json.loads(response.text)['value'][0].keys()
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
    
    time_filters = [
        "Products?$filter=PublicationDate eq 2019-02-16T12:00:00.000Z",
        "Products?$filter=PublicationDate lte 2019-02-16T12:00:00.000Z",
        "Products?$filter=PublicationDate gte 2019-02-16T12:00:00.000Z"
    ]
    for query in time_filters:
        resp = adgs_client_with_auth.get(query)
        assert resp.status_code == HTTPStatus.OK
        resp_data = json.loads(resp.text)
        assert ("value" in resp_data and products_response in resp_data["value"]) or resp_data == json.loads(resp.text)


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
            "Products?$filter=contains(Name, 'S1A_OPER_MPL_ORBSCT_20210902T150704_99999999T999999_0025.EOF') and PublicationDate gt 2020-01-01T00:00:00.000Z and PublicationDate lt 2024-01-01T00:00:00.000Z",
            True
        ),
        (
            "Products?$filter=contains(Name, 'S1A_OPER_MPL_ORBSCT_20240514T150704_99999999T999999_0025.EOF') and Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'OPER_MPL_ORBSCT') and Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'platformShortName' and att/OData.CSC.StringAttribute/Value eq 'sentinel-1')&$orderby=PublicationDate desc&$top=10000&$skip=0&$expand=Attributes",
            True
        ),
        (
            "Products?$filter=contains(Name, 'S1A_OPER_MPL_ORBSCT_20240514T150704_99999999T999999_0025.EOF') and PublicationDate gt 2024-05-13T23:59:59.000Z and PublicationDate lt 2024-05-14T00:00:01.000Z&$orderby=PublicationDate desc&$top=10000&$skip=0&$expand=Attributes",
            True
        ),
        (
            "Products?$filter=Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'OPER_AUX_PREORB_OPOD') and Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'platformShortName' and att/OData.CSC.StringAttribute/Value eq 'sentinel-1')&$orderby=PublicationDate desc&$top=10000&$skip=0&$expand=Attributes",
            True
        )
    ],
)
def test_complex_query(adgs_client_with_auth, query, is_valid):
    # Name and attrs
    resp = adgs_client_with_auth.get(query)
    assert resp.status_code == HTTPStatus.OK
    if is_valid:
        assert json.loads(resp.data)
    else:
        assert json.loads(resp.data) == {"value": []}

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
    assert adgs_client_with_auth.get(api_route).status_code == HTTPStatus.NOT_FOUND

    # Test existing file download
    api_route = "Products(2b17b57d-fff4-4645-b539-91f305c27c69)/$value"
    response = adgs_client_with_auth.get(api_route)
    assert response.status_code == HTTPStatus.OK

    # Dump response to file
    with download_file_path.open("wb+") as df:
        df.write(response.get_data())

    # Test file content using filecmp
    assert filecmp.cmp(original_file_path, download_file_path), "Downloaded file differs from the original file"

    # Clean up the downloaded file and directory
    download_file_path.unlink()  # Remove the file
    if not any(download_dir.iterdir()):  # If the directory is empty, remove it
        download_dir.rmdir()
