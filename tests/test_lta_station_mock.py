import pytest
import json

HTTP_OK = 200
HTTP_NOT_FOUND = 404


@pytest.mark.unit
@pytest.mark.parametrize(
    "query, expected_status, check_in_response",
    [
        ("Products?$filter=contains(Name,'S1A_IW_SLC__1SDV_2016')", HTTP_OK, True),
        ("Products?$filter=contains(Name,'S2B')", HTTP_NOT_FOUND, False),
        ("Products?$filter=startswith(Name,'S1A')", HTTP_OK, True),
        ("Products?$filter=startswith(Name,'S2B')", HTTP_NOT_FOUND, False),
        ("Products?$filter=endswith(Name,'SAFE.zip')", HTTP_OK, True),
        ("Products?$filter=endswith(Name,'.txt')", HTTP_NOT_FOUND, False)
    ]
)
def test_query_products_by_name(lta_client, lta_response, query, expected_status, check_in_response):
    """Test query (name based) LTA products."""
    # Perform the GET request
    response = lta_client.get(query)
    # Check status code
    assert response.status_code == expected_status

    if expected_status == HTTP_OK:
        response_data = json.loads(response.text)
        is_included = all(key in response_data.keys() for key in lta_response.keys())
        assert is_included == check_in_response, f"The dictionary is not present in the response for query: {query}"
    else:
        # Ensure the response is empty
        assert not response.text, f"The response should be empty for query: {query}"


@pytest.mark.unit
@pytest.mark.parametrize(
    "query, expected_status, check_in_response",
    [
        ("Products?$filter=PublicationDate gt 2018-01-15T00:00:00.000Z and PublicationDate lt 2018-01-19T00:00:00.000Z",
         HTTP_OK, True),
        ("Products?$filter=PublicationDate eq 2018-01-17T14:46:03.788Z", HTTP_OK, True),
        ("Products?$filter=PublicationDate gt 2024-01-15T00:00:00.000Z and PublicationDate lt 2025-01-19T00:00:00.000Z",
         HTTP_OK, False) # 200ok status but empty response as per ICD.
    ]
)
def test_query_products_by_publication_date(lta_client, lta_response, query, expected_status, check_in_response):
    """Test query (publication date intervals based) LTA products."""
    # Perform the GET request
    response = lta_client.get(query)
    # Check status code
    assert response.status_code == expected_status

    response_data = json.loads(response.text)
    if check_in_response:
        is_included = all(key in response_data.keys() for key in lta_response.keys())
        assert is_included == check_in_response, f"The dictionary is not present in the response for query: {query}"
    else:
        # Ensure the response is empty
        assert not response_data, f"The response should be empty for query: {query}"


@pytest.mark.unit
def test_order_endpoint(lta_client):
    """Test order processing endpoint."""
    pass


@pytest.mark.unit
def test_download_when_order_completed(lta_client):
    """Download when order is completed."""
    pass


@pytest.mark.unit
def test_download_when_order_incomplete(lta_client):
    """Try to download when order is not completed."""
    pass
