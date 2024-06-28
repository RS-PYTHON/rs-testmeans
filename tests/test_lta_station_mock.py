import json

import pytest

from .conftest import mock_queued_order_data, mock_completed_order_data

HTTP_OK = 200
HTTP_NOT_FOUND = 404
HTTP_BAD_REQUEST = 400


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
         HTTP_OK, False)  # 200ok status but empty response as per ICD.
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
        assert is_included, f"The dictionary is not present in the response for query: {query}"
    else:
        # Ensure the response is empty
        assert not response_data, f"The response should be empty for query: {query}"


@pytest.mark.unit
def test_queued_order_endpoint_by_id(lta_client, mock_open_queued_feature):
    """Test order processing endpoint by requesting order ID."""
    # Test incorrect request
    assert lta_client.get("Orders").status_code == HTTP_BAD_REQUEST
    assert lta_client.get("Orders?$filter=Id eq Incorrect_order_id").status_code == HTTP_NOT_FOUND

    # Test requests with mocked orders.json internal file.
    correct_order_by_id = lta_client.get("Orders?$filter=Id eq test_order")
    assert correct_order_by_id.status_code == HTTP_OK
    order = json.loads(correct_order_by_id.text)
    # Test that returned json order is not empty
    assert order
    # Test that mock modified the order by chaging status from queued to in_progress
    assert order != mock_queued_order_data['orders'][0]
    assert order['Status'] != 'queued' and order['Status'] == "in_progress"
    assert order['StatusMessage'] != 'request is queued' and order['StatusMessage'] == "request is under processing"


@pytest.mark.unit
def test_queued_order_endpoint_by_status(lta_client, mock_open_queued_feature):
    """Test order processing endpoint by requesting order Status."""
    incorrect_order_by_status = lta_client.get("Orders?$filter=Status eq invalid")
    assert not incorrect_order_by_status.text
    assert incorrect_order_by_status.status_code == HTTP_NOT_FOUND
    correct_order_by_status = lta_client.get("Orders?$filter=Status eq queued")
    assert correct_order_by_status.status_code == HTTP_OK
    order = json.loads(correct_order_by_status.text)
    # Test that returned json order is not empty
    assert order
    assert order != mock_queued_order_data['orders'][0]
    assert order['Status'] != 'queued' and order['Status'] == "in_progress"
    assert order['StatusMessage'] != 'request is queued' and order['StatusMessage'] == "request is under processing"


def test_completed_order_endpoint_by_id(lta_client, mock_open_completed_feature):
    """Test order processing endpoint by requesting order Status."""
    correct_order_by_status = lta_client.get("Orders?$filter=Status eq completed")
    assert correct_order_by_status.status_code == HTTP_OK
    order = json.loads(correct_order_by_status.text)
    # Test that returned json order is not empty
    assert order
    assert order != mock_queued_order_data['orders'][0]
    # Make sure that this order status was not changed.
    assert order['Status'] == "completed"
    assert order['StatusMessage'] == "requested product is available"


@pytest.mark.unit
def test_download_when_order_completed(lta_client):
    """Download when order is completed."""
    pass


@pytest.mark.unit
def test_download_when_order_incomplete(lta_client):
    """Try to download when order is not completed."""
    pass
