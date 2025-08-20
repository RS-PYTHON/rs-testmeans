import pytest
from odata_lexer import parse_odata_filter

@pytest.mark.parametrize(
    "input_str, expected_output",
    [
        (
            "contains(Name, 'S1A_IW_RAW')",
            {
                "Name":
                    {"op": "contains", "value": "S1A_IW_RAW"},
            },
        ),
        (
            "startswith(Name, 'S1')",
            {
                "Name":
                    {"op": "startswith", "value": "S1"},
            },
        ),
        (
            "endswith(Name, '.ZIP')",
            {
                "Name":
                    {"op": "endswith", "value": ".ZIP"},
            },
        ),
        (
            "PublicationDate eq 2019-01-01T00:00:00.000Z",
            {
                "PublicationDate":
                    {"op": "Eq", "value": "2019-01-01T00:00:00.000Z"},
            },
        ),
        (
            "contains(Name, 'S1A_IW_RAW') and PublicationDate eq 2019-01-01T00:00:00.000Z",
            {
                "Name":
                    {"op": "contains", "value": "S1A_IW_RAW"},
                "PublicationDate":
                    {"op": "Eq", "value": "2019-01-01T00:00:00.000Z"},
            },
        ),
        (
            "contains(Name, 'S1A_IW_RAW') and"
            " PublicationDate gt 2018-01-01T00:00:00.000Z and"
            " PublicationDate lt 2023-01-01T00:00:00.000Z",
            {
                "Name":
                    {"op": "contains", "value": "S1A_IW_RAW"},
                "PublicationDate": [
                    {"op": "Gt", "value": "2018-01-01T00:00:00.000Z"},
                    {"op": "Lt", "value": "2023-01-01T00:00:00.000Z"},
                ],
            },
        ),
        (
            "endswith(Name, '.TGZ') and"
            " PublicationDate gt 2018-01-01T00:00:00.000Z and"
            " PublicationDate lt 2023-01-01T00:00:00.000Z and"
            " ContentDate/Start gt 2018-01-01T00:00:00.000Z and"
            " ContentDate/Start lt 2023-01-01T00:00:00.000Z",
            {
                "Name":
                    {"op": "endswith", "value": ".TGZ"},
                "PublicationDate": [
                    {"op": "Gt", "value": "2018-01-01T00:00:00.000Z"},
                    {"op": "Lt", "value": "2023-01-01T00:00:00.000Z"},
                ],
                "ContentDate/Start": [
                    {"op": "Gt", "value": "2018-01-01T00:00:00.000Z"},
                    {"op": "Lt", "value": "2023-01-01T00:00:00.000Z"},
                ],
            },
        ),
        (
            "ContentDate/Start gt 2019-01-01T00:00:00.000Z and"
            " ContentDate/Start lt 2023-01-01T00:00:00.000Z and"
            " PublicationDate gt 2018-01-01T00:00:00.000Z and"
            " PublicationDate lt 2023-01-01T00:00:00.000Z",
            {
                "ContentDate/Start": [
                    {"op": "Gt", "value": "2019-01-01T00:00:00.000Z"},
                    {"op": "Lt", "value": "2023-01-01T00:00:00.000Z"},
                ],
                "PublicationDate": [
                    {"op": "Gt", "value": "2018-01-01T00:00:00.000Z"},
                    {"op": "Lt", "value": "2023-01-01T00:00:00.000Z"},
                ],
            },
        ),
        (
            "Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'IW_RAW__0N') and"
            " Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'sliceProductFlag' and att/OData.CSC.StringAttribute/Value eq 'False')",
            {
                "productType":
                    {"op": "Eq", "value": "IW_RAW__0N"},
                "sliceProductFlag":
                    {"op": "Eq", "value": "False"}
            },
        ),
        (
            "ContentDate/Start gt 2019-01-01T00:00:00.000Z and"
            " Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'IW_RAW__0N') and"
            " Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'sliceProductFlag' and att/OData.CSC.StringAttribute/Value eq 'False')",
            {
                "ContentDate/Start":
                    {"op": "Gt", "value": "2019-01-01T00:00:00.000Z"},
                "productType":
                    {"op": "Eq", "value": "IW_RAW__0N"},
                "sliceProductFlag":
                    {"op": "Eq", "value": "False"}
            },
        ),
        (
            "startswith(Name, 'S1') and"
            " ContentDate/Start gt 2019-01-01T00:00:00.000Z and"
            " ContentDate/Start lt 2025-01-01T00:00:00.000Z and"
            " Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'IW_RAW__0N') and"
            " Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'sliceProductFlag' and att/OData.CSC.StringAttribute/Value eq 'False')",
            {
                "Name":
                    {"op": "startswith", "value": "S1"},
                "ContentDate/Start": [
                    {"op": "Gt", "value": "2019-01-01T00:00:00.000Z"},
                    {"op": "Lt", "value": "2025-01-01T00:00:00.000Z"},
                ],
                "productType":
                    {"op": "Eq", "value": "IW_RAW__0N"},
                "sliceProductFlag":
                    {"op": "Eq", "value": "False"}
            },
        ),
        (
            "startswith(Name, 'S1') and"
            " ContentDate/Start gt 2019-01-01T00:00:00.000Z and"
            " ContentDate/Start lt 2025-01-01T00:00:00.000Z and"
            " PublicationDate gt 2018-01-01T00:00:00.000Z and"
            " PublicationDate lt 2023-01-01T00:00:00.000Z and"
            " Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'IW_RAW__0N') and"
            " Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'sliceProductFlag' and att/OData.CSC.StringAttribute/Value eq 'False')",
            {
                "Name":
                    {"op": "startswith", "value": "S1"},
                "ContentDate/Start": [
                    {"op": "Gt", "value": "2019-01-01T00:00:00.000Z"},
                    {"op": "Lt", "value": "2025-01-01T00:00:00.000Z"},
                ],
                "PublicationDate": [
                    {"op": "Gt", "value": "2018-01-01T00:00:00.000Z"},
                    {"op": "Lt", "value": "2023-01-01T00:00:00.000Z"},
                ],
                "productType":
                    {"op": "Eq", "value": "IW_RAW__0N"},
                "sliceProductFlag":
                    {"op": "Eq", "value": "False"}
            },
        ),
        (
            "startswith(Name, 'S1') and"
            " ContentDate/Start gt 2019-01-01T00:00:00.000Z and"
            " ContentDate/Start lt 2025-01-01T00:00:00.000Z and"
            " PublicationDate gt 2018-01-01T00:00:00.000Z and"
            " PublicationDate lt 2023-01-01T00:00:00.000Z and"
            " Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productType' and att/OData.CSC.StringAttribute/Value eq 'IW_RAW__0N') and"
            " Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'sliceProductFlag' and att/OData.CSC.StringAttribute/Value eq 'False') and"
            " Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'polarisationChannels' and att/OData.CSC.StringAttribute/Value eq 'HH') and"
            " Attributes/OData.CSC.StringAttribute/any(att:att/Name eq 'productConsolidation' and att/OData.CSC.StringAttribute/Value eq 'FULL')",
            {
                "Name":
                    {"op": "startswith", "value": "S1"},
                "ContentDate/Start": [
                    {"op": "Gt", "value": "2019-01-01T00:00:00.000Z"},
                    {"op": "Lt", "value": "2025-01-01T00:00:00.000Z"},
                ],
                "PublicationDate": [
                    {"op": "Gt", "value": "2018-01-01T00:00:00.000Z"},
                    {"op": "Lt", "value": "2023-01-01T00:00:00.000Z"},
                ],
                "productType":
                    {"op": "Eq", "value": "IW_RAW__0N"},
                "sliceProductFlag":
                    {"op": "Eq", "value": "False"},
                "polarisationChannels":
                    {"op": "Eq", "value": "HH"},
                "productConsolidation":
                    {"op": "Eq", "value": "FULL"},
            },
        )
    ]
)
def test_parse_odata_filter(input_str, expected_output):
    result = parse_odata_filter(input_str)
    assert result == expected_output