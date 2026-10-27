# Copyright 2023-2026 CS Group
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Check grouped mission filters against a catalogue containing crossed satellite combinations."""

import json

import pytest
from adgs_station_mock import app, query_products, split_composite_filter


def attribute(name, value, operator="eq"):
    """Build an attribute comparison using the syntax sent by rs-server."""
    literal = f"'{value}'" if operator == "eq" else value
    return (
        f"Attributes/OData.CSC.StringAttribute/any(att:att/Name eq '{name}' "
        f"and att/OData.CSC.StringAttribute/Value {operator} {literal})"
    )


def mission(constellation, serial):
    """Keep each constellation and serial identifier in the same alternative."""
    return f"({attribute('platformShortName', constellation)} and {attribute('platformSerialIdentifier', serial)})"


REQUESTED_PAIRS = [("SENTINEL-1", "C"), ("SENTINEL-2", "B"), ("SENTINEL-3", "A")]
MISSION_FILTER = "(" + " or ".join(mission(*pair) for pair in REQUESTED_PAIRS) + ")"


@pytest.fixture
def mission_catalogue(tmp_path, monkeypatch):
    """Supply three requested satellites and four decoys without changing the station's catalogue."""
    (tmp_path / "Catalog").mkdir()
    decoys = [("SENTINEL-1", "A"), ("SENTINEL-1", "B"), ("SENTINEL-2", "A"), ("SENTINEL-3", "B")]
    products = [
        {
            "Id": f"p{index}",
            "Name": f"p{index}",
            "PublicationDate": f"2026-01-{index + 1:02d}T00:00:00Z",
            "Attributes": [
                {"Name": "platformShortName", "Value": constellation},
                {"Name": "platformSerialIdentifier", "Value": serial},
                {"Name": "productType", "Value": "TYPE_Y" if index == 1 else "TYPE_X"},
            ],
        }
        for index, (constellation, serial) in enumerate(REQUESTED_PAIRS + decoys)
    ]
    (tmp_path / "Catalog" / "GETFileResponse.json").write_text(json.dumps({"Data": products}), encoding="utf-8")
    monkeypatch.setitem(app.config, "configuration_path", tmp_path)


@pytest.mark.parametrize(
    "odata_filter,expected,options",
    [
        (MISSION_FILTER, ["p0", "p1", "p2"], {}),
        (mission(*REQUESTED_PAIRS[0]), ["p0"], {}),
        ("((" + MISSION_FILTER + "))", ["p0", "p1", "p2"], {}),
        (attribute("productType", "TYPE_X") + " and " + MISSION_FILTER, ["p0", "p2"], {}),
        ("(" + mission("SENTINEL-1", "D") + ")", [], {}),
        (MISSION_FILTER, ["p2"], {"$orderby": "PublicationDate desc", "$top": "1"}),
        (
            attribute("platformShortName", "('SENTINEL-1','SENTINEL-2')", "in")
            + " and "
            + attribute("platformSerialIdentifier", "('A','B')", "in"),
            ["p1", "p3", "p4", "p5"],
            {},
        ),
    ],
    ids=["three-pairs", "single-pair", "nested-groups", "product-type", "empty", "third-pair-pagination", "legacy-in"],
)
def test_grouped_mission_filters(mission_catalogue, odata_filter, expected, options):
    """Apply mission restrictions before pagination and exclude satellites outside the requested pairs."""
    params = {"$filter": odata_filter, "$expand": "Attributes", **options}
    with app.test_request_context("/Products", query_string=params):
        # Exercise the route and pagination wrapper, bypassing only authentication.
        response = app.make_response(query_products.__wrapped__())
    assert response.status_code == 200
    identifiers = [product["Id"] for product in json.loads(response.data)["value"]]
    assert set(identifiers) == set(expected)
    assert len(identifiers) == len(expected)


def test_separate_groups_are_not_stripped_together():
    """Only remove a matching pair of parentheses that encloses the entire expression."""
    parts, operators = split_composite_filter("(a) and (b)")
    assert parts == ["(a)", "(b)"]
    assert operators == ["and"]


@pytest.mark.parametrize("options", [{}, {"$orderby": "PublicationDate desc", "$top": "2"}])
def test_repeated_alternatives_do_not_consume_page(mission_catalogue, options):
    """Repeated collection branches must not fill a page with copies of the same product."""
    predicate = "(" + " or ".join(["(Id in ('p0','p1'))"] * 10) + ")"
    with app.test_request_context("/Products", query_string={"$filter": predicate, "$expand": "Attributes", **options}):
        response = app.make_response(query_products.__wrapped__())
    assert response.status_code == 200
    identifiers = [item["Id"] for item in json.loads(response.data)["value"]]
    assert set(identifiers) == {"p0", "p1"}
    assert len(identifiers) == 2
