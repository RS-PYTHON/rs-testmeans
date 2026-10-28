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

"""Check boolean grouping, mission pairs and collection predicates before pagination."""

import json

import prip_station_mock as station
import pytest


def attribute(name, value):
    return (
        f"Attributes/OData.CSC.StringAttribute/any(att:att/Name eq '{name}' "
        f"and att/OData.CSC.StringAttribute/Value eq '{value}')"
    )


def mission(constellation, serial):
    return f"({attribute('platformShortName', constellation)} and {attribute('platformSerialIdentifier', serial)})"


PAIRS = [("SENTINEL-1", "C"), ("SENTINEL-2", "B"), ("SENTINEL-3", "A")]
MISSION_FILTER = "(" + " or ".join(mission(*pair) for pair in PAIRS) + ")"
GEO_FILTER = "OData.CSC.Intersects(area=geography'SRID=4326;POLYGON((0 0,2 0,2 2,0 2,0 0))')"


@pytest.fixture
def mission_catalogue(monkeypatch):
    """Include crossed satellite combinations and products outside the requested geometry."""
    decoys = [("SENTINEL-1", "A"), ("SENTINEL-1", "B"), ("SENTINEL-2", "A"), ("SENTINEL-3", "B")]
    products = []
    for index, (constellation, serial) in enumerate(PAIRS + decoys):
        products.append(
            {
                "Id": f"p{index}",
                "Name": "Rock 'n' roll and orbit" if index == 0 else f"p{index}",
                "PublicationDate": f"2026-01-{index + 1:02d}T00:00:00Z",
                "ContentDate": {"Start": f"2026-01-{index + 1:02d}T00:00:00Z"},
                "GeoFootprint": {"type": "Point", "coordinates": [10, 10] if index == 2 else [1, 1]},
                "Attributes": [
                    {"Name": "platformShortName", "Value": constellation},
                    {"Name": "platformSerialIdentifier", "Value": serial},
                    {"Name": "productType", "Value": "TYPE_Y" if index in (1, 4) else "TYPE_X"},
                ],
            },
        )
    monkeypatch.setattr(station, "data", products)
    monkeypatch.setattr(station, "ATTRS", ["platformShortName", "platformSerialIdentifier", "productType"])


@pytest.mark.parametrize(
    "odata_filter,expected,options",
    [
        (MISSION_FILTER, ["p0", "p1", "p2"], {}),
        (mission(*PAIRS[0]), ["p0"], {}),
        ("((" + MISSION_FILTER + "))", ["p0", "p1", "p2"], {}),
        (attribute("productType", "TYPE_X") + " and " + MISSION_FILTER, ["p0", "p2"], {}),
        (mission("SENTINEL-1", "D"), [], {}),
        (MISSION_FILTER, ["p2"], {"$orderby": "PublicationDate desc", "$top": "1"}),
        # An empty first alternative must not hide a later matching collection.
        (f"({attribute('productType', 'MISSING')}) or ({attribute('productType', 'TYPE_Y')})", ["p1", "p4"], {}),
        (
            f"({GEO_FILTER} and {attribute('productType', 'MISSING')}) or "
            f"({GEO_FILTER} and {attribute('productType', 'TYPE_Y')})",
            ["p1", "p4"],
            {},
        ),
        # Keep the geometry inside its own alternative instead of applying it to every branch.
        (f"({GEO_FILTER} and {mission(*PAIRS[0])}) or {mission(*PAIRS[2])}", ["p0", "p2"], {}),
        (
            f"({mission(*PAIRS[0])} and {attribute('productType', 'TYPE_X')}) or "
            f"({mission(*PAIRS[1])} and {attribute('productType', 'TYPE_X')})",
            ["p0"],
            {},
        ),
        (f"{GEO_FILTER} and {MISSION_FILTER}", ["p0", "p1"], {}),
        (
            "(ContentDate/Start gt 2026-01-02T00:00:00Z or ContentDate/Start eq 2026-01-02T00:00:00Z) "
            "and ContentDate/Start lt 2026-01-04T00:00:00Z",
            ["p1", "p2"],
            {},
        ),
        ("Name eq 'Rock ''n'' roll and orbit'", ["p0"], {}),
        ("Id in ('p0','p2')", ["p0", "p2"], {}),
        (
            "(" + " or ".join(["(Id in ('p0','p1'))"] * 10) + ")",
            ["p0", "p1"],
            {"$orderby": "PublicationDate desc", "$top": "2"},
        ),
    ],
)
def test_grouped_filters(mission_catalogue, odata_filter, expected, options):
    params = {"$filter": odata_filter, "$expand": "Attributes", **options}
    with station.app.test_request_context("/Products", query_string=params):
        # Keep pagination active while bypassing only authentication.
        response = station.app.make_response(station.query_products.__wrapped__())
    assert response.status_code == 200
    identifiers = [item["Id"] for item in json.loads(response.data)["value"]]
    assert set(identifiers) == set(expected)
    assert len(identifiers) == len(expected)
