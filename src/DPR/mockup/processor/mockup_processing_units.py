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

"""EOPF-compatible mockup processing units."""

import copy
import json
import logging
import zipfile
from pathlib import Path
from typing import Any

from eopf.computing import EOProcessingUnit
from eopf.logging import EOLogging
from eopf.product import EOProduct

logger = EOLogging().get_logger(__name__, level=logging.INFO)

DEFAULT_OUTPUT_PRODUCTS = [
    {
        "name": "S03OLCL0_",
        "mode": "always",
        "mandatory": True,
        "regex": ".*",
    },
]

MOCKUP_DATA_FILES = (
    "S01SEWRAW_20250611T041159_0050_A102_TFDC.zarr.zip",
    "S01SIWRAW_20250611T044009_0023_A102_TC97.zarr.zip",
    "S01SIWRAW_20250611T050659_0518_A102_TB03.zarr.zip",
    "S01SWVRAW_20250611T004605_0011_A102_T38E.zarr.zip",
    "S01SWVRAW_20250611T023633_1378_A102_T14D.zarr.zip",
)


class single_unit_mockup(EOProcessingUnit):  # pylint: disable=invalid-name
    """EOPF processing unit used by the DPR mockup tasktable."""

    PROCESSOR_MODEL = False

    def run(self, inputs, adfs=None, mode=None, **kwargs):  # pylint: disable=unused-argument
        """Return mock EOProducts that EOPF can write to the configured outputs."""
        logger.info("Running DPR EOPF mockup processing unit")
        output_product_types = self._output_product_types(kwargs.get("output_products"))
        products = {}

        for index, fixture_path in enumerate(self._fixture_paths(), start=1):
            product_type = output_product_types[(index - 1) % len(output_product_types)]
            product_name = self._product_name(product_type, index)
            attrs = self._load_attrs(fixture_path, product_name, product_type)
            products[f"mock_output_{index}"] = EOProduct(product_name, attrs=attrs, product_type=product_type)

        return products

    @classmethod
    def _output_product_types(cls, output_products: Any | None = None) -> list[str]:
        product_types = []
        output_specs = output_products or DEFAULT_OUTPUT_PRODUCTS
        if isinstance(output_specs, dict):
            if {"name", "id", "product_type"} & set(output_specs):
                output_specs = [output_specs]
            else:
                output_specs = list(output_specs)

        for product in output_specs:
            if isinstance(product, str):
                product_types.append(product)
            elif isinstance(product, dict):
                product_type = product.get("name") or product.get("id") or product.get("product_type")
                if product_type:
                    product_types.append(product_type)

        return product_types or [DEFAULT_OUTPUT_PRODUCTS[0]["name"]]

    @staticmethod
    def _product_name(product_type: str, index: int) -> str:
        normalized_type = product_type.rstrip("_") or "MOCKUP"
        return f"{normalized_type}_MOCKUP_{index:03d}_20260101T000000"

    @staticmethod
    def _fixture_paths() -> tuple[Path, ...]:
        data_dir = Path(__file__).resolve().parents[2] / "data"
        paths = tuple(data_dir / filename for filename in MOCKUP_DATA_FILES if (data_dir / filename).exists())
        return paths or (Path(),)

    @classmethod
    def _load_attrs(cls, fixture_path: Path, product_name: str, product_type: str) -> dict:
        try:
            attrs = cls._read_attrs(fixture_path)
        except Exception:  # pylint: disable=broad-exception-caught
            attrs = cls._load_default_attrs()

        return cls._normalize_attrs(attrs, product_name, product_type)

    @staticmethod
    def _read_attrs(path: Path) -> dict:
        if path.suffix == ".zip":
            with zipfile.ZipFile(path, "r") as zipped:
                data = zipped.read(f"{path.stem}/.zattrs")
        else:
            with open(path / ".zattrs", encoding="utf-8") as opened:
                data = opened.read()
        return json.loads(data)

    @staticmethod
    def _load_default_attrs() -> dict:
        """Load the default mockup metadata used for the generated EOProduct."""
        attrs_path = Path(__file__).resolve().parents[2] / "default_zattrs.json"
        with open(attrs_path, encoding="utf-8") as opened:
            return copy.deepcopy(json.load(opened))

    @staticmethod
    def _normalize_attrs(attrs: dict, product_name: str, product_type: str) -> dict:
        """Normalize the mockup metadata used for the generated EOProduct."""
        attrs = copy.deepcopy(attrs)
        stac_discovery = attrs.setdefault("stac_discovery", {})
        stac_discovery["id"] = product_name
        stac_discovery.setdefault("type", "Feature")
        stac_discovery.setdefault("stac_version", "1.1.0")
        geometry = stac_discovery.get("geometry", {})
        if not isinstance(geometry, dict):
            geometry = copy.deepcopy(single_unit_mockup._load_default_attrs()["stac_discovery"]["geometry"])
            stac_discovery["geometry"] = geometry
        if geometry.get("type") == "Polygon":
            for ring in geometry.get("coordinates", []):
                if ring and ring[0] != ring[-1]:
                    ring.append(copy.deepcopy(ring[0]))
                area = sum(
                    ring[index][0] * ring[index + 1][1] - ring[index + 1][0] * ring[index][1]
                    for index in range(len(ring) - 1)
                )
                if area < 0:
                    ring[:] = [ring[0], *reversed(ring[1:-1]), ring[0]]
            coordinates = [point for ring in geometry.get("coordinates", []) for point in ring]
            if coordinates:
                longitudes = [point[0] for point in coordinates]
                latitudes = [point[1] for point in coordinates]
                stac_discovery["bbox"] = [min(longitudes), min(latitudes), max(longitudes), max(latitudes)]

        properties = stac_discovery.setdefault("properties", {})
        properties["datetime"] = "2026-01-01T00:00:00+00:00"
        properties["start_datetime"] = "2026-01-01T00:00:00+00:00"
        properties["end_datetime"] = "2026-01-01T00:00:00+00:00"
        properties["created"] = "2026-01-01T00:00:00+00:00"
        properties["eopf:type"] = product_type
        properties["product:type"] = product_type
        properties["product:timeliness_category"] = "NRT-3h"
        properties["processing:level"] = "L0"

        return attrs
