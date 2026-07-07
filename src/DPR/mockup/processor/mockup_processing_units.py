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

# Module-level logger; it has no processor-instance state.
logger = EOLogging().get_logger(__name__, level=logging.INFO)


def output_product_types(output_products: Any | None = None) -> list[str]:
    """Extract the output product type names supplied by the tasktable payload."""
    if not output_products:
        logger.error("Missing output_products in the mockup tasktable payload")
        raise ValueError("The mockup processor requires output_products from the tasktable payload")

    product_types = []
    output_specs = output_products
    if isinstance(output_specs, dict):
        # EOPF may pass either one output spec or a routing map whose keys
        # are the product type names declared in the tasktable step.
        if {"name", "id", "product_type"} & set(output_specs):
            output_specs = [output_specs]
        else:
            output_specs = list(output_specs)

    for product in output_specs:
        if isinstance(product, str):
            # The mock tasktable passes the compact form: ["S03..._", ...].
            product_types.append(product)
        elif isinstance(product, dict):
            product_type = product.get("name") or product.get("id") or product.get("product_type")
            if product_type:
                product_types.append(product_type)

    if not product_types:
        logger.error(f"No valid output product type found in output_products={output_products!r}")
        raise ValueError("The mockup processor received no valid output product type")

    return product_types


def product_name(product_type: str, index: int) -> str:
    """Build a deterministic EOProduct id for the selected output type."""
    # Trim the tasktable suffix only for readability in the generated id.
    normalized_type = product_type.rstrip("_") or "MOCKUP"
    return f"{normalized_type}_MOCKUP_{index:03d}_20260101T000000"


def fixture_paths() -> tuple[Path, ...]:
    """Discover zipped Zarr fixtures available to the mock processor."""
    data_dir = Path(__file__).resolve().parents[2] / "data"
    # Keep fixture selection data-driven and stable across runs.
    paths = tuple(sorted(data_dir.glob("*.zarr.zip")))
    if not paths:
        logger.warning(f"No zipped Zarr fixture found in {data_dir}; default metadata will be used")
    # Path() deliberately triggers the default metadata fallback.
    return paths or (Path(),)


def load_attrs(fixture_path: Path, product_name: str, product_type: str) -> dict:
    """Load fixture metadata and adapt it to the generated mock product."""
    try:
        attrs = read_attrs(fixture_path)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        # Fixture data is optional for the mock; default STAC metadata keeps the flow runnable.
        logger.warning(f"Failed to read fixture metadata from {fixture_path}; using default metadata: {exc}")
        attrs = load_default_attrs()

    return normalize_attrs(attrs, product_name, product_type)


def read_attrs(path: Path) -> dict:
    """Read the root .zattrs metadata from a Zarr fixture archive or directory."""
    if path.suffix == ".zip":
        # A zipped Zarr keeps the root metadata under <archive-stem>/.zattrs.
        with zipfile.ZipFile(path, "r") as zipped:
            data = zipped.read(f"{path.stem}/.zattrs")
    else:
        # Keep directory support for local/unpacked fixture debugging.
        with open(path / ".zattrs", encoding="utf-8") as opened:
            data = opened.read()
    return json.loads(data)


def load_default_attrs() -> dict:
    """Load fallback STAC metadata used when fixture metadata is incomplete."""
    attrs_path = Path(__file__).resolve().parents[2] / "default_zattrs.json"
    with open(attrs_path, encoding="utf-8") as opened:
        return copy.deepcopy(json.load(opened))


def normalize_attrs(attrs: dict, product_name: str, product_type: str) -> dict:
    """Adapt fixture metadata to the mock EOProduct generated for this run."""
    # Fixtures are reusable templates. Copy before injecting the per-product
    # STAC id, product type and deterministic timestamps.
    attrs = copy.deepcopy(attrs)
    stac_discovery = attrs.setdefault("stac_discovery", {})
    stac_discovery["id"] = product_name
    stac_discovery.setdefault("type", "Feature")
    stac_discovery.setdefault("stac_version", "1.1.0")
    if not isinstance(stac_discovery.get("geometry"), dict):
        logger.warning(f"Fixture metadata has no STAC geometry object; using default geometry for {product_name}")
        # Some fixture .zattrs expose geometry in a non-STAC shape. Use the
        # corrected default STAC geometry/bbox instead of computing it here.
        default_stac = load_default_attrs()["stac_discovery"]
        stac_discovery["geometry"] = default_stac["geometry"]
        stac_discovery["bbox"] = default_stac["bbox"]

    properties = stac_discovery.setdefault("properties", {})
    # Keep catalog entries stable while making their type match the
    # tasktable output selected for this product.
    properties["datetime"] = "2026-01-01T00:00:00+00:00"
    properties["start_datetime"] = "2026-01-01T00:00:00+00:00"
    properties["end_datetime"] = "2026-01-01T00:00:00+00:00"
    properties["created"] = "2026-01-01T00:00:00+00:00"
    properties["eopf:type"] = product_type
    properties["product:type"] = product_type
    properties["product:timeliness_category"] = "NRT-3h"
    properties["processing:level"] = "L0"

    return attrs


def force_synchronous_zarr_writes() -> None:
    """
    Force EOPF to write Zarr outputs immediately.

    The processor itself is already running as a Dask task. With a minimal Dask
    cluster, EOPF delayed writing may submit extra Zarr write tasks to the same
    cluster while the only worker slot is still busy. Those write tasks cannot
    start, so EOPF waits until timeout. Forcing delayed_writing=False and
    delayed_consolidate=False makes EOPF write inline in the current task,
    without creating separate Dask write tasks.
    """
    # Patch only when the mock processor runs.
    from eopf.store.zarr import EOZarrStore  # pylint: disable=import-outside-toplevel

    # Idempotent: both mock steps may run in the same Python process.
    if getattr(EOZarrStore.open, "_dpr_mockup_sync_patch", False):
        return

    # Keep EOPF behavior; override only the delayed-write flags.
    original_open = EOZarrStore.open

    def open_with_synchronous_writes(self, *args, **kwargs):
        # Avoid extra Dask futures for this lightweight mock output.
        kwargs["delayed_writing"] = False
        kwargs["delayed_consolidate"] = False
        return original_open(self, *args, **kwargs)

    # Install the wrapper for this process only.
    open_with_synchronous_writes._dpr_mockup_sync_patch = True
    EOZarrStore.open = open_with_synchronous_writes
    logger.warning("DPR mockup monkeypatch active: EOPF Zarr delayed writing is disabled")


class single_unit_mockup(EOProcessingUnit):  # pylint: disable=invalid-name
    """EOPF processing unit used by the DPR mockup tasktable."""

    # EOPF instantiates this class from the workflow module/processing_unit
    # entries, so the mock follows the same orchestration path as real processors.
    PROCESSOR_MODEL = False

    def run(self, inputs, adfs=None, mode=None, **kwargs):  # pylint: disable=unused-argument
        """Return mock EOProducts that EOPF can write to the configured outputs."""
        force_synchronous_zarr_writes()
        # output_products comes from the tasktable payload; it is the source of
        # truth for the mock product types generated below.
        product_types = output_product_types(kwargs.get("output_products"))
        paths = fixture_paths()
        logger.info(f"Running DPR EOPF mockup processing unit step={self.identifier}")
        logger.info(f"Generating mock products for output types {product_types} from {len(paths)} fixture(s)")
        products = {}

        # Return stable generic keys; the tasktable routes each key to the
        # configured output destination through its output regex entries.
        for index, fixture_path in enumerate(paths, start=1):
            product_type = product_types[(index - 1) % len(product_types)]
            name = product_name(product_type, index)
            attrs = load_attrs(fixture_path, name, product_type)
            output_key = f"mock_output_{index}"
            logger.info(f"Created {output_key} as {product_type} using fixture {fixture_path}")
            products[output_key] = EOProduct(name, attrs=attrs, product_type=product_type)

        # EOPF handles storage/upload after this method returns.
        logger.info(f"Mockup processing unit returned {len(products)} product(s)")
        return products
