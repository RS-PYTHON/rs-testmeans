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

"""PRIP mockup module implementation"""

import argparse
import datetime
import json
import logging
import os
import pathlib
import re
import sys
from http import HTTPStatus

import dotenv
from flask import Flask, Response, after_this_request, request, send_file
from flask_bcrypt import Bcrypt
from flask_httpauth import HTTPBasicAuth
from shapely.geometry import Polygon, shape

from common.common_routes import (
    register_token_route,
    token_required,
)
from common.odata_lexer import parse_odata_filter
from common.pagination import additional_options, prepare_response_odata_v4
from common.s3_handler import GetKeysFromS3Config, S3StorageHandler

PATH_TO_CONFIG = pathlib.Path(__file__).parent.resolve() / "config"

with open(PATH_TO_CONFIG / "Catalog" / "GETFileResponse.json") as bdata:
    data = json.loads(bdata.read())["Data"]
    ATTRS = [attr["Name"] for attr in data[0]["Attributes"]]

logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
app = Flask(__name__)
bcrypt = Bcrypt(app)
auth = HTTPBasicAuth()
register_token_route(app)


@app.route("/", methods=["GET", "POST"])
@token_required
def hello():
    """Homepage"""
    return Response(status=HTTPStatus.OK)


@app.route("/health", methods=["GET"])
def ready_live_status():
    """Live check endpoint"""
    return Response(status=HTTPStatus.OK)


@app.route("/Products", methods=["GET"])
@token_required
@additional_options
def query_products():
    if "$filter" not in request.args:
        return Response(status=HTTPStatus.OK, response=prepare_response_odata_v4(data), headers=request.args)
    matching_ids = evaluate_filter(request.args["$filter"]) or set()
    return Response(
        status=HTTPStatus.OK,
        response=prepare_response_odata_v4([item for item in data if item["Id"] in matching_ids]),
        headers=request.args,
    )


def split_filter_group(expression: str) -> tuple[str, list[str]]:
    """Split outer boolean operators, leaving quoted literals and any() expressions intact."""
    expression = expression.strip()
    depth = 0
    quoted = False
    closing_outer = None
    operators: dict[str, list[int]] = {"or": [], "and": []}
    for position, char in enumerate(expression):
        if char == "'":
            quoted = not quoted
        elif not quoted:
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0 and closing_outer is None:
                    closing_outer = position
            elif depth == 0:
                for operator in operators:
                    if expression[position : position + len(operator) + 2].lower() == f" {operator} ":
                        operators[operator].append(position)

    # Strip only parentheses enclosing the whole group, not the first of several sibling groups.
    if expression.startswith("(") and closing_outer == len(expression) - 1:
        return split_filter_group(expression[1:-1])
    # OR has lower precedence: each of its operands can contain a complete AND group.
    for operator, positions in operators.items():
        if positions:
            parts = []
            start = 0
            for position in positions:
                parts.append(expression[start:position])
                start = position + len(operator) + 2
            parts.append(expression[start:])
            return operator, parts
    return "", [expression]


def evaluate_filter(expression: str) -> set[str] | None:
    """Combine matching product IDs recursively, preserving AND/OR grouping before pagination."""
    operator, parts = split_filter_group(expression)
    if operator:
        matches = [result for part in parts if (result := evaluate_filter(part)) is not None]
        if not matches:
            return None
        return set.union(*matches) if operator == "or" else set.intersection(*matches)

    predicate = parts[0]
    if predicate.startswith("OData.CSC.Intersects"):
        return {item["Id"] for item in filter_items_by_polygon(data, predicate)}

    # Reuse the existing field handlers only for an atomic predicate; flattening a whole group loses OR.
    matches = []
    for field, conditions in parse_odata_filter(predicate).items():
        for condition in conditions if isinstance(conditions, list) else [conditions]:
            values = condition["value"]
            values = values if isinstance(values, list) else [values]
            identifiers = set()
            for value in values:
                products = process_products(field, condition["op"], getattr(value, "val", value))
                identifiers.update(item["Id"] for item in products)
            matches.append(identifiers)
    # Preserve the existing lexer behavior: unsupported predicates do not add a restriction.
    # An understood predicate with no matches still contributes an empty set.
    return set.intersection(*matches) if matches else None


def process_products(field, op, value) -> Response:
    # handle special case:
    match field:
        case "Id":
            # Support exact and list matching for Id in OData filters.
            op_lower = op.lower()

            def normalize_value(raw):
                return str(raw).strip().strip("'\"[]()")

            if op_lower == "eq":
                # Exact Id match.
                norm_value = normalize_value(value)
                results = [product for product in data if product["Id"] == norm_value]
            elif op_lower == "in":
                # Accept (a,b) and (['a','b']) list formats.
                t_values = value if isinstance(value, list) else [value]
                values = [normalize_value(v) for v in t_values]
                results = [product for product in data if product["Id"] in values]
            else:
                return []
            return results
        case "Name" | "Online":
            match op.lower():
                case "contains":
                    results = [product for product in data if value in product[field]]
                case "startswith":
                    results = [product for product in data if product[field].startswith(value)]
                case "endswith":
                    results = [product for product in data if product[field].endswith(value)]
                case "eq":
                    results = [product for product in data if str(product[field]).lower() == str(value).lower()]
                case "in":
                    t_values = value if isinstance(value, list) else [value]
                    values = [str(v).lower() for v in t_values]

                    results = [product for product in data if str(product[field]).lower() in values]
                case _:
                    return []
            return results
        case (
            "PublicationDate"
            | "EvictionDate"
            | "ModificationDate"
            | "OriginDate"
            | "ContentDate/Start"
            | "ContentDate/End"
        ):
            # Special case of ContentDate/Start
            if "/" in field:
                top_key, sub_key = field.split("/")
                get_field = lambda product: datetime.datetime.fromisoformat(product[top_key][sub_key])
            else:
                get_field = lambda product: datetime.datetime.fromisoformat(product[field])
            date = datetime.datetime.fromisoformat(value)
            match op.lower():
                case "eq":
                    results = [product for product in data if date == get_field(product)]
                case "gt":
                    results = [product for product in data if date < get_field(product)]
                case "lt":
                    results = [product for product in data if date > get_field(product)]
                case _:
                    return []
        case _ if field in ATTRS:
            results = [
                item
                for item in data
                if op == "Eq"
                and any(
                    attr.get("Name") == field and str(attr.get("Value")) == value for attr in item.get("Attributes", [])
                )
            ]
        case _:
            raise NotImplementedError
    return results


def create_prip_app():
    """Used to pass instance to conftest."""
    app.config["configuration_path"] = pathlib.Path(__file__).parent.resolve() / "config"
    return app


@app.route("/Products(<Id>)/$value", methods=["GET"])
@token_required
def download_file(Id) -> Response:  # noqa: N803 # Must match endpoint arg
    """Download file endpoint"""
    files = [product for product in data if Id.replace("'", "") == product["Id"]]
    if len(files) != 1:
        return Response(status="404 None/Multiple files found")

    file_info = files[0]
    if "S3_path" in file_info:
        try:
            # Try to create s3 connector using env variables
            handler = S3StorageHandler(
                os.environ["S3_ACCESSKEY"],
                os.environ["S3_SECRETKEY"],
                os.environ["S3_ENDPOINT"],
                os.environ["S3_REGION"],  # "sbg",
            )
        except KeyError:
            # If env variables are not set, check if /.s3cfg is there, and map the values.
            if not (s3_credentials := dotenv.dotenv_values(os.path.expanduser("/.s3cfg"))):
                return Response(
                    status=HTTPStatus.BAD_REQUEST,
                    response="You must have a s3cmd config file under '~/.s3cfg'",
                )
            handler = S3StorageHandler(
                s3_credentials["access_key"],
                s3_credentials["secret_key"],
                s3_credentials["host_bucket"],
                s3_credentials["bucket_location"],  # "sbg",
            )
        parts = file_info["S3_path"].replace("s3://", "").split("/", 1)
        handler.get_keys_from_s3(GetKeysFromS3Config([parts[1]], parts[0], "/tmp/prip"))
        file_path = f"/tmp/prip/{file_info['Name']}"

        @after_this_request
        def remove_file(response):
            try:
                os.remove(file_path)
            except Exception as e:
                app.logger.error(f"Failed to delete {file_path}: {e}")
            return response

        return send_file(file_path)

    # Send bytes of gzip files in order to avoid auto-decompress feature from application/gzip headers
    if any(gzip_extension in files[0]["Name"] for gzip_extension in [".TGZ", ".gz", ".zip", ".tar"]):
        import io

        fpath = app.config["configuration_path"] / "Storage" / files[0]["Name"]
        send_args = io.BytesIO(open(fpath, "rb").read())
        return send_file(send_args, download_name=files[0]["Name"], as_attachment=True)
    else:
        # Nominal case.
        send_args = f'config/Storage/{files[0]["Name"]}'
    return send_file(send_args)


def extract_polygon_from_odata_filter(odata_filter: str) -> Polygon:
    match = re.search(r"POLYGON\s*\(\((.*?)\)\)", odata_filter)
    if not match:
        raise ValueError("No valid POLYGON found in the OData filter string.")

    coords_str = match.group(1)
    coords = [tuple(map(float, c.strip().split())) for c in coords_str.split(",")]
    return Polygon(coords)


def filter_items_by_polygon(data: list[dict], odata_filter: str) -> list[dict]:
    request_polygon = extract_polygon_from_odata_filter(odata_filter)

    return [item for item in data if "GeoFootprint" in item and request_polygon.intersects(shape(item["GeoFootprint"]))]


def remove_intersects(filter_str: str) -> str:
    pattern = r"(\s*OData\.CSC\.Intersects\s*\(\s*area=geography'[^']+'\s*\)\s*and\s*)|(\s*and\s*OData\.CSC\.Intersects\s*\(\s*area=geography'[^']+'\s*\))|(^OData\.CSC\.Intersects\s*\(\s*area=geography'[^']+'\s*\)$)"
    result = re.sub(pattern, "", filter_str, flags=re.IGNORECASE)
    return result.strip()


if __name__ == "__main__":
    """Docstring to be added."""
    parser = argparse.ArgumentParser(
        description="Starts the ADGS server mockup ",
    )

    default_config_path = pathlib.Path(__file__).parent.resolve() / "config"
    parser.add_argument("-p", "--port", type=int, required=False, default=5000, help="Port to use")
    parser.add_argument("-H", "--host", type=str, required=False, default="127.0.0.1", help="Host to use")
    parser.add_argument("-c", "--config", type=str, required=False, default=default_config_path)

    args = parser.parse_args()
    configuration_path = pathlib.Path(args.config)

    if default_config_path is not configuration_path:
        # define config folder mandatory structure
        config_signature = ["auth.json", "Catalogue/GETFileResponse.json"]
        if not all((configuration_path / file_name).exists() for file_name in config_signature):
            # use default config if given structure doesn't match
            configuration_path = default_config_path
            logger.info("Using default config")
    app.config["configuration_path"] = configuration_path

    # Create a json file containing the authentification configuration
    # this file will be deleted at the shutdown of the application
    auth_tmp_path = str(app.config["configuration_path"] / "auth_tmp.json")
    auth_path = str(app.config["configuration_path"] / "auth.json")

    # Copy data from the authentification template file (auth_tmp.json) to the authentification file (auth.json)
    with open(auth_tmp_path, encoding="utf-8") as src:
        auth_tmp_dict = json.load(src)
    with open(auth_path, "w", encoding="utf-8") as dest:
        json.dump(auth_tmp_dict, dest, indent=4, ensure_ascii=False)

    app.run(debug=True, host=args.host, port=args.port)  # local
    # app.run(debug=True, host="0.0.0.0", port=8443) # loopback for LAN
