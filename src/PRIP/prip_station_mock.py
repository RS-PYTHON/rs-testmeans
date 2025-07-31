"""PRIP mockup module implementation"""
import argparse
import pathlib
import logging
import datetime
import json
from flask import Flask, Response, request, send_file, after_this_request
from flask_bcrypt import Bcrypt
from flask_httpauth import HTTPBasicAuth
from http import HTTPStatus
import sys
from common.common_routes import (
    token_required,
    register_token_route, 
)
from common.pagination import additional_options, prepare_response_odata_v4
import re
from odata_lexer import parse_odata_filter
from shapely.geometry import Polygon, shape

PATH_TO_CONFIG = pathlib.Path(__file__).parent.resolve() / "config"

with open(PATH_TO_CONFIG / "Catalog" / "GETFileResponse.json") as bdata:
    data = json.loads(bdata.read())['Data']
    ATTRS = [attr["Name"] for attr in data[0]['Attributes']]

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
# @token_required to be activated later
@additional_options
def query_products():
    odata_filter = request.args["$filter"]
    geo_products = []
    all_id_sets = []
    if "OData.CSC.Intersects" in request.args['$filter']:
        geo_products = filter_items_by_polygon(data, odata_filter=request.args['$filter'])
        # Remove odata.csc.intersects after processed, and then continue with normal queries
        odata_filter = remove_intersects(request.args['$filter'])
        ids = {p['Id'] for p in geo_products}
        all_id_sets.append(ids)
    # use lexer to parse request, split it into field: {op, value}
    processed_filters = parse_odata_filter(odata_filter)
    # XAND?
    for filter_key, conditions in processed_filters.items():
        for cond in (conditions if isinstance(conditions, list) else [conditions]):
            products = process_products(
                filter_key,
                cond['op'],
                cond['value']
            )

        # store only id of the result
        ids = {p['Id'] for p in products}
        all_id_sets.append(ids)
    # create set intersection, XAND, exclusive and beetween requests
    if not all_id_sets:
        common_ids = set()
    else:
        common_ids = set.intersection(*all_id_sets) if all_id_sets else set()
    # filter data and return all items that match ids from common_ids
    return (
        Response(
            status=HTTPStatus.OK,
            response=json.dumps({"value": [item for item in data if item['Id'] in common_ids]}),
            headers=request.args
        ) if common_ids else Response(status=HTTPStatus.OK, response=json.dumps({"value": []}))
    )


def process_products(field, op, value) -> Response:
    # handle special case:
    match field:
        case "Name":
            match op.lower():
                case "contains":
                    results = [product for product in data if value in product[field]]
                case "startswith":
                    results = [product for product in data if product[field].startswith(value)]
                case "endswith":
                    results = [product for product in data if product[field].endswith(value)]
                case _:
                    return []
            return results
        case "PublicationDate" | "EvictionDate" | "ModificationDate" | "OriginDate" | "ContentDate/Start" | "ContentDate/End":
            # Special case of ContentDate/Start
            if "/" in field:
                top_key, sub_key = field.split("/")
                get_field = lambda product: datetime.datetime.fromisoformat(product[top_key][sub_key])
            else:
                get_field = lambda product: datetime.datetime.fromisoformat(product[field])
            date = datetime.datetime.fromisoformat(value)
            match op.lower():
                case "eq":
                    results = [
                        product
                        for product in data
                        if date == get_field(product)
                    ]
                case "gt":
                    results = [
                        product
                        for product in data
                        if date < get_field(product)
                    ]
                case "lt":
                    results = [
                        product
                        for product in data
                        if date > get_field(product)
                    ]
                case _:
                    return []
        case _ if field in ATTRS:
            results = [
                item for item in data
                if op == 'Eq' and any(attr.get("Name") == field and str(attr.get("Value")) == value for attr in item.get("Attributes", []))
            ]
        case _:
            raise NotImplemented
    return results


def create_prip_app():
    """Used to pass instance to conftest."""
    app.config["configuration_path"] = pathlib.Path(__file__).parent.resolve() / "config"
    return app

@app.route("/Products(<Id>)/$value", methods=["GET"])
#@token_required
def download_file(Id) -> Response:  # noqa: N803 # Must match endpoint arg
    """Download file endpoint"""
    files = [product for product in data if Id.replace("'", "") == product["Id"]]
    if len(files) != 1:
        return Response(status="404 None/Multiple files found")
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

    return [
        item for item in data
        if 'GeoFootprint' in item and request_polygon.intersects(shape(item['GeoFootprint']))
    ]

def remove_intersects(filter_str: str) -> str:
    pattern = r"OData\.CSC\.Intersects\s*\(\s*area=geography'[^']+'\s*\)\s*and\s*"
    return re.sub(pattern, '', filter_str, flags=re.IGNORECASE)

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
    auth_tmp_path =  str(app.config["configuration_path"] / "auth_tmp.json")
    auth_path =  str(app.config["configuration_path"] / "auth.json")

    # Copy data from the authentification template file (auth_tmp.json) to the authentification file (auth.json)
    with open(auth_tmp_path, "r", encoding="utf-8") as src:
        auth_tmp_dict = json.load(src)
    with open(auth_path, "w", encoding="utf-8") as dest:
        json.dump(auth_tmp_dict, dest, indent=4, ensure_ascii=False)
    
    app.run(debug=True, host=args.host, port=args.port)  # local
    # app.run(debug=True, host="0.0.0.0", port=8443) # loopback for LAN
