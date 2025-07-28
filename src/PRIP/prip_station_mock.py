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
#@additional_options
def query_products():
    # use lexer to parse request, split it into field: {op, value}
    processed_filters = parse_odata_filter(request.args["$filter"])
    # XAND?
    all_id_sets = []

    for filter_key in processed_filters:
        # process individual filter
        products = process_products(
            filter_key,
            processed_filters[filter_key]['op'],
            processed_filters[filter_key]['value']
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
                    # If the operation is not recognized, return a 404 NOT FOUND response
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
