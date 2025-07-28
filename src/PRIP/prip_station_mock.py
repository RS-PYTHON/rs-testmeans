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

PATH_TO_CONFIG = pathlib.Path(__file__).parent.resolve() / "config"

with open(PATH_TO_CONFIG / "Catalog" / "GETFileResponse.json") as bdata:
    data = json.loads(bdata.read())['Data']

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
    return process_products(request.args["$filter"], request.args)


def process_products(request, headers) -> Response:
    if "Name" in request:
        pattern = r"(\w+)\((\w+),\s*'([^']+)'\)"
        op = re.search(pattern, request).group(1)
        filter_by = re.search(pattern, request).group(2)
        filter_value = re.search(pattern, request).group(3)
        match op:
            case "contains":
                resp_body = [product for product in data if filter_value in product[filter_by]]
            case "startswith":
                resp_body = [product for product in data if product[filter_by].startswith(filter_value)]
            case "endswith":
                resp_body = [product for product in data if product[filter_by].endswith(filter_value)]
        return (
            Response(status=HTTPStatus.OK, response=prepare_response_odata_v4(resp_body), headers=headers)
            if resp_body
            else Response(status=HTTPStatus.NOT_FOUND)
        )
    elif any(field in request for field in ["PublicationDate", "EvictionDate", "ModificationDate", "OriginDate"]):
        field, op, value = request.split(" ")
        date = datetime.datetime.fromisoformat(value)
        match op:
            case "eq":
                resp_body = [
                    product
                    for product in data
                    if date == datetime.datetime.fromisoformat(product[field])
                ]
            case "gt":
                resp_body = [
                    product
                    for product in data
                    if date < datetime.datetime.fromisoformat(product[field])
                ]
            case "lt":
                resp_body = [
                    product
                    for product in data
                    if date > datetime.datetime.fromisoformat(product[field])
                ]
            case _:
                # If the operation is not recognized, return a 404 NOT FOUND response
                return Response(status=HTTPStatus.NOT_FOUND)
        return (
            Response(status=HTTPStatus.OK, response=prepare_response_odata_v4(resp_body), headers=headers)
            if resp_body
            else Response(status=HTTPStatus.OK, response=json.dumps({"value": []}))
        )

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
