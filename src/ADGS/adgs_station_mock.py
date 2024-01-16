"""Docstring to be added."""
import argparse
import datetime
import json
import pathlib
import re
from typing import Any

from flask import Flask, Response, request, send_file
from flask_bcrypt import Bcrypt
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
bcrypt = Bcrypt(app)
auth = HTTPBasicAuth()

OK = 200
BAD_REQUEST = 400
UNAUTHORIZED = 401
NOT_FOUND = 404

aditional_operators = [" and ", " or ", " in ", " not "]


def prepare_response_odata_v4(resp_body: list | map) -> Any:
    """Prepare an OData v4 response.

    :param resp_body: The response body, which can be a list or a map.
    :type resp_body: Union[List[Any], Map[str, Any]]

    :return: A JSON string representing the OData v4 response.
    :rtype: str
    """
    unpacked = list(resp_body) if not isinstance(resp_body, list) else resp_body
    return json.dumps(dict(responses=unpacked)) if len(unpacked) > 1 else json.dumps(unpacked[0])


@auth.verify_password
def verify_password(username: str, password: str) -> bool:
    """Verify the password for a given username.

    :param username: The username for which the password is being verified.
    :type username: str

    :param password: The password to be verified.
    :type password: str

    :return: True if the password is valid, False otherwise.
    :rtype: Optional[bool]
    """
    auth_path = app.config["configuration_path"] / "auth.json"
    users = json.loads(open(auth_path).read())
    if username in users.keys():
        return bcrypt.check_password_hash(users.get(username), password)
    return False


@app.route("/", methods=["GET", "POST"])
@auth.login_required
def hello():
    """Docstring to be added."""
    return Response(status=OK)


def process_products_request(request):
    """Docstring to be added."""
    catalog_path = app.config["configuration_path"] / "Catalog/GETFileResponse.json"
    catalog_data = json.loads(open(catalog_path).read())
    if "Name" in request:
        pattern = r"(\w+)\((\w+), \'?(\w+)\'?\)"
        op = re.search(pattern, request).group(1)
        filter_by = re.search(pattern, request).group(2)
        filter_value = re.search(pattern, request).group(3)
        match op:
            case "contains":
                resp_body = [product for product in catalog_data["Data"] if filter_value in product[filter_by]]
            case "startswith":
                resp_body = [product for product in catalog_data["Data"] if product[filter_by].startswith(filter_value)]
            case "endswith":
                resp_body = [product for product in catalog_data["Data"] if product[filter_by].endswith(filter_value)]
        return (
            Response(status=OK, response=prepare_response_odata_v4(resp_body))
            if resp_body
            else Response(status=NOT_FOUND)
        )
    elif "PublicationDate" in request:
        field, op, value = request.split(" ")
        # year-month-day
        date = datetime.datetime.fromisoformat(value)
        match op:
            case "eq":
                resp_body = [
                    product
                    for product in catalog_data["Data"]
                    if date == datetime.datetime.fromisoformat(product[field])
                ]
            case "gt":
                resp_body = [
                    product
                    for product in catalog_data["Data"]
                    if date < datetime.datetime.fromisoformat(product[field])
                ]
            case "lt":
                resp_body = [
                    product
                    for product in catalog_data["Data"]
                    if date > datetime.datetime.fromisoformat(product[field])
                ]
            case _:
                # If the operation is not recognized, return a 404 NOT FOUND response
                return Response(status=NOT_FOUND)
        return (
            Response(status=OK, response=prepare_response_odata_v4(resp_body))
            if resp_body
            else Response(status=NOT_FOUND)
        )
    elif "ContentDate" in request.args["$filter"]:
        pattern = r"Start (\S+) (\S+) and ContentDate/End (\S+) (\S+)"
        regex_match = re.search(pattern, request.args["$filter"])
        start_oper = regex_match.group(1)
        start_date = datetime.datetime.fromisoformat(regex_match.group(2))
        stop_oper = regex_match.group(3)
        stop_date = datetime.datetime.fromisoformat(regex_match.group(4))
        match (start_oper, stop_oper):
            case ("gt", "lt"):
                resp_body = [
                    product
                    for product in catalog_data["Data"]
                    if (
                        start_date < datetime.datetime.fromisoformat(product["ContentDate"]["Start"])
                        and stop_date > datetime.datetime.fromisoformat(product["ContentDate"]["End"])
                    )
                ]
            case ("eq", "lt"):
                resp_body = [
                    product
                    for product in catalog_data["Data"]
                    if (
                        start_date == datetime.datetime.fromisoformat(product["ContentDate"]["Start"])
                        and stop_date > datetime.datetime.fromisoformat(product["ContentDate"]["End"])
                    )
                ]
        return (
            Response(status=OK, response=prepare_response_odata_v4(resp_body))
            if resp_body
            else Response(status=NOT_FOUND)
        )
    elif "Attributes" in request.args["$filter"]:
        pass  # WIP
    else:
        return Response(status=BAD_REQUEST)


@app.route("/Products", methods=["GET"])
@auth.login_required
def query_products():
    """Docstring to be added."""
    if not request.args:
        return Response(status=BAD_REQUEST)
    if not any(
        [query_text in request.args["$filter"].split(" ")[0] for query_text in ["Name", "PublicationDate"]],
    ):
        return Response(status=BAD_REQUEST)
    if any(header in request.args["$filter"] for header in aditional_operators):
        pattern = r"(\S+ \S+ \S+) (\S+) (\S+ \S+ \S+)"
        groups = re.search(pattern, request.args["$filter"])
        if groups:
            first_request, operator, second_request = groups.group(1), groups.group(2), groups.group(3)
            # split and processes the requests
            first_response = process_products_request(first_request.replace('"', ""))
            second_response = process_products_request(second_request.replace('"', ""))
            # Load response data to a json dict
            first_response = json.loads(first_response.data).get("responses", json.loads(first_response.data))
            second_response = json.loads(second_response.data).get("responses", json.loads(second_response.data))
            # Normalize responses, must be a list, even with one element, for iterator
            first_response = first_response if isinstance(first_response, list) else [first_response]
            second_response = second_response if isinstance(second_response, list) else [second_response]
            # Convert to a set, elements unique by ID
            fresp_set = {d.get("Id") for d in first_response}
            sresp_set = {d.get("Id") for d in second_response}
            match operator:
                case "and":  # intersection
                    common_response = fresp_set.intersection(sresp_set)
                    common_elements = [d for d in first_response if d.get("Id") in common_response]
                    return Response(status=OK, response=prepare_response_odata_v4(common_elements))
                case "or":  # union
                    union_set = fresp_set.union(sresp_set)
                    union_elements = [d for d in first_response + second_response if d.get("Id") in union_set]
                    return Response(status=OK, response=prepare_response_odata_v4(union_elements))

    return process_products_request(str(request.args["$filter"]))


@app.route("/Products(<Id>)/$value", methods=["GET"])
@auth.login_required
def download_file(Id) -> Response:  # noqa: N803 # Must match endpoint arg
    """Docstring to be added."""
    catalog_path = app.config["configuration_path"] / "Catalog/GETFileResponse.json"
    catalog_data = json.loads(open(catalog_path).read())

    files = [product for product in catalog_data["Data"] if Id.replace("'", "") == product["Id"]]
    return (
        send_file("config/Storage/" + files[0]["Name"])
        if len(files) == 1
        else Response(status="404 None/Multiple files found")
    )


def create_adgs_app():
    """Docstring to be added."""
    # Used to pass instance to conftest
    app.config["configuration_path"] = pathlib.Path(__file__).parent.resolve() / "config"
    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Starts the ADGS server mockup ",
    )

    default_config_path = pathlib.Path(__file__).parent.resolve() / "config"
    parser.add_argument("-p", "--port", type=int, required=False, default=5001, help="Port to use")
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
            print("Using default config")
    app.config["configuration_path"] = configuration_path
    app.run(debug=True, host=args.host, port=args.port)  # local
    # app.run(debug=True, host="0.0.0.0", port=8443) # loopback for LAN
