import argparse
import datetime
import json
import pathlib
import random
import re
from functools import wraps
from pathlib import Path
from typing import Any

from flask import Flask, Response, jsonify, request, send_file
from flask_bcrypt import Bcrypt
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
bcrypt = Bcrypt(app)
auth = HTTPBasicAuth()

HTTP_OK = 200
HTTP_CREATED = 201
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404

def token_required(f):
    """Docstring to be added."""

    @wraps(f)
    def decorated(*args, **kwargs):
        """Docstring to be added."""
        token = None        
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split()[1]

        if not token:
            return jsonify({"message": "Token is missing!"}), HTTP_FORBIDDEN

        auth_path = app.config["configuration_path"] / "auth.json"
        config_auth = json.loads(open(auth_path).read())        
        if token != config_auth["token"]:
            print("Returning HTTP_FORBIDDEN")
            return jsonify({"message": "Token is invalid!"}), HTTP_FORBIDDEN

        return f(*args, **kwargs)

    return decorated

def batch_response_odata_v4(resp_body: list | map) -> Any:
    """Used to custom-jsonify output to OData v4 protocol."""
    unpacked = list(resp_body) if not isinstance(resp_body, list) else resp_body
    return json.dumps(dict(responses=unpacked)) if len(unpacked) > 1 else json.dumps(unpacked[0])


@auth.verify_password
def verify_password(username, password) -> bool:
    """Small deco for basic auth check."""
    auth_path = app.config["configuration_path"] / "auth.json"
    users = json.loads(open(auth_path).read())
    if username in users.keys():
        return bcrypt.check_password_hash(users.get(username), password)
    return False


@app.route("/", methods=["GET", "POST"])
@token_required
def auth_page():
    """Only for auth, if reached here, return OK."""
    return Response(status=HTTP_OK)


@token_required
@app.route("/Products", methods=["GET"])
def query_files_endpoint():
    """Endpoint used to process query files requests."""
    if not request.args:
        return Response(status=HTTP_BAD_REQUEST)

    catalog_path = app.config["configuration_path"] / "Catalog/GETQueryResponse.json"
    catalog_data = json.loads(open(catalog_path).read())
    accepted_operators = [" and ", " or ", " not "]
    if any(header in request.args["$filter"] for header in accepted_operators):
        pattern = r"(\S+ \S+ \S+) (\S+) (\S+ \S+ \S+)"
        groups = re.search(pattern, request.args["$filter"])
        if groups:
            first_request, operator, second_request = groups.group(1), groups.group(2), groups.group(3)
            first_response = process_query_request(first_request.replace('"', ""), catalog_data)
            second_response = process_query_request(second_request.replace('"', ""), catalog_data)
        try:
            first_response = json.loads(first_response.data).get("responses", json.loads(first_response.data))
        except json.JSONDecodeError:
            first_response = []
        try:
            second_response = json.loads(second_response.data).get("responses", json.loads(second_response.data))
        except json.JSONDecodeError:
            second_response = []

        first_response = first_response if isinstance(first_response, list) else [first_response]
        second_response = second_response if isinstance(second_response, list) else [second_response]

        # Convert to a set, elements unique by ID
        fresp_set = {d.get("Id", None) for d in first_response}
        sresp_set = {d.get("Id", None) for d in second_response}
        match operator:
            case "and":  # intersection
                common_response = fresp_set.intersection(sresp_set)
                common_elements = [d for d in first_response if d.get("Id") in common_response]
                if common_elements:
                    return Response(
                        status=HTTP_OK,
                        response=batch_response_odata_v4(common_elements),
                        headers=request.args,
                    )
                return Response(status=HTTP_OK, response=json.dumps([]))
            case "or":  # union
                union_set = fresp_set.union(sresp_set)
                union_elements = [d for d in first_response + second_response if d.get("Id") in union_set]
                return Response(status=HTTP_OK, response=batch_response_odata_v4(union_elements), headers=request.args)
    else:
        response = process_query_request(request.args["$filter"], catalog_data)
        return Response(status=response.status, response=response.response)


def process_query_request(request: str, catalog_data: dict) -> Response:
    """Process individual requests."""
    resp_body = []
    if "Name" in request:
        if regex := re.search(r"(\w+)\((\w+),\'([^\']+)\'\)", request):
            op = regex.group(1)
            filter_by = regex.group(2)
            filter_value = regex.group(3).replace("'", "")
            match op:
                case "contains":
                    resp_body = [product for product in catalog_data["Data"] if filter_value in product[filter_by]]
                case "startswith":
                    resp_body = [
                        product for product in catalog_data["Data"] if product[filter_by].startswith(filter_value)
                    ]
                case "endswith":
                    resp_body = [
                        product for product in catalog_data["Data"] if product[filter_by].endswith(filter_value)
                    ]
            return (
                Response(status=HTTP_OK, response=batch_response_odata_v4(resp_body))
                if resp_body
                else (Response(status=HTTP_NOT_FOUND))
            )
    elif "PublicationDate" in request:
        field, op, value = request.split(" ")
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
        return (
            Response(status=HTTP_OK, response=batch_response_odata_v4(resp_body))
            if resp_body
            else Response(status=HTTP_NOT_FOUND)
        )
    elif "OData.CSC.Intersects" in request:
        # Geometrical intersection to be added in next versions
        pass
    else:
        split_request = request.replace('"', "")
        field, op, *value = split_request.split(" ")
        matching = []
        match op:
            case "eq":
                matching = [product for product in catalog_data["Data"] if value[0] == product[field]]
            case "in":
                for idx in value:
                    matching += [product for product in catalog_data["Data"] if idx.replace(",", "") in product[field]]
        return (
            Response(response=batch_response_odata_v4(matching), status=HTTP_OK)
            if matching
            else Response(status=HTTP_NOT_FOUND)
        )


@token_required
@app.route("/Products(<Id>)", methods=["GET", "POST"])
def create_order_endpoint(Id):
    """Add order to internal json."""
    return Response(status=HTTP_CREATED, response=create_product_order(Id))


def create_product_order(product_id: str) -> dict | str:
    """Create a product order."""
    order_file = Path(app.config["configuration_path"]) / "Internal/orders.json"

    # Open the JSON file and load the data
    with order_file.open("r") as file:
        data = json.load(file)

    existing_order = [order for order in data["orders"] if order["Id"] == product_id]
    if existing_order:
        return batch_response_odata_v4(existing_order)

    # Create a new order entry
    order_info = {
        "Id": product_id,
        "Status": "queued",
        "StatusMessage": "request is queued",
        "OrderSize": random.randint(0, 10000),
        "SubmissionDate": str(datetime.datetime.now()),
        "EstimatedDate": str(datetime.datetime.now() + datetime.timedelta(seconds=random.randint(10, 120))),
        "CompletedDate": None,
        "EvictionDate": None,
        "Priority": 1,  # default, not supported
        # "NotificationEndpoint": "N/A",
        # "NotificationEpUsername": "N/A",
        # "NotificationEpPassword": "N/A"
    }

    # Append the new order to the existing orders
    data["orders"].append(order_info)

    # Write the updated data back to the JSON file
    with order_file.open("w") as file:
        json.dump(data, file, indent=4)

    return json.dumps(order_info)


def update_product_order(order: dict, field: str, value: str) -> dict:
    """Update an existing order."""
    pass


@token_required
@app.route("/Orders", methods=["GET"])
def query_order_status_endpoint():
    """Check and update status of an existing order."""
    if not request.args:
        return Response(status=HTTP_BAD_REQUEST)

    field, op, value = request.args["$filter"].split(" ")
    order_file = Path(app.config["configuration_path"]) / "Internal/orders.json"
    if op != "eq":
        return  # not implemented yed
    # Open the JSON file and load the data
    with order_file.open("r") as file:
        data = json.load(file)

    selected_order = [order for order in data["orders"] if order[field] == value]
    if not selected_order or len(selected_order) > 1:
        return Response(status=HTTP_NOT_FOUND)
    else:
        selected_order = selected_order[0]

    order_estimated_time = datetime.datetime.strptime(selected_order["EstimatedDate"], "%Y-%m-%d %H:%M:%S.%f")
    if datetime.datetime.now() < order_estimated_time:
        # If estimated time has not passed, means that order is still processing
        selected_order["Status"] = "in_progress"
        selected_order["StatusMessage"] = "request is under processing"
    else:
        # order finished, return it.
        selected_order["Status"] = "completed"
        selected_order["StatusMessage"] = "requested product is available"
        selected_order["CompletedDate"] = str(datetime.datetime.now())
        selected_order["EvictionDate"] = str(datetime.datetime.now() + datetime.timedelta(days=3))

    with order_file.open("w") as file:
        json.dump(data, file, indent=4)

    return json.dumps(selected_order)


@token_required
@app.route("/Products(<product_id>)/$value", methods=["GET"])
def download_product_endpoint(product_id):
    """Endpoint to process download if available."""
    order_file = Path(app.config["configuration_path"]) / "Internal/orders.json"
    with order_file.open("r") as file:
        order_data = json.load(file)
    selected_order = [order for order in order_data["orders"] if order["Id"] == product_id]
    if selected_order != "completed":
        if not selected_order or len(selected_order) > 1:
            return Response(status=HTTP_NOT_FOUND)
        else:
            selected_order = selected_order[0]
        order_estimated_time = datetime.datetime.strptime(selected_order["EstimatedDate"], "%Y-%m-%d %H:%M:%S.%f")
        if datetime.datetime.now() < order_estimated_time:
            return Response(status=HTTP_FORBIDDEN, response="Not allowed yet")
        else:
            selected_order["Status"] = "completed"
            selected_order["StatusMessage"] = "requested product is available"
            selected_order["CompletedDate"] = str(datetime.datetime.now())
            selected_order["EvictionDate"] = str(datetime.datetime.now() + datetime.timedelta(days=3))
    # download it
    print(selected_order)
    catalog_path = app.config["configuration_path"] / "Catalog/GETQueryResponse.json"
    catalog_data = json.loads(open(catalog_path).read())
    product_name = [product["Name"] for product in catalog_data["Data"] if product["Id"] == selected_order["Id"]]
    if len(product_name) > 1:
        # Should be non-reachable
        return Response(status=HTTP_NOT_FOUND)
    else:
        product_name = product_name[0]

    if any(gzip_extension in product_name for gzip_extension in [".TGZ", ".gz", ".zip", ".tar"]):
        import io

        fpath = app.config["configuration_path"] / "Storage" / product_name
        send_args = io.BytesIO(open(fpath, "rb").read())
        return send_file(send_args, download_name=product_name, as_attachment=True)
    else:
        # Nominal case.
        return send_file(f"config/Storage/{product_name}")


@app.route("/health", methods=["GET"])
def ready_live_status():
    """Health probe."""
    return Response(status=HTTP_OK)


@app.route("/oauth2/token", methods=["POST"])
def token():
    """Docstring to be added."""
    # Get the form data
    print("Endpoint oauth2/token called")
    auth_path = app.config["configuration_path"] / "auth.json"
    config_auth = json.loads(open(auth_path).read())
    client_id = request.form.get("client_id")
    client_secret = request.form.get("client_secret")
    username = request.form.get("username")
    password = request.form.get("password")
    grant_type = request.form.get("grant_type")
    scope = request.form.get("scope")    

    # Optional Authorization header check
    # auth_header = request.headers.get('Authorization')
    # print(f"auth_header {auth_header}")
    print("Token requested")
    if request.headers.get("Authorization", None):
        print(f"Authorization in request.headers = {request.headers['Authorization']}")

    # Validate required fields
    if not client_id or not client_secret or not username or not password:
        print("Invalid client. The token is not granted")
        return Response(status=HTTP_UNAUTHORIZED, response=jsonify({"error": "Invalid client"}))

    if client_id != config_auth["client_id"] or client_secret != config_auth["client_secret"]:
        print("Invalid client id and/or secret. The token is not granted")
        return Response(status=HTTP_UNAUTHORIZED, response=jsonify({"error": "Invalid client id and/or secret"}))
    if username != config_auth["username"] or password != config_auth["password"]:
        print("Invalid username and/or password. The token is not granted")
        return Response(status=HTTP_UNAUTHORIZED, response=jsonify({"error": "Invalid username and/or password"}))
    # Validate the grant_type
    if grant_type != config_auth["grant_type"]:
        print("Unsupported grant_type. The token is not granted")
        return jsonify({"error": "Unsupported grant_type"}), HTTP_BAD_REQUEST    
    # Return the token in JSON format
    response = {"access_token": config_auth["token"], "token_type": "Bearer", "expires_in": 3600}
    print("Grant type validated. Token sent back")
    return Response(status=HTTP_OK, response=json.dumps(response))



def create_lta_app():  # noqa: D103
    """Docstring to be added."""
    app.config["configuration_path"] = pathlib.Path(__file__).parent.resolve() / "config"
    return app


if __name__ == "__main__":
    """Docstring to be added."""
    parser = argparse.ArgumentParser(description="Starts the LTA  server mockup ")

    default_config_path = pathlib.Path(__file__).parent.resolve() / "config"
    parser.add_argument("-p", "--port", type=int, required=False, default=5000, help="Port to use")
    parser.add_argument("-H", "--host", type=str, required=False, default="127.0.0.1", help="Host to use")

    args = parser.parse_args()

    app.config["configuration_path"] = pathlib.Path(__file__).parent.resolve() / "config"
    app.run(debug=True, host=args.host, port=args.port)  # local
    # app.run(debug=True, host="0.0.0.0", port=8443) # loopback for LAN
