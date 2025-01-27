"""Docstring to be added."""
import argparse
import datetime
import json
import logging
import pathlib
import re
import sys
from functools import wraps
from typing import Any

from flask import Flask, Response, request, send_file
from flask_bcrypt import Bcrypt
from flask_httpauth import HTTPBasicAuth

logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
app = Flask(__name__)
bcrypt = Bcrypt(app)
auth = HTTPBasicAuth()

HTTP_OK = 200
HTTP_BAD_REQUEST = 400
HTTP_UNAUTHORIZED = 401
HTTP_NOT_FOUND = 404

aditional_operators = [" and ", " or ", " in ", " not "]

def token_required(f):
    """Decorator to enforce token-based authentication for a Flask route.

    This decorator checks for the presence of a valid authorization token in the 
    request headers. It ensures that the incoming request contains a valid token, 
    which is compared against a pre-configured value stored in the auth.json file. If the 
    token is missing or invalid, the request is denied with a 403 Forbidden response.

    Args:
        f: The Flask route function being decorated.

    Returns:
        The decorated function that performs token validation before executing the original 
        route logic.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        """Inner function that performs token validation for the decorated route.

        This function:
        - Retrieves the token from the "Authorization" header.
        - If no token is found or the token is invalid, it logs the error and returns a 403 
          Forbidden response.
        - If the token is valid, it allows the original route logic to proceed.

        Args:
            *args: Positional arguments passed to the original route function.
            **kwargs: Keyword arguments passed to the original route function.

        Returns:
            A Response object with a 403 Forbidden status if the token is missing or invalid.
            Otherwise, the original route function's response is returned.
        """
        token = None        
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split()[1]

        if not token:
            logger.error("Returning HTTP_UNAUTHORIZED. Token is missing")
            return Response(status=HTTP_UNAUTHORIZED, response=json.dumps({"message": "Token is missing!"}))
        

        auth_path = app.config["configuration_path"] / "auth.json"
        config_auth = json.loads(open(auth_path).read())        
        if token != config_auth["token"]:
            logger.error("Returning HTTP_UNAUTHORIZED. Token is invalid!")
            return Response(status=HTTP_UNAUTHORIZED, response=json.dumps({"message": "Token is invalid!"}))

        return f(*args, **kwargs)

    return decorated

def additional_options(func):
    """Docstring to be added."""

    # This method is a wrapper that check if endpoints have some display options activated.
    # Endpoint function is called inside wrapper and output is sorted or sliced according to request arguments.
    @wraps(func)
    def wrapper(*args, **kwargs):
        accepted_display_options = ["$orderby", "$top", "$skip", "$count"]
        response = func(*args, **kwargs)
        display_headers = response.headers
        def parse_response_data():
            try:
                return json.loads(response.data)
            except json.JSONDecodeError:
                return None

        def sort_responses_by_field(json_data, field, reverse=False):
            keys = field.split("/")
            return {"value": sorted(json_data["value"], key=lambda x: x[keys[0]][keys[1]] if len(keys) > 1 else x[field], reverse=reverse)}

        def truncate_attrs(request, json_data):
            # Remove attribtes if not defined
            if not request.args.get("$expand", False) == "Attributes":
                if "value" in json_data:
                    for item in json_data['value']:
                        item.pop("Attributes")
                else:
                    json_data.pop("Attributes", None)
            return json_data
        
        if data := parse_response_data():
            json_data = truncate_attrs(request, data)
        else:
            return response
        if "value" not in json_data:
            return json_data
        if "$orderby" in display_headers:
            if " " in display_headers["$orderby"]:
                field, ordering_type = display_headers["$orderby"].split(" ")
            else:
                field, ordering_type = display_headers["$orderby"], "desc"
            json_data = sort_responses_by_field(json_data, field, reverse=(ordering_type == "desc"))
        # ICD extract:
        # $top and $skip are often applied together; in this case $skip is always applied first regardless of the order in which they appear in the query.
        skip_value = int(display_headers.get("$skip", 0))
        top_value = int(display_headers.get("$top", 1000))
        if "$skip" in display_headers:
            # No slicing if there is only one result
            json_data['value'] = json_data['value'][skip_value:]
        if "$top" in display_headers:
            # No slicing if there is only one result
            json_data['value'] = json_data['value'][:top_value]
                
        return prepare_response_odata_v4(json_data['value'])

    return wrapper


def prepare_response_odata_v4(resp_body: list | map) -> Any:
    """Prepare an OData v4 response.

    :param resp_body: The response body, which can be a list or a map.
    :type resp_body: Union[List[Any], Map[str, Any]]

    :return: A JSON string representing the OData v4 response.
    :rtype: str
    """
    unpacked = list(resp_body) if not isinstance(resp_body, list) else resp_body
    try:
        data = json.dumps(dict(value=unpacked)) # if len(unpacked) > 1 else json.dumps(unpacked[0])
    except IndexError:
        return json.dumps({"value": []})
    return data


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


@app.route("/health", methods=["GET"])
def ready_live_status():
    """Docstring to be added."""
    return Response(status=HTTP_OK)


@app.route("/", methods=["GET", "POST"])
@token_required
def hello():
    """Docstring to be added."""
    return Response(status=HTTP_OK)


def process_products_request(request, headers):
    """Docstring to be added."""
    catalog_path = app.config["configuration_path"] / "Catalog/GETFileResponse.json"
    catalog_data = json.loads(open(catalog_path).read())
    if "Name" in request:
        pattern = r"(\w+)\((\w+), '?([\w.]+)'?\)"
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
            Response(status=HTTP_OK, response=prepare_response_odata_v4(resp_body), headers=headers)
            if resp_body
            else Response(status=HTTP_NOT_FOUND)
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
            case "gte":
                resp_body = [
                    product
                    for product in catalog_data["Data"]
                    if date < datetime.datetime.fromisoformat(product[field]) or date == datetime.datetime.fromisoformat(product[field])
                ]
            case "lte":
                resp_body = [
                    product
                    for product in catalog_data["Data"]
                    if date > datetime.datetime.fromisoformat(product[field]) or date == datetime.datetime.fromisoformat(product[field])
                ]
            case _:
                # If the operation is not recognized, return a 404 NOT FOUND response
                return Response(status=HTTP_NOT_FOUND)
        return (
            Response(status=HTTP_OK, response=prepare_response_odata_v4(resp_body), headers=headers)
            if resp_body
            else Response(status=HTTP_OK, response=json.dumps({"value": []}))
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
            Response(status=HTTP_OK, response=prepare_response_odata_v4(resp_body), headers=headers)
            if resp_body
            else Response(status=HTTP_OK, response=json.dumps({"value": []}))
        )
    elif "Attributes" in request.args["$filter"]:
        pass  # WIP
    else:
        return Response(status=HTTP_BAD_REQUEST)

def process_query(query):
    # Step 1: Remove the part before "any("
    queries = query.split("any(")
    
    results = []
    
    # Step 2: Process each part individually
    for q in queries:
        if ")" in q:
            # Extract the content inside the parentheses
            q = q.split(")", 1)[0]
            # Split by "and" to separate the conditions
            parts = q.split(" and ")
            # Collect and clean up each part
            for part in parts:
                results.append(part.strip())
    
    return results
    
def extract_values_and_operation(part1, part2):
    # Regular expression to capture the operation and value between single quotes
    pattern = r"(\b(eq|gt|lt)\b)\s+'(.*?)'"
    
    # Search for the operation and value in part1
    value1 = re.search(r"'(.*?)'", part1).group(1) if re.search(r"'(.*?)'", part1) else None

    # Search for the operation and value in part2
    match2 = re.search(pattern, part2)
    if match2:
        operation = match2.group(1)  # Capture the operation (eq, gt, lt)
        value2 = match2.group(3)      # Capture the value between single quotes
    else:
        operation, value2 = None, None

    return value1, operation, value2
    
def process_attributes_search(query, headers):
    # Don;t touch this, it just works
    results = process_query(query)
    if len(results) == 2:
        return process_individual_query_part(process_query(query), headers)
    elif len(results) == 4:
        part1 = process_individual_query_part(process_query(query)[:2], headers)
        part2 = process_individual_query_part(process_query(query)[2:], headers)
        return Response(status=HTTP_OK, response=prepare_response_odata_v4(process_response(part1, part2)), headers=headers)

def process_response(query_resp1, query_resp2):
    response1 = json.loads(query_resp1.response[0].decode('utf-8')).get("value", json.loads(query_resp1.response[0].decode('utf-8')))
    response2 = json.loads(query_resp2.response[0].decode('utf-8')).get("value", json.loads(query_resp2.response[0].decode('utf-8')))
    ids_list1 = {item['Id'] for item in response1}
    ids_list2 = {item['Id'] for item in response2}
    common_ids = ids_list1.intersection(ids_list2)
    common_items_list1 = [item for item in response1 if item['Id'] in common_ids]
    common_items_list2 = [item for item in response2 if item['Id'] in common_ids]
    return common_items_list1 + common_items_list2


def process_individual_query_part(query_parts, headers):
    field, op, value = extract_values_and_operation(query_parts[0], query_parts[1])
    catalog_path = app.config["configuration_path"] / "Catalog/GETFileResponse.json"
    catalog_data = json.loads(open(catalog_path).read())
    if field in ("beginningDateTime", "endingDateTime", "processingDate"):
        date = datetime.datetime.fromisoformat(value)
        resp = []
        for product in catalog_data['Data']:
            for attr in product["Attributes"]:
                try:
                    if attr['Name'] == field:
                        match op:
                            case "eq":
                                if date == datetime.datetime.fromisoformat(attr['Value']):
                                    resp.append(product)
                            case "lt":
                                if date > datetime.datetime.fromisoformat(attr['Value']):
                                    resp.append(product)
                            case "gt":
                                if date > datetime.datetime.fromisoformat(attr['Value']):
                                    resp.append(product)
                except KeyError:
                    continue
    if field in ("platformShortName", "platformSerialIdentifier", "processingCenter", "productType", "processorVersion"):
        resp = []
        for product in catalog_data['Data']:
            for attr in product["Attributes"]:
                try:
                    if attr['Name'].lower() == field.lower() and attr['Value'].lower() == value.lower():
                        resp.append(product)
                except KeyError:
                    continue
    return Response(status=HTTP_OK, response=prepare_response_odata_v4(resp if resp else []), headers=headers)

def process_common_elements(first_response, second_response, operator):
    try:
        # Decode
        first_response_data = json.loads(first_response.data)
        # Get responses if any, else default json
        first_response = first_response_data.get("value", json.loads(first_response.data))
    except (json.decoder.JSONDecodeError, AttributeError):
        # Empty dict if error while unwrapping
        first_response = {"value": []}
    try:
        # Decode
        second_response_data = json.loads(second_response.data)
        # Get responses if any, else default json
        second_response = second_response_data.get("value", json.loads(second_response.data))
    except (json.decoder.JSONDecodeError, AttributeError):
        # Empty dict if error while unwrapping
        second_response = {"value": []}
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
            if common_elements:
                return Response(
                    status=HTTP_OK,
                    response=prepare_response_odata_v4(common_elements),
                    headers=request.args,
                )
            return Response(status=HTTP_OK, response=json.dumps({"value": []}))
        case "or":  # union
            union_set = fresp_set.union(sresp_set)
            union_elements = [d for d in first_response + second_response if d.get("Id") in union_set]
            return Response(
                status=HTTP_OK,
                response=prepare_response_odata_v4(union_elements),
                headers=request.args,
            )



@app.route("/Products", methods=["GET"])
@token_required
@additional_options
def query_products():
    """Docstring to be added."""
    if "$filter" not in request.args:
        catalog_path = app.config["configuration_path"] / "Catalog/GETFileResponse.json"
        catalog_data = json.loads(open(catalog_path).read())
        return Response(status=HTTP_OK, response=prepare_response_odata_v4(catalog_data['Data']), headers=request.args)
    if not any(
        [query_text in request.args["$filter"].split(" ")[0] for query_text in ["Name", "PublicationDate", "Attributes"]],
    ):
        return Response(status=HTTP_BAD_REQUEST)
    if len(qs_parser := request.args['$filter'].split(' and ')) > 2:
        outputs = []
        properties_filter = []
        attributes_filter = []
        for filter in qs_parser:
            if any(property in filter for property in ["contains", "PublicationDate"]):
                properties_filter.append(filter)
            elif "OData.CSC.StringAttribute" in filter:
                attributes_filter.append(filter)

        if len(properties_filter) > 4 or len(attributes_filter) > 4:
            msg = "Too complex for adgs sim"
            logger.error(msg)
            return Response ("Too complex for adgs sim", status=HTTP_BAD_REQUEST)

        # Process each property in the filter
        processed_requests = [
            process_products_request(prop.strip("'\""), request.args)
            for prop in properties_filter
        ]

        # Combine the processed requests based on the number of filters
        if len(processed_requests) in {1, 2, 3}:
            if len(processed_requests) == 1:
                outputs.append(processed_requests[0])
            else:
                common_elements = processed_requests[0]
                for req in processed_requests[1:]:
                    common_elements = process_common_elements(common_elements, req, "and")
                outputs.append(common_elements)
                if not attributes_filter:
                    # If there are no attributes to process, just return this
                    return Response(status=outputs[0].status, response=outputs[0].data, headers=request.args)


        # Handle attributes_filter processing
        if len(attributes_filter) in {2, 4}:
            for i in range(0, len(attributes_filter), 2):
                outputs.append(process_attributes_search(f"{attributes_filter[i]} and {attributes_filter[i + 1]}", request.args))

        try:
            return process_common_elements(outputs[0], outputs[1], "and")
        except IndexError:
            return Response(status=HTTP_OK, response=json.dumps({"value": []}))

    if "Attributes" in request.args['$filter'] or "OData.CSC" in request.args['$filter']:
        return process_attributes_search(request.args['$filter'], request.args)
    if any(header in request.args["$filter"] for header in aditional_operators):
        pattern = r"(\S+ \S+ \S+) (\S+) (\S+ \S+ \S+)"
        groups = re.search(pattern, request.args["$filter"])
        if groups:
            first_request, operator, second_request = groups.group(1), groups.group(2), groups.group(3)
            # split and processes the requests
            first_response = process_products_request(first_request.replace('"', ""), request.args)
            second_response = process_products_request(second_request.replace('"', ""), request.args)
            # Load response data to a json dict
            return process_common_elements(first_response, second_response, operator)

    return process_products_request(str(request.args["$filter"]), request.args)


@app.route("/Products(<Id>)/$value", methods=["GET"])
@token_required
def download_file(Id) -> Response:  # noqa: N803 # Must match endpoint arg
    """Docstring to be added."""
    catalog_path = app.config["configuration_path"] / "Catalog/GETFileResponse.json"
    catalog_data = json.loads(open(catalog_path).read())

    files = [product for product in catalog_data["Data"] if Id.replace("'", "") == product["Id"]]
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

@app.route("/oauth2/token", methods=["POST"])
def token():
    """OAuth 2.0 token endpoint for issuing an access token based on client credentials.

    It is intended to be used for tests only.
    This function handles the OAuth 2.0 token request by validating the incoming client 
    credentials, username, password, and grant type against the pre-configured values 
    stored in an authentication file (`auth.json`). If the request is valid, an access 
    token (fake string) is returned in JSON format; otherwise, appropriate error responses are sent.

    The supported grant type is validated against the `grant_type` stored in the configuration.

    Returns:
        Response: 
            - A JSON response with the access token and other token-related information 
              if the client credentials and other parameters are valid.
            - An HTTP 401 Unauthorized response if the client credentials, username, or 
              password are invalid.
            - An HTTP 400 Bad Request response if the grant type is unsupported or missing 
              required parameters.
    """
    # Get the form data
    logger.info("Endpoint oauth2/token called")
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
    logger.info("Token requested")    
    if request.headers.get("Authorization", None):
        logger.debug(f"Authorization in request.headers = {request.headers['Authorization']}")
    
    # Validate required fields
    if not client_id or not client_secret or not username or not password:
        logger.error("Invalid client. The token is not granted")
        return Response(status=HTTP_UNAUTHORIZED, response=json.dumps({"error": "Invalid client"}))

    if client_id != config_auth["client_id"] or client_secret != config_auth["client_secret"]:
        logger.error("Invalid client id and/or secret. The token is not granted")
        return Response(status=HTTP_UNAUTHORIZED, response=json.dumps({"error": 
                                                                       f"Invalid client id and/or secret: {client_id} | {client_secret}"}))
    if username != config_auth["username"] or password != config_auth["password"]:
        logger.error("Invalid username and/or password. The token is not granted")
        return Response(status=HTTP_UNAUTHORIZED, response=json.dumps({"error": "Invalid username and/or password"}))
    # Validate the grant_type
    if grant_type != config_auth["grant_type"]:
        logger.error("Unsupported grant_type. The token is not granted")
        return json.dumps({"error": "Unsupported grant_type"}), HTTP_BAD_REQUEST    
    # Return the token in JSON format
    response = {
        "access_token": config_auth["token"],
        "refresh_token": config_auth["refresh_token"], 
        "token_type": "Bearer", 
        "expires_in": 3600
    }
    logger.info("Grant type validated. Token sent back")
    return Response(status=HTTP_OK, response=json.dumps(response))



def create_adgs_app():
    """Docstring to be added."""
    # Used to pass instance to conftest
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
            print("Using default config")
    app.config["configuration_path"] = configuration_path
    app.run(debug=True, host=args.host, port=args.port)  # local
    # app.run(debug=True, host="0.0.0.0", port=8443) # loopback for LAN
