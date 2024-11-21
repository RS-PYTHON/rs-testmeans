"""Docstring to be added."""
import argparse
import datetime
import json
import logging
import os
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
HTTP_FORBIDDEN = 403
HTTP_NOT_FOUND = 404

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
            logger.error("Returning HTTP_FORBIDDEN. Token is missing")
            return Response(status=HTTP_FORBIDDEN, response=json.dumps({"message": "Token is missing!"}))
        

        auth_path = app.config["configuration_path"] / "auth.json"
        config_auth = json.loads(open(auth_path).read())        
        if token != config_auth["token"]:
            logger.error("Returning HTTP_FORBIDDEN. Token is invalid!")
            return Response(status=HTTP_FORBIDDEN, response=json.dumps({"message": "Token is invalid!"}))

        return f(*args, **kwargs)

    return decorated

def additional_options(func):
    """Docstring to be added."""

    # This method is a wrapper that check if endpoints have some display options activated.
    # Endpoint function is called inside wrapper and output is sorted or sliced according to request arguments.
    @wraps(func)
    def wrapper(*args, **kwargs):
        response = func(*args, **kwargs)
        display_headers = response.headers

        def parse_response_data():
            try:
                return json.loads(response.data)
            except json.JSONDecodeError:
                return None

        def sort_responses_by_field(json_data, field, reverse=False):
            return {"value": sorted(json_data["value"], key=lambda x: x[field], reverse=reverse)}

        json_data = parse_response_data()
        if json_data and "value" not in json_data or not json_data:
            return response

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
        if "$orderby" in display_headers:
            if " " in display_headers["$orderby"]:
                field, ordering_type = display_headers["$orderby"].split(" ")
            else:
                field, ordering_type = display_headers["$orderby"], "desc"
            json_data = sort_responses_by_field(json_data, field, reverse=(ordering_type == "desc"))
                
        return batch_response_odata_v4(json_data['value'])

    return wrapper


def batch_response_odata_v4(resp_body: list | map) -> Any:
    """Docstring to be added."""
    unpacked = list(resp_body) if resp_body and not isinstance(resp_body, list) else resp_body
    try:
        data = json.dumps(dict(value=unpacked)) if len(unpacked) > 1 else json.dumps(unpacked[0] if unpacked else [])
    except IndexError:
        return json.dumps({})
    return data


@auth.verify_password
def verify_password(username, password) -> bool:
    """Docstring to be added."""
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
    # Used only for auth, if reached here, return HTTP_OK.
    return Response(status=HTTP_OK)


# 3.3 (PSD)
@app.route("/Sessions", methods=["GET"])
@token_required
@additional_options
def query_session() -> Response | list[Any]:
    """Docstring to be added."""
    catalog_path = app.config["configuration_path"] / "Catalogue/SPJ.json"
    catalog_data = json.loads(open(catalog_path).read())
    if "$filter" not in request.args:
        return Response(status=HTTP_OK, response=batch_response_odata_v4(catalog_data['Data']), headers=request.args)
        # return Response('Bad Request', Response.status_code(400), None)
    # Check requested values, filter type can only be json keys
    if not any(
        [query_text == request.args["$filter"].strip('"').split(" ")[0] for query_text in SPJ_LUT.keys()],
    ):
        return Response(status=HTTP_BAD_REQUEST)
    # Proceed to process request
    catalog_path_files = app.config["configuration_path"] / "Catalogue/FileResponse.json"
    catalog_data_files = json.loads(open(catalog_path_files).read())
    # all operators with all possible spacing combinations
    # accepted_operators = [" and ", " or ", " in ", " not ", "and ", " or ", " in ", " not", "and", "or", "in", "not"]
    # split_request = [req.strip() for req in request.args["$filter"].split('and')]
    # Handle multiple "AND" / "OR" operands
    if len(split_request := [req.strip() for req in request.args["$filter"].split("and")]) in [2, 3]:
        responses = [process_session_request(req, request.args, catalog_data) for req in split_request]
        if not all(resp.status_code == 200 for resp in responses):
            return Response(response=json.dumps([]), status=HTTP_OK)
        if any(not resp.response for resp in responses):
            # Case where an response is empty or not dict => the query is empty
            return Response(response=json.dumps([]), status=HTTP_NOT_FOUND)
        try:
            responses_json = [json.loads(resp.data).get("value", json.loads(resp.data)) for resp in responses]
            responses_norm = [resp if isinstance(resp, list) else [resp] for resp in responses_json]
            resp_set = [{d.get("Id") for d in resp} for resp in responses_norm]
            common_response = set.intersection(*resp_set)
            common_elements = [d for d in responses_norm[0] if d.get("Id") in common_response]
            # 200 HTTP_OK even if search is empty
            if app.config.get("expand", None) and request.args.get("$expand", None) in ["Files", "files"]:
                for session in common_elements:
                    files = json.loads(
                        process_files_request(
                            f'SessionID eq {session["SessionId"]}',
                            request.args,
                            catalog_data_files,
                        ).response[0],
                    )
                    files = files["value"] if "value" in files else [files]
                    session.update({"Files": [file for file in files]})
                return Response(status=HTTP_OK, response=batch_response_odata_v4(common_elements), headers=request.args)
            else:
                # If expand is enabled with -e and request contains &$expand
                # Do not expand
                return (
                    Response(status=HTTP_OK, response=batch_response_odata_v4(common_elements), headers=request.args)
                    if common_elements
                    else (Response(response=json.dumps([]), status=HTTP_OK))
                )
        except (json.JSONDecodeError, AttributeError):  # if a response is empty, whole querry is empty
            return Response(status=HTTP_NOT_FOUND)
    elif len(split_request := [req.strip() for req in request.args["$filter"].split("or")]) in [2, 3]:
        # add test when a response is empty, and other not.
        responses = [process_session_request(req, request.args, catalog_data) for req in split_request]
        # if not all(isinstance(resp, dict) for resp in responses):
        #     # handle incorrect requests, status HTTP_OK, but empty content
        #     For OR operator, responses can be empty
        #     return Response(status=HTTP_OK)
        responses_json = [json.loads(resp.data).get("value", json.loads(resp.data)) for resp in responses]
        responses_norm = [resp if isinstance(resp, list) else [resp] for resp in responses_json]
        union_set = [{d.get("Id") for d in resp} for resp in responses_norm]
        union_response = set.union(*union_set)
        common_elements = [d for d in sum(responses_norm, []) if d.get("Id") in union_response]
        if app.config.get("expand", None) and request.args.get("$expand", None) in ["Files", "files"]:
            # If expand is enabled with -e and request contains &$expand
            for session in common_elements:
                files = json.loads(
                    process_files_request(
                        f'SessionID eq {session["SessionId"]}',
                        request.args,
                        catalog_data_files,
                    ).response[0],
                )
                files = files["value"] if "value" in files else [files]
                session.update({"Files": [file for file in files]})
            return Response(status=HTTP_OK, response=batch_response_odata_v4(common_elements), headers=request.args)
        else:
            return (
                Response(status=HTTP_OK, response=batch_response_odata_v4(common_elements))
                if common_elements
                else Response(status=HTTP_NOT_FOUND)
            )

    if app.config.get("expand", None) and request.args.get("$expand", None) in ["Files", "files"]:
        # If expand is enabled with -e and request contains &$expand
        raw_result = json.loads(
            process_session_request(request.args["$filter"], request.args, catalog_data).response[0],
        )
        session_response = raw_result["value"] if "value" in raw_result else [raw_result]
        session_response = [] if session_response in [[], [[]]] else session_response  # flatten empty if needed
        for session in session_response:
            files = json.loads(
                process_files_request(
                    f'SessionID eq {session["SessionId"]}',
                    request.args,
                    catalog_data_files,
                ).response[0],
            )
            files = files["value"] if "value" in files else [files]
            session.update({"Files": [file for file in files]})
        session_response = batch_response_odata_v4(session_response) if session_response else json.dumps([])
        return Response(status=HTTP_OK, response=session_response, headers=request.args)
    else:
        return process_session_request(request.args["$filter"], request.args, catalog_data)


def manage_int_querry(op, value, catalog_data, field, headers):
    """Docstring to be added."""
    try:
        value = int(value)
    except ValueError:
        return Response(status=HTTP_BAD_REQUEST)
    match op:
        case "eq":
            query_result = [product for product in catalog_data["Data"] if value == int(product[field])]
        case "lt":
            query_result = [product for product in catalog_data["Data"] if value > int(product[field])]
        case "gt":
            query_result = [product for product in catalog_data["Data"] if value < int(product[field])]
    return (
        Response(status=HTTP_OK, response=batch_response_odata_v4(query_result), headers=headers)
        if query_result
        else Response(status=HTTP_NOT_FOUND)
    )


def manage_bool_querry(op, value, catalog_data, field, headers):
    """Docstring to be added."""
    try:
        value = bool(value)
    except ValueError:
        return Response(status=HTTP_BAD_REQUEST)
    match op:
        case "eq":
            query_result = [product for product in catalog_data["Data"] if value == product[field]]
        case "lt":
            query_result = [product for product in catalog_data["Data"] if value < product[field]]
        case "gt":
            query_result = [product for product in catalog_data["Data"] if value > product[field]]
    return (
        Response(status=HTTP_OK, response=batch_response_odata_v4(query_result), headers=headers)
        if query_result
        else Response(status=HTTP_NOT_FOUND)
    )


def manage_satellite_sid_query(op, value, catalog_data, field, headers):
    """Docstring to be added."""
    match op:
        case "eq":
            query_result = [product for product in catalog_data["Data"] if value == product[field]]
        case "in":
            sat_sid_match = re.sub(r"[()]", "", value).split(", ")
            query_result = [
                [product for product in catalog_data["Data"] if product[field] == sat_sid.strip()]
                for sat_sid in sat_sid_match
            ]
            query_result = [product for sublist in query_result for product in sublist]
    return (
        Response(status=HTTP_OK, response=batch_response_odata_v4(query_result), headers=headers)
        if query_result
        # as per ICD response is HTTP_OK even if empty
        else Response(status=HTTP_OK, response=json.dumps([]))
    )


def manage_str_querry(op, value, catalog_data, field, headers):
    """Docstring to be added."""
    match op:
        case "eq":
            query_result = [product for product in catalog_data["Data"] if value == product[field]]
        case "in":
            query_result = [product for product in catalog_data["Data"] if value in product[field]]
    return (
        Response(status=HTTP_OK, response=batch_response_odata_v4(query_result), headers=headers)
        if query_result
        else Response(status=HTTP_NOT_FOUND)
    )


def manage_datetime_querry(op, value, catalog_data, field, headers):
    """Docstring to be added."""
    date = datetime.datetime.fromisoformat(value)
    match op:
        case "eq":
            resp_body = [
                product for product in catalog_data["Data"] if date == datetime.datetime.fromisoformat(product[field])
            ]
        case "gt":
            resp_body = [
                product for product in catalog_data["Data"] if date < datetime.datetime.fromisoformat(product[field])
            ]
        case "lt":
            resp_body = [
                product for product in catalog_data["Data"] if date > datetime.datetime.fromisoformat(product[field])
            ]
        case _:
            # If the operation is not recognized, return a 404 NOT FOUND response
            return Response(status=HTTP_NOT_FOUND)
    # Return the response with the processed results or a 404 NOT FOUND if no results are found
    return (
        Response(status=HTTP_OK, response=batch_response_odata_v4(resp_body), headers=headers)
        if resp_body
        else Response(status=HTTP_NOT_FOUND)
    )


SPJ_LUT = {
    "Id": manage_str_querry,
    "SessionId": manage_satellite_sid_query,
    "NumChannels": manage_int_querry,
    "PublicationDate": manage_datetime_querry,
    "Satellite": manage_satellite_sid_query,
    "StationUnitId": manage_str_querry,
    "DownlinkOrbit": manage_int_querry,
    "AcquisitionId": manage_str_querry,
    "AntennaId": manage_str_querry,
    "FronEndId": manage_str_querry,
    "Retransfer": manage_bool_querry,
    "AntennaStatusHTTP_OK": manage_bool_querry,
    "FrontEndStatusHTTP_OK": manage_bool_querry,
    "PlannedDataStart": manage_datetime_querry,
    "PlannedDataStop": manage_datetime_querry,
    "DownlinkStart": manage_datetime_querry,
    "DownlinkStop": manage_datetime_querry,
    "DownlinkStatusHTTP_OK": manage_bool_querry,
    "DeliveryPushHTTP_OK": manage_bool_querry,
    "NumChannels": manage_int_querry,
}


def process_session_request(request: str, headers: dict, catalog_data: dict) -> Response:
    """Docstring to be added."""
    # Normalize request (lower case / remove ')
    try:
        field, op, *value = map(
            lambda norm: norm.replace("'", ""),
            request.strip('"').split(" "),
        )
    except:
        return Response(status=HTTP_NOT_FOUND, response={})
    # field, op, *value = request.split(" ")
    value = " ".join(value)
    # return results or the 200HTTP_OK code is returned with an empty response (PSD)
    return (
        SPJ_LUT[field](op, value, catalog_data, field, headers) if field in SPJ_LUT else Response(status=HTTP_NOT_FOUND)
    )


# 3.4
@app.route("/Files", methods=["GET"])
@token_required
@additional_options
def query_files() -> Response | list[Any]:
    """Docstring to be added."""
    if not request.args:
        return Response(status=HTTP_BAD_REQUEST)

    if not any(
        [
            query_text in request.args["$filter"].split(" ")[0]
            for query_text in ["Id", "Orbit", "Name", "PublicationDate", "SessionID"]
        ],
    ):
        return Response(status=HTTP_BAD_REQUEST)
    catalog_path = app.config["configuration_path"] / "Catalogue/FileResponse.json"
    catalog_data = json.loads(open(catalog_path).read())

    accepted_operators = [" and ", " or ", " not "]
    if any(header in request.args["$filter"] for header in accepted_operators):
        pattern = r"(\S+ \S+ \S+) (\S+) (\S+ \S+ \S+)"
        groups = re.search(pattern, request.args["$filter"])
        if groups:
            first_request, operator, second_request = groups.group(1), groups.group(2), groups.group(3)
        # split and processes the requests
        first_response = process_files_request(first_request.replace('"', ""), request.args, catalog_data)
        second_response = process_files_request(second_request.replace('"', ""), request.args, catalog_data)
        # Load response data to a json dict
        try:
            first_response = json.loads(first_response.data).get("value", json.loads(first_response.data))
        except json.JSONDecodeError:
            first_response = []
        try:
            second_response = json.loads(second_response.data).get("value", json.loads(second_response.data))
        except json.JSONDecodeError:
            second_response = []
        # Normalize responses, must be a list, even with one element, for iterator
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
    return process_files_request(request.args["$filter"], request.args, catalog_data)


def process_files_request(request, headers, catalog_data):
    """Docstring to be added."""
    if "Name" in request:
        op, value = request.split("(")
        regex = re.search(r"(\w+)\((\w+), \'([\w_]+)\'\)", request)
        if regex:
            op = regex.group(1)
            filter_by = regex.group(2)
            filter_value = regex.group(3).replace("'", "")
        match op:
            case "contains":
                resp_body = [product for product in catalog_data["Data"] if filter_value in product[filter_by]]
            case "startswith":
                resp_body = [product for product in catalog_data["Data"] if product[filter_by].startswith(filter_value)]
            case "endswith":
                resp_body = [product for product in catalog_data["Data"] if product[filter_by].endswith(filter_value)]
        return (
            Response(status=HTTP_OK, response=batch_response_odata_v4(resp_body), headers=headers)
            if resp_body
            else Response(status=HTTP_NOT_FOUND)
        )
    elif "PublicationDate" in request:
        field, op, value = request.split(" ")
        date = datetime.datetime.fromisoformat(value)
        match op:
            case "eq":
                # map inside map, to be reviewed?
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
            Response(status=HTTP_OK, response=batch_response_odata_v4(resp_body), headers=headers)
            if resp_body
            else Response(status=HTTP_NOT_FOUND)
        )
    else:  # SessionId / Orbit
        request = request.replace('"', "")
        field, op, *value = request.split(" ")
        match op:
            case "eq":
                matching = [product for product in catalog_data["Data"] if value[0].strip("('),") == product[field]]
            case "in":
                matching = []
                for idx in value:
                    matching += [product for product in catalog_data["Data"] if idx.strip("('),") in product[field]]
        return (
            Response(response=batch_response_odata_v4(matching), status=HTTP_OK)
            if matching
            else Response(status=HTTP_NOT_FOUND)
        )


# 3.5
# v1.0.0 takes id from route GET and filters FPJ (json outputs of file query) in order to download a file
# Is possible / how to download multiple files
@app.route("/Files(<Id>)/$value", methods=["GET"])
@token_required
def download_file(Id) -> Response:  # noqa: N803
    """Docstring to be added."""
    catalog_path = app.config["configuration_path"] / "Catalogue/FileResponse.json"
    catalog_data = json.loads(open(catalog_path).read())

    files = [product for product in catalog_data["Data"] if Id.replace("'", "") == product["Id"]]
    return (
        send_file("config/S3Mock/" + files[0]["Name"])
        if len(files) == 1
        else Response(status="404 None/Multiple files found")
    )
    # if files:
    #    return send_file("S3Mock/" + files[0]["Name"]) if len(files) == 1 else Response(status="200 not implemented")
    # else:
    #    return Response(status=404)


# 3.6
@app.route("/Sessions(<Id>)", methods=["GET"])
def quality_info(Id) -> Response | list[Any]:  # noqa: N803
    """Docstring to be added."""
    if "expand" in request.args:
        if request.args["expand"] == "qualityInfo":
            catalog_path = app.config["configuration_path"] / "Catalogue/QualityInfoResponse.json"
            catalog_data = json.loads(open(catalog_path).read())
            QIData = map(  # noqa: N806
                json.dumps,
                [QIData for QIData in catalog_data["Data"] if Id.replace("'", "") == QIData["Id"]],
            )
            return Response(status=HTTP_OK, response=QIData)
    return Response(status="405 Request denied, need qualityInfo")


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
    response = {"access_token": config_auth["token"], "token_type": "Bearer", "expires_in": 3600}
    logger.info("Grant type validated. Token sent back")
    return Response(status=HTTP_OK, response=json.dumps(response))

def create_cadip_app():
    """Docstring to be added."""
    # Used to pass instance to conftest
    app.config["configuration_path"] = pathlib.Path(__file__).parent.resolve() / "config"
    app.config["expand"] = True
    return app


if __name__ == "__main__":
    """Docstring to be added."""
    parser = argparse.ArgumentParser(description="Starts the CADIP server mockup ")

    default_config_path = pathlib.Path(__file__).parent.resolve() / "config"
    parser.add_argument("-p", "--port", type=int, required=False, default=5000, help="Port to use")
    parser.add_argument("-H", "--host", type=str, required=False, default="127.0.0.1", help="Host to use")
    parser.add_argument("-c", "--config", type=str, required=False, default=default_config_path)

    args = parser.parse_args()
    configuration_path = pathlib.Path(args.config)
    if is_expanded := str(os.getenv("CADIP_SESSION_EXPAND", True)).lower() in ("true", "1", "t", "y", "yes"):
        print("Starting CADIP server mockup with expanded sessions support.")
    app.config["expand"] = is_expanded
    # configuration_path.iterdir() / signature in str(x)
    if default_config_path is not configuration_path:
        # define config folder mandatory structure
        config_signature = [
            "auth.json",
            "Catalogue/FileResponse.json",
            "Catalogue/QualityInfoResponse.json",
            "Catalogue/SPJ.json",
        ]
        if not all((configuration_path / file_name).exists() for file_name in config_signature):
            # use default config if given structure doesn't match
            configuration_path = default_config_path
            print("Using default config")
    app.config["configuration_path"] = configuration_path
    app.run(debug=True, host=args.host, port=args.port)  # local
    # app.run(debug=True, host="0.0.0.0", port=8443) # loopback for LAN
