"""Docstring to be added."""
import argparse
import datetime
import json
import pathlib
import re
from functools import wraps
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


def additional_options(func):
    """Docstring to be added."""

    # This method is a wrapper that check if endpoints have some display options activated.
    # Endpoint function is called inside wrapper and output is sorted or sliced according to request arguments.
    @wraps(func)
    def wrapper(*args, **kwargs):
        accepted_display_options = ["$orderBy", "$top", "$skip", "$count"]
        response = func(*args, **kwargs)
        display_headers = response.headers

        def parse_response_data():
            try:
                return json.loads(response.data)
            except json.JSONDecodeError:
                return None

        def sort_responses_by_field(json_data, field, reverse=False):
            if "responses" in json_data:
                return {"responses": sorted(json_data["responses"], key=lambda x: x[field], reverse=reverse)}
            return json_data

        if any(header in accepted_display_options for header in display_headers.keys()):
            match list(set(accepted_display_options) & set(display_headers.keys()))[0]:
                case "$orderBy":
                    field, ordering_type = display_headers["$orderBy"].split(" ")
                    json_data = parse_response_data()
                    return sort_responses_by_field(json_data, field, reverse=(ordering_type == "desc"))
                case "$top":
                    top_value = int(display_headers["$top"])
                    json_data = parse_response_data()
                    return (
                        batch_response_odata_v4(json_data["responses"][:top_value])
                        if "responses" in json_data
                        else json_data  # No need for slicing since there is only one response.
                    )
                case "$skip":
                    skip_value = int(display_headers.get("$skip", 0))
                    json_data = parse_response_data()
                    return (
                        batch_response_odata_v4(json_data["responses"][skip_value:])
                        if "responses" in json_data
                        else json_data  # No need for slicing since there is only one response.
                    )
                case "$count":
                    json_data = parse_response_data()
                    if "responses" in json_data:
                        return Response(status=OK, response=str(len(json_data["responses"])))
                    return Response(status=OK, response=str(len(json_data)))
        return response

    return wrapper


def batch_response_odata_v4(resp_body: list | map) -> Any:
    """Docstring to be added."""
    unpacked = list(resp_body) if not isinstance(resp_body, list) else resp_body
    return json.dumps(dict(responses=unpacked)) if len(unpacked) > 1 else json.dumps(unpacked[0])


@auth.verify_password
def verify_password(username, password) -> bool:
    """Docstring to be added."""
    auth_path = app.config["configuration_path"] / "auth.json"
    users = json.loads(open(auth_path).read())
    if username in users.keys():
        return bcrypt.check_password_hash(users.get(username), password)
    return False


@app.route("/", methods=["GET", "POST"])
@auth.login_required
def hello():
    """Docstring to be added."""
    # Used only for auth, if reached here, return OK.
    return Response(status=OK)


# 3.3 (PSD)
@app.route("/Sessions", methods=["GET"])
@auth.login_required
@additional_options
def query_session() -> Response | list[Any]:
    """Docstring to be added."""
    if not request.args:
        return Response(status=BAD_REQUEST)
        # return Response('Bad Request', Response.status_code(400), None)
    # Check requested values, filter type can only be json keys
    if not any(
            [
                query_text == request.args["$filter"].strip('"').split(" ")[0]
                for query_text in SPJ_LUT.keys()
            ],
    ):
        return Response(status=BAD_REQUEST)
    # Proceed to process request
    catalog_path = app.config["configuration_path"] / "Catalogue/SPJ.json"
    catalog_data = json.loads(open(catalog_path).read())
    # all operators with all possible spacing combinations
    # accepted_operators = [" and ", " or ", " in ", " not ", "and ", " or ", " in ", " not", "and", "or", "in", "not"]
    # split_request = [req.strip() for req in request.args["$filter"].split('and')]
    # Handle multiple "AND" / "OR" operands
    if len(split_request := [req.strip() for req in request.args["$filter"].split('and')]) in [2, 3]:
        responses = [process_session_request(req, request.args, catalog_data) for req in split_request]
        if not all(resp.status_code == 200 for resp in responses):
            return Response(status=NOT_FOUND)
        try:
            responses_json = [json.loads(resp.data).get("responses", json.loads(resp.data)) for resp in responses]
            responses_norm = [resp if isinstance(resp, list) else [resp] for resp in responses_json]
            resp_set = [{d.get("Id") for d in resp} for resp in responses_norm]
            common_response = set.intersection(*resp_set)
            common_elements = [d for d in responses_norm[0] if d.get("Id") in common_response]
            return Response(status=OK, response=batch_response_odata_v4(common_elements)) if common_elements else Response(
                status=NOT_FOUND)
        except json.JSONDecodeError:  # if a response is empty, whole querry is empty
            return Response(status=NOT_FOUND)
    elif len(split_request := [req.strip() for req in request.args["$filter"].split('or')]) in [2, 3]:
        # add test when a response is empty, and other not.
        responses = [process_session_request(req, request.args, catalog_data) for req in split_request]
        responses_json = [json.loads(resp.data).get("responses", json.loads(resp.data)) for resp in responses]
        responses_norm = [resp if isinstance(resp, list) else [resp] for resp in responses_json]
        union_set = [{d.get("Id") for d in resp} for resp in responses_norm]
        union_response = set.union(*union_set)
        common_elements = [d for d in sum(responses_norm, []) if d.get("Id") in union_response]
        return Response(status=OK, response=batch_response_odata_v4(common_elements)) if common_elements else Response(
                status=NOT_FOUND)

    return process_session_request(request.args["$filter"], request.args, catalog_data)


def manage_int_querry(op, value, catalog_data, field, headers):
    try:
        value = int(value)
    except ValueError:
        return Response(status=BAD_REQUEST)
    query_result = [product for product in catalog_data["Data"] if value == product[field]]
    return (
        Response(status=OK, response=batch_response_odata_v4(query_result), headers=headers)
        if query_result
        else Response(status=NOT_FOUND)
    )


def manage_bool_querry(op, value, catalog_data, field, headers):
    try:
        value = bool(value)
    except ValueError:
        return Response(status=BAD_REQUEST)
    match op:
        case "eq":
            query_result = [product for product in catalog_data["Data"] if value == product[field]]
        case "lt":
            query_result = [product for product in catalog_data["Data"] if value < product[field]]
        case "gt":
            query_result = [product for product in catalog_data["Data"] if value > product[field]]
    return (
        Response(status=OK, response=batch_response_odata_v4(query_result), headers=headers)
        if query_result
        else Response(status=NOT_FOUND)
    )


def manage_satellite_sid_query(op, value, catalog_data, field, headers):
    match op:
        case "eq":
            query_result = [product for product in catalog_data["Data"] if value == product[field]]
        case "in":
            sat_sid_match = re.sub(r'[()]', '', value).split(', ')
            query_result = [[product for product in catalog_data["Data"] if product[field] == sat_sid.strip()] for
                            sat_sid in sat_sid_match]
            query_result = query_result[0] + query_result[1]
    # import pdb
    # pdb.set_trace()
    return (
        Response(status=OK, response=batch_response_odata_v4(query_result), headers=headers)
        if query_result
        # as per ICD response is OK even if empty
        else Response(status=OK)
    )

def manage_str_querry(op, value, catalog_data, field, headers):
    match op:
        case "eq":
            query_result = [product for product in catalog_data["Data"] if value == product[field]]
        case "in":
            query_result = [product for product in catalog_data["Data"] if value in product[field]]
    return (
        Response(status=OK, response=batch_response_odata_v4(query_result), headers=headers)
        if query_result
        else Response(status=NOT_FOUND)
    )


def manage_datetime_querry(op, value, catalog_data, field, headers):
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
    # Return the response with the processed results or a 404 NOT FOUND if no results are found
    return (
        Response(status=OK, response=batch_response_odata_v4(resp_body), headers=headers)
        if resp_body
        else Response(status=NOT_FOUND)
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
    "AntennaStatusOK": manage_bool_querry,
    "FrontEndStatusOK": manage_bool_querry,
    "PlannedDataStart": manage_datetime_querry,
    "PlannedDataStop": manage_datetime_querry,
    "DownlinkStart": manage_datetime_querry,
    "DownlinkStop": manage_datetime_querry,
    "DownlinkStatusOK": manage_bool_querry,
    "DeliveryPushOK": manage_bool_querry,
    "NumChannels": manage_int_querry,
}


def process_session_request(request: str, headers: dict, catalog_data: dict) -> Response:
    """Docstring to be added."""
    # Normalize request (lower case / remove ')
    field, op, *value = map(
        lambda norm: norm.replace("'", ""),
        request.strip('"').split(" "),
    )
    # field, op, *value = request.split(" ")
    value = " ".join(value)
    # return results or the 200OK code is returned with an empty response (PSD)
    return SPJ_LUT[field](op, value, catalog_data, field, headers) if field in SPJ_LUT else Response(status=NOT_FOUND)


# 3.4
@app.route("/Files", methods=["GET"])
@auth.login_required
@additional_options
def query_files() -> Response | list[Any]:
    """Docstring to be added."""
    if not request.args:
        return Response(status=BAD_REQUEST)

    if not any(
            [
                query_text in request.args["$filter"].split(" ")[0]
                for query_text in ["Id", "Orbit", "Name", "PublicationDate"]
            ],
    ):
        return Response(status=BAD_REQUEST)
    catalog_path = app.config["configuration_path"] / "Catalogue/FileResponse.json"
    catalog_data = json.loads(open(catalog_path).read())

    accepted_operators = [" and ", " or ", " in ", " not "]
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
            first_response = json.loads(first_response.data).get("responses", json.loads(first_response.data))
        except json.JSONDecodeError:
            first_response = []
        try:
            second_response = json.loads(second_response.data).get("responses", json.loads(second_response.data))
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
                    return Response(status=OK, response=batch_response_odata_v4(common_elements), headers=request.args)
                return Response(status=OK, response=json.dumps([]))
            case "or":  # union
                union_set = fresp_set.union(sresp_set)
                union_elements = [d for d in first_response + second_response if d.get("Id") in union_set]
                return Response(status=OK, response=batch_response_odata_v4(union_elements), headers=request.args)

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
            Response(status=OK, response=batch_response_odata_v4(resp_body), headers=headers)
            if resp_body
            else Response(status=NOT_FOUND)
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
            Response(status=OK, response=batch_response_odata_v4(resp_body), headers=headers)
            if resp_body
            else Response(status=NOT_FOUND)
        )
    else:  # SessionId / Orbit
        field, op, value = request.split(" ")
        matching = map(
            json.dumps,
            [product for product in catalog_data["Data"] if value == product[field]],
        )
        return Response(response=matching, status=OK) if matching else Response(status=NOT_FOUND)


# 3.5
# v1.0.0 takes id from route GET and filters FPJ (json outputs of file query) in order to download a file
# Is possible / how to download multiple files
@app.route("/Files(<Id>)/$value", methods=["GET"])
@auth.login_required
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
            return Response(status=OK, response=QIData)
    return Response(status="405 Request denied, need qualityInfo")


def create_cadip_app():
    """Docstring to be added."""
    # Used to pass instance to conftest
    app.config["configuration_path"] = pathlib.Path(__file__).parent.resolve() / "config"
    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Starts the CADIP server mockup ")

    default_config_path = pathlib.Path(__file__).parent.resolve() / "config"
    parser.add_argument("-p", "--port", type=int, required=False, default=5000, help="Port to use")
    parser.add_argument("-H", "--host", type=str, required=False, default="127.0.0.1", help="Host to use")
    parser.add_argument("-c", "--config", type=str, required=False, default=default_config_path)

    args = parser.parse_args()
    configuration_path = pathlib.Path(args.config)
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
