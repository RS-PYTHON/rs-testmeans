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
import random
import string
from flask import Flask, Response, request, send_file, after_this_request
from flask_bcrypt import Bcrypt
from flask_httpauth import HTTPBasicAuth
from http import HTTPStatus
from common.common_routes import (
    token_required,
    register_token_route, 
)
import dotenv
from common.s3_handler import S3StorageHandler, GetKeysFromS3Config
import os

PATH_TO_CONFIG = pathlib.Path(__file__).parent.resolve() / "config"


logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
app = Flask(__name__)
bcrypt = Bcrypt(app)
auth = HTTPBasicAuth()

aditional_operators = [" and ", " or ", " in ", " not "]

#Register route (common to CADIP AND ADGS) to register a new token
register_token_route(app)

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


@app.route("/health", methods=["GET"])
def ready_live_status():
    """Docstring to be added."""
    return Response(status=HTTPStatus.OK)


@app.route("/", methods=["GET", "POST"])
@token_required
def hello():
    """Docstring to be added."""
    return Response(status=HTTPStatus.OK)


def process_products_request(request, headers) -> Response:
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
            Response(status=HTTPStatus.OK, response=prepare_response_odata_v4(resp_body), headers=headers)
            if resp_body
            else Response(status=HTTPStatus.NOT_FOUND)
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
                return Response(status=HTTPStatus.NOT_FOUND)
        return (
            Response(status=HTTPStatus.OK, response=prepare_response_odata_v4(resp_body), headers=headers)
            if resp_body
            else Response(status=HTTPStatus.OK, response=json.dumps({"value": []}))
        )
    elif "ContentDate" in request:
        pattern = r"Start (\S+) (\S+) and ContentDate/End (\S+) (\S+)"
        if regex_match := re.search(pattern, request):
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
                Response(status=HTTPStatus.OK, response=prepare_response_odata_v4(resp_body), headers=headers)
                if resp_body
                else Response(status=HTTPStatus.OK, response=json.dumps({"value": []}))
            )
        else:
            field, op, value = request.split(" ")
            value = value.strip("()")
            date = datetime.datetime.fromisoformat(value)
            date_field = "Start" if "Start" in field else "End"

            # Define a comparison map to avoid repetitive code
            comparison_ops = {
                "eq": lambda d: d == date,
                "lt": lambda d: d < date,
                "gt": lambda d: d > date,
                "lte": lambda d: d <= date,
                "gte": lambda d: d >= date,
            }

            # Parse and filter in one comprehension
            if op in comparison_ops:
                resp_body = [
                    product
                    for product in catalog_data["Data"]
                    if comparison_ops[op](
                        datetime.datetime.fromisoformat(product["ContentDate"][date_field])
                    )
                ]
            else:
                resp_body = []
                
            return (
                Response(status=HTTPStatus.OK, response=prepare_response_odata_v4(resp_body), headers=headers)
                if resp_body
                else Response(status=HTTPStatus.OK, response=json.dumps({"value": []}))
            )
    elif "Attributes" in request.args["$filter"]:
        pass  # WIP
    else:
        return Response(status=HTTPStatus.BAD_REQUEST)

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


def is_operator_next(expression: str, position: int) -> str:
    """Check in the expression if there is an operator from the list at the given position
    and returns it if so.
    """
    for operator in aditional_operators:
        if position<len(expression)-len(operator) and expression[position:position+len(operator)] == operator:
            return operator
    return ""


def split_composite_filter(filter_to_split: str) -> tuple[list[str], list[str]]:
    """Function to split a filter made of two or more filters separated with an operator.
    The split is done at the first level of the filter only.
    
    Examples:
      - used on "(field1 or condition1) and (field2 or condition2)" it will return
        ["field1 or condition1", "field2 or condition2"] with operators = ["and"]
      - used on "field1 or condition1" it will return ["field1", "condition1"] with operators = ["or"]

    Note that if the input filter is like "(field1 and condition1)" the parenthesis will be removed and
    it will be considered as "field1 and condition1", but if it's like "SomeInfo(field1 and condition1)"
    then it won't be considered as a composite filter and won't be splitted.
    """
    splitted_filter: list[str] = []
    current = []
    operators = []
    depth = 0
    i = 0

    # Remove parenthesis if useless (ex: "(ex1 and ex2)" but not "(ex1) and (ex2)")
    if re.fullmatch(r'\([^()]*\)', filter_to_split.strip()):
        filter_to_split = filter_to_split.removeprefix("(")
        filter_to_split = filter_to_split.removesuffix(")")

    # Split filter at depth 0 based on operators (anything outside parenthesis basically)
    while i < len(filter_to_split):
        if filter_to_split[i] == '(':
            depth += 1
            current.append(filter_to_split[i])
            i += 1
        elif filter_to_split[i] == ')':
            depth -= 1
            current.append(filter_to_split[i])
            i += 1
        elif depth == 0 and (operator := is_operator_next(filter_to_split, i)):
            splitted_filter.append(''.join(current).strip())
            current = []
            operators.append(operator.strip())
            i += len(operator)
        else:
            current.append(filter_to_split[i])
            i += 1

    if current:
        splitted_filter.append(''.join(current).strip())

    # Return subfilters and operators found
    return splitted_filter, operators


def process_filter(request, input_filter: str) -> Response:
    """Recursive function to go through any filter (composite or not) and return
    the result of the full filter.
    """
    # Split the filter
    splitted_filters, operators = split_composite_filter(input_filter)

    # If there is only one filter, apply it and gather results
    if len(splitted_filters)==1:
        end_filter = splitted_filters[0]
        if "Attributes" in end_filter or "OData.CSC" in end_filter:
            return process_attributes_search(end_filter, request.args)
        return process_products_request(str(end_filter), request.args)

    # If there is more than one filter, repeat operation on each one and combine its
    # results with the ones of the previous one using the correct operator
    else:
        i=1
        final_results = process_filter(request, splitted_filters[0])
        while i < len(splitted_filters):
            current_filter_results = process_filter(request, splitted_filters[i])
            final_results = process_common_elements(final_results, current_filter_results, operators[i-1])
            return final_results


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
    
def process_attributes_search(query, headers) -> Response:
    # Don;t touch this, it just works
    results = process_query(query)
    if len(results) == 2:
        return process_individual_query_part(process_query(query), headers)
    elif len(results) == 4:
        part1 = process_individual_query_part(process_query(query)[:2], headers)
        part2 = process_individual_query_part(process_query(query)[2:], headers)
        return Response(status=HTTPStatus.OK, response=prepare_response_odata_v4(process_response(part1, part2)), headers=headers)

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
    return Response(status=HTTPStatus.OK, response=prepare_response_odata_v4(resp if resp else []), headers=headers)

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
                    status=HTTPStatus.OK,
                    response=prepare_response_odata_v4(common_elements),
                    headers=request.args,
                )
            return Response(status=HTTPStatus.OK, response=json.dumps({"value": []}))
        case "or":  # union
            union_set = fresp_set.union(sresp_set)
            union_elements = [d for d in first_response + second_response if d.get("Id") in union_set]
            return Response(
                status=HTTPStatus.OK,
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
        return Response(status=HTTPStatus.OK, response=prepare_response_odata_v4(catalog_data['Data']), headers=request.args)
        # Handle parantheses
    if not re.search(r"\(([^()]*\sor\s[^()]*)\)", request.args["$filter"]):
        if not any(
            [query_text in request.args["$filter"].split(" ")[0] for query_text in ["Name", "PublicationDate", "Attributes", "ContentDate/Start", "ContentDate/End"]],
        ):
            return Response(status=HTTPStatus.BAD_REQUEST)

    return process_filter(request, request.args['$filter'])


@app.route("/Products(<Id>)/$value", methods=["GET"])
@token_required
def download_file(Id) -> Response:  # noqa: N803 # Must match endpoint arg
    """Docstring to be added."""
    catalog_path = app.config["configuration_path"] / "Catalog/GETFileResponse.json"
    catalog_data = json.loads(open(catalog_path).read())

    files = [product for product in catalog_data["Data"] if Id.replace("'", "") == product["Id"]]
    if len(files) != 1:
        return Response(status="404 None/Multiple files found")
    
    if len(files) == 1:
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
                    return Response(status=HTTPStatus.BAD_REQUEST, response="You must have a s3cmd config file under '~/.s3cfg'")
                handler = S3StorageHandler(
                    s3_credentials["access_key"],
                    s3_credentials["secret_key"],
                    s3_credentials["host_bucket"],
                    s3_credentials["bucket_location"],  # "sbg",
                )
            parts = file_info["S3_path"].replace("s3://", "").split("/", 1)
            handler.get_keys_from_s3(GetKeysFromS3Config([parts[1]], parts[0], "/tmp/auxip"))
            file_path = f"/tmp/auxip/{file_info['Name']}"
            @after_this_request
            def remove_file(response):
                try:
                    os.remove(file_path)
                except Exception as e:
                    app.logger.error(f"Failed to delete {file_path}: {e}")
                return response
        # Send bytes of gzip files in order to avoid auto-decompress feature from application/gzip headers
        if any(gzip_extension in files[0]["Name"] for gzip_extension in [".TGZ", ".gz", ".zip", ".tar"]):
            import io

            fpath = app.config["configuration_path"] / "Storage" / files[0]["Name"]
            send_args = io.BytesIO(open(fpath if "S3_path" not in file_info else file_path, "rb").read())
            return send_file(send_args, download_name=files[0]["Name"], as_attachment=True)
        else:
            # Nominal case.
            send_args = f'config/Storage/{files[0]["Name"]}'
            return send_file(send_args)

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
