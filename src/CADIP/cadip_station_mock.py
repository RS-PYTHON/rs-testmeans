"""Docstring to be added."""
import argparse
import asyncio
import datetime
import json
import logging
import os
import re
import sys
from functools import wraps
from typing import Any

from flask import Flask, Response, render_template, request, send_file
from flask_bcrypt import Bcrypt
from flask_httpauth import HTTPBasicAuth
from prefect import flow

sys.path.insert(1, "../rs-server/src")

from s3_storage_handler import (  # type: ignore # noqa
    files_to_be_downloaded,  # type: ignore # noqa
    get_secrets,  # type: ignore # noqa
    prefect_get_keys_from_s3,  # type: ignore # noqa
)

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
                        else json_data
                    )
                case "$skip":
                    skip_value = int(display_headers.get("$skip", 0))
                    json_data = parse_response_data()
                    return (
                        batch_response_odata_v4(json_data["responses"][skip_value:])
                        if "responses" in json_data
                        else json_data
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
    users = json.loads(open("src/CADIP/auth.json").read())
    if username in users.keys():
        return bcrypt.check_password_hash(users.get(username), password)
    return False


@app.route("/", methods=["GET", "POST"])
@auth.login_required
def hello():
    """Docstring to be added."""
    return render_template("home.html")


# 3.3 (PSD)
@app.route("/Sessions", methods=["GET"])
@auth.login_required
@additional_options
def query_session() -> Response | list[Any]:
    """Docstring to be added."""
    # Additional output options to be added: orderby, top, skip, count.
    # Aditional operators to be added, and, or, not, in
    # Request with publicationDate gt / lt are not implemented yet
    if not request.args:
        return Response(status=BAD_REQUEST)
        # return Response('Bad Request', Response.status_code(400), None)
    # Check requested values, filter type can only be json keys
    if not any(
        [
            query_text == request.args["$filter"].split(" ")[0]
            for query_text in ["Satellite", "DownlinkOrbit", "PublicationDate"]
        ],
    ):
        return Response(status=BAD_REQUEST)
    # Proceed to procces request
    catalog_data = json.loads(open("src/CADIP/Catalogue/SPJ.json").read())
    accepted_operators = [" and ", " or ", " in ", " not "]
    if any(header in request.args["$filter"] for header in accepted_operators):
        # If request match the pattern (field, op, value OPERATOR field, op, value)
        pattern = r"(\S+ \S+ \S+) (\S+) (\S+ \S+ \S+)"
        groups = re.search(pattern, request.args["$filter"])
        if groups:
            first_request, operator, second_request = groups.group(1), groups.group(2), groups.group(3)
        # split and processes the requests
        first_response = process_session_request(first_request, request.args, catalog_data)
        second_response = process_session_request(second_request, request.args, catalog_data)
        # Load response data to a json dict
        first_response = json.loads(first_response.data).get("responses", json.loads(first_response.data))
        second_response = json.loads(second_response.data).get("responses", json.loads(second_response.data))
        # Normalize responses, must be a list, even with one element, for iterator
        # Maybe use functools here, tbu
        if not isinstance(first_response, list):
            first_response = [first_response]
        if not isinstance(second_response, list):
            second_response = [second_response]
        # Convert to a set, elements unique by ID
        fresp_set = {d.get("Id") for d in first_response}
        sresp_set = {d.get("Id") for d in second_response}
        match operator:
            case "and":  # intersection
                common_response = fresp_set.intersection(sresp_set)
                common_elements = [d for d in first_response if d.get("Id") in common_response]
                return Response(status=OK, response=batch_response_odata_v4(common_elements))
            case "or":  # union
                union_set = fresp_set.union(sresp_set)
                union_elements = [d for d in first_response + second_response if d.get("Id") in union_set]
                return Response(status=OK, response=batch_response_odata_v4(union_elements))
            case "in":  # not in icd yet
                pass
            case "not":  # not in icd yet
                pass

    return process_session_request(request.args["$filter"], request.args, catalog_data)


def process_session_request(request: str, headers: dict, catalog_data: dict) -> Response:
    """Docstring to be added."""
    # Normalize request (lower case / remove ')
    field, op, value = map(
        lambda norm: norm.replace("'", ""),
        request.split(" "),
    )
    # return results or the 200OK code is returned with an empty response (PSD)
    if field == "PublicationDate":
        # year-month-day
        date_placeholder = datetime.datetime(2014, 1, 1, 12, 0, tzinfo=datetime.timezone.utc)
        date = date_placeholder.replace(*map(int, value.split("-")))  # type: ignore
        # Maybe should use LUT for operations
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
    else:
        # For fields other than "PublicationDate", perform a substring match on the specified value
        query_result = [product for product in catalog_data["Data"] if value in product[field]]
        # Return the response with the processed results or a 200 OK response if no results are found
        return (
            Response(status=OK, response=batch_response_odata_v4(query_result), headers=headers)
            if query_result
            else Response(status=OK)
        )


# 3.4
@app.route("/Files", methods=["GET"])
@auth.login_required
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

    catalog_data = json.loads(open("src/CADIP/Catalogue/FileResponse.json").read())
    if "Name" in request.args["$filter"]:
        op, value = request.args["$filter"].split("(")
        regex = re.search("('.*?', '.*?')", value)
        if regex:
            filter_by, filter_value = regex.group(0).replace("'", "").split(", ")
        match op:
            case "contains":
                resp_body = map(
                    json.dumps,
                    [product for product in catalog_data["Data"] if filter_value in product[filter_by]],
                )
            case "startswith":
                resp_body = map(
                    json.dumps,
                    [product for product in catalog_data["Data"] if product[filter_by].startswith(filter_value)],
                )
            case "endswith":
                resp_body = map(
                    json.dumps,
                    [product for product in catalog_data["Data"] if product[filter_by].endswith(filter_value)],
                )
        return (
            Response(status=OK, response=batch_response_odata_v4(resp_body))
            if resp_body
            else Response(status=NOT_FOUND)
        )
    elif "PublicationDate" in request.args["$filter"]:
        field, op, value = request.args["$filter"].split(" ")
        date_placeholder = datetime.datetime(2014, 1, 1, 12, 0, tzinfo=datetime.timezone.utc)
        date = date_placeholder.replace(*map(int, value.split("-")))  # type: ignore
        match op:
            case "eq":
                # map inside map, to be reviewed?
                resp_body = map(
                    json.dumps,
                    [
                        product
                        for product in catalog_data["Data"]
                        if date == datetime.datetime.fromisoformat(product[field])
                    ],
                )
            case "gt":
                resp_body = map(
                    json.dumps,
                    [
                        product
                        for product in catalog_data["Data"]
                        if date < datetime.datetime.fromisoformat(product[field])
                    ],
                )
            case "lt":
                resp_body = map(
                    json.dumps,
                    [
                        product
                        for product in catalog_data["Data"]
                        if date > datetime.datetime.fromisoformat(product[field])
                    ],
                )
        return (
            Response(status=OK, response=batch_response_odata_v4(resp_body))
            if resp_body
            else Response(status=NOT_FOUND)
        )
    else:  # SessionId / Orbit
        field, op, value = request.args["$filter"].split(" ")
        matching = map(
            json.dumps,
            [product for product in catalog_data["Data"] if value == product[field]],
        )
        return Response(response=matching, status=OK) if matching else Response(status=NOT_FOUND)


# 3.5
# Not sure if download should be requested only with ID or with a json request?
# v1.0.0 takes id from route GET and filters FPJ (json outputs of file query) in order to download a file
# Is possible / how to download multiple files
@app.route("/Files(<Id>)/$value", methods=["GET"])
@auth.login_required
def download_file(Id) -> Response:  # noqa: N803
    """Docstring to be added."""
    catalog_data = json.loads(open("src/CADIP/Catalogue/FileResponse.json").read())

    files = [product for product in catalog_data["Data"] if Id.replace("'", "") == product["Id"]]
    return (
        send_file("S3Mock/" + files[0]["Name"]) if len(files) == 1 else Response(status="404 None/Multiple files found")
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
            catalog_data = json.loads(open("src/CADIP/Catalogue/QualityInfoResponse.json").read())
            QIData = map(  # noqa: N806
                json.dumps,
                [QIData for QIData in catalog_data["Data"] if Id.replace("'", "") == QIData["Id"]],
            )
            return Response(status=OK, response=QIData)
    return Response(status="405 Request denied, need qualityInfo")


@app.route("/Files(<Id>)/$S3OS", methods=["GET"])
# @auth.login_required # Not yet
def s3_download_file(Id) -> Response:  # noqa: N803 # can't be lowercase, must mach endpoint & ICD
    """Docstring to be added."""
    catalog_data = json.loads(open("src/CADIP/Catalogue/S3FileResp.json").read())
    bucket = "rs-addon-input"
    path = "S3Download"

    logger = logging.getLogger()

    s3_file_path = [resp["S3Path"] for resp in catalog_data["Data"] if Id == resp["Id"]]

    list_per_task = files_to_be_downloaded(bucket, s3_file_path, logger)

    @flow
    async def download_s3():
        task1 = asyncio.create_task(prefect_get_keys_from_s3(list_per_task, bucket, path, 1))
        await task1

    asyncio.run(download_s3())
    return send_file(os.path.join(os.path.abspath(path), s3_file_path[0].split("/")[-1]))
    # os.remove(os.path.join(path, s3_file_path[0].split('/')[-1]))
    # return '200'


def create_cadip_app():
    """Docstring to be added."""
    # Used to pass instance to conftest
    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Starts the CADIP server mockup ",
    )

    parser.add_argument("-s", "--secret-file", type=str, required=False, help="File with the secrets")
    parser.add_argument("-p", "--port", type=int, required=False, default=5000, help="Port to use")
    parser.add_argument("-H", "--host", type=str, required=False, default="127.0.0.1", help="Host to use")

    args = parser.parse_args()
    if args.secret_file:
        secrets = {
            "s3endpoint": "https://oss.eu-west-0.prod-cloud-ocb.orange-business.com",
            "accesskey": None,
            "secretkey": None,
        }
        if not get_secrets(secrets, args.secret_file):
            print("Could not get the secrets")
            sys.exit(-1)

        os.environ["S3_ENDPOINT"] = secrets["s3endpoint"] if secrets["s3endpoint"] is not None else ""
        os.environ["S3_ACCESS_KEY_ID"] = secrets["accesskey"] if secrets["accesskey"] is not None else ""
        os.environ["S3_SECRET_ACCESS_KEY"] = secrets["secretkey"] if secrets["secretkey"] is not None else ""
        os.environ["S3_REGION"] = "sbg"

    app.run(debug=True, host=args.host, port=args.port)  # local
    # app.run(debug=True, host="0.0.0.0", port=8443) # loopback for LAN
