"""Docstring to be added."""
import asyncio
import datetime
import json
import re
import sys
from functools import wraps
from typing import Any

from flask import Flask, Response, render_template, request, send_file
from flask_bcrypt import Bcrypt
from flask_httpauth import HTTPBasicAuth
from prefect import flow

app = Flask(__name__)
bcrypt = Bcrypt(app)
auth = HTTPBasicAuth()

OK = 200
BAD_REQUEST = 400
UNAUTHORIZED = 401
NOT_FOUND = 404


def additional_options(func):
    """Docstring to be added."""

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
def querry_session() -> Response | list[Any]:
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
            querry_text == request.args["$filter"].split(" ")[0]
            for querry_text in ["Satellite", "DownlinkOrbit", "PublicationDate"]
        ],
    ):
        return Response(status=BAD_REQUEST)

    # Normalize request (lower case / remove ')
    field, op, value = map(
        lambda norm: norm.replace("'", ""),
        request.args["$filter"].split(" "),
    )
    catalog_data = json.loads(open("src/CADIP/Catalogue/SPJ.json").read())

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
                return Response(status=NOT_FOUND)
        return (
            Response(status=OK, response=batch_response_odata_v4(resp_body), headers=request.args)
            if resp_body
            else Response(status=NOT_FOUND)
        )
    else:
        querry_result = [product for product in catalog_data["Data"] if value in product[field]]
        return (
            Response(status=OK, response=batch_response_odata_v4(querry_result), headers=request.args)
            if querry_result
            else Response(status=OK)
        )


# 3.4
@app.route("/Files", methods=["GET"])
@auth.login_required
def querry_files() -> Response | list[Any]:
    """Docstring to be added."""
    if not request.args:
        return Response(status=BAD_REQUEST)

    if not any(
        [
            querry_text in request.args["$filter"].split(" ")[0]
            for querry_text in ["Id", "Orbit", "Name", "PublicationDate"]
        ],
    ):
        return Response(status=BAD_REQUEST)

    catalog_data = json.loads(open("src/CADIP/Catalogue/FileResponse.json").read())
    if "Name" in request.args["$filter"]:
        op, value = request.args["$filter"].split("(")
        filter_by, filter_value = (
            re.search("('.*?', '.*?')", value).group(0).replace("'", "").split(", ")  # type: ignore
        )
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
# v1.0.0 takes id from route GET and filters FPJ (json outputs of file querry) in order to download a file
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

    import sys

    sys.path.insert(1, "../rs-server/src")

    import logging

    logger = logging.getLogger()

    from s3_storage_handler import (
        files_to_be_downloaded,
        get_secrets,
        prefect_get_keys_from_s3,
    )

    s3_file_path = [resp["S3Path"] for resp in catalog_data["Data"] if Id == resp["Id"]]
    secrets = {
        "s3endpoint": "https://oss.eu-west-0.prod-cloud-ocb.orange-business.com",
        "accesskey": None,
        "secretkey": None,
    }
    if not get_secrets(secrets, "/home/opadeanu/.s3cfg"):
        logger.error("Could not get the secrets")
        return
    import os

    os.environ["S3_ENDPOINT"] = secrets["s3endpoint"] if secrets["s3endpoint"] is not None else ""
    os.environ["S3_ACCESS_KEY_ID"] = secrets["accesskey"] if secrets["accesskey"] is not None else ""
    os.environ["S3_SECRET_ACCESS_KEY"] = secrets["secretkey"] if secrets["secretkey"] is not None else ""
    os.environ["S3_REGION"] = "sbg"

    list_per_task = files_to_be_downloaded(bucket, s3_file_path, logger)

    @flow
    async def download_s3():
        task1 = asyncio.create_task(prefect_get_keys_from_s3(list_per_task, bucket, path, 1))
        await task1

    asyncio.run(download_s3())
    return send_file(os.path.join(os.path.abspath(path), s3_file_path[0].split("/")[-1]))
    # os.remove(os.path.join(path, s3_file_path[0].split('/')[-1]))
    # return '200'


def create_app():
    """Docstring to be added."""
    # Used to pass instance to conftest
    return app


if __name__ == "__main__":
    if len(sys.argv) > 1:  # script
        host, port = sys.argv[1:]
        app.run(debug=True, host=host, port=int(port))

    app.run(debug=True)  # local
    # app.run(debug=True, host="0.0.0.0", port=8443) # loopback for LAN
