"""Docstring to be added."""
import argparse
import asyncio
import datetime
import json
import logging
import os
import re
import sys
from typing import Any

from flask import Flask, Response, request, send_file
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
    users = json.loads(open("src/ADGS/auth.json").read())
    if username in users.keys():
        return bcrypt.check_password_hash(users.get(username), password)
    return False


@app.route("/", methods=["GET", "POST"])
@auth.login_required
def hello():
    """Docstring to be added."""
    return Response(status=OK)


@app.route("/Products", methods=["GET"])
def query_products():
    """Docstring to be added."""
    if not request.args:
        return Response(status=BAD_REQUEST)

    if not any(
        [query_text in request.args["$filter"].split(" ")[0] for query_text in ["Name", "PublicationDate"]],
    ):
        return Response(status=BAD_REQUEST)

    catalog_data = json.loads(open("src/ADGS/Catalog/GETFileResponse.json").read())
    if "Name" in request.args["$filter"]:
        pattern = r"(\w+)\((\w+), \'?(\w+)\'?\)"
        op = re.search(pattern, request.args["$filter"]).group(1)
        filter_by = re.search(pattern, request.args["$filter"]).group(2)
        filter_value = re.search(pattern, request.args["$filter"]).group(3)
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
    elif "PublicationDate" in request.args["$filter"]:
        field, op, value = request.args["$filter"].split(" ")
        date_placeholder = datetime.datetime(2014, 1, 1, 12, 0, tzinfo=datetime.timezone.utc)
        date = date_placeholder.replace(*map(int, value.split("-")))  # type: ignore
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


@app.route("/Products(<Id>)/$value", methods=["GET"])
@auth.login_required
def download_file(Id) -> Response:  # noqa: N803
    """Docstring to be added."""
    catalog_data = json.loads(open("src/ADGS/Catalog/GETFileResponse.json").read())

    files = [product for product in catalog_data["Data"] if Id.replace("'", "") == product["Id"]]
    return (
        send_file("Storage/" + files[0]["Name"])
        if len(files) == 1
        else Response(status="404 None/Multiple files found")
    )


@app.route("/Products(<Id>)/$S3OS", methods=["GET"])
@auth.login_required
def download_file_s3(Id) -> Response:  # noqa: N803
    """Docstring to be added."""
    catalog_data = json.loads(open("src/ADGS/Catalog/GETS3FileResponse.json").read())
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


def create_adgs_app():
    """Docstring to be added."""
    # Used to pass instance to conftest
    return app


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Starts the ADGS server mockup ",
    )

    parser.add_argument("-s", "--secret-file", type=str, required=False, help="File with the secrets")
    parser.add_argument("-p", "--port", type=int, required=False, default=5001, help="Port to use")
    parser.add_argument("-H", "--host", type=str, required=False, default="127.0.0.1", help="Host to use")

    args = parser.parse_args()

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

    app.run(debug=True, port=args.port)  # local
