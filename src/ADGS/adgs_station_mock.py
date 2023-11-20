import datetime
import json
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


def prepare_response_odata_v4(resp_body: list | map) -> Any:
    """Docstring to be added."""
    unpacked = list(resp_body) if not isinstance(resp_body, list) else resp_body
    return json.dumps(dict(responses=unpacked)) if len(unpacked) > 1 else json.dumps(unpacked[0])


@auth.verify_password
def verify_password(username: str, password: str) -> bool:
    """Docstring to be added."""
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
def querry_products():
    """Docstring to be added."""
    if not request.args:
        return Response(status=BAD_REQUEST)

    if not any(
        [querry_text in request.args["$filter"].split(" ")[0] for querry_text in ["Name", "PublicationDate"]],
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
        return Response(status=OK, response=prepare_response_odata_v4(resp_body)) if resp_body else Response(status=NOT_FOUND)
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
        pass  # WIP
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

def create_app():
    """Docstring to be added."""
    # Used to pass instance to conftest
    return app

if __name__ == "__main__":
    app.run(debug=True, port='5001')  # local
