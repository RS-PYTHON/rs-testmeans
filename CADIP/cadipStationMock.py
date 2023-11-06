import datetime
import json
import re
import sys
from typing import Any

from flask import Flask, Response, render_template, request, send_file
from flask_bcrypt import Bcrypt
from flask_httpauth import HTTPBasicAuth

app = Flask(__name__)
bcrypt = Bcrypt(app)
auth = HTTPBasicAuth()


@auth.verify_password
def verify_password(username, password) -> bool:
    users = json.loads(open("auth.json").read())
    if username in users.keys():
        return bcrypt.check_password_hash(users.get(username), password)
    return False


@app.route("/")
@auth.login_required
def hello():
    return render_template("home.html")


# 3.3 (PSD)
@app.route("/Sessions", methods=["GET"])
# @auth.login_required # Not yet
def querrySession() -> Response | list[Any]:
    # Additional output options to be added: orderby, top, skip, count.
    # Aditional operators to be added, and, or, not, in
    # Request with publicationDate gt / lt are not implemented yet
    if not request.args:
        return Response(status="400 Bad Request")
        # return Response('Bad Request', Response.status_code(400), None)

    # Check requested values, filter type can only be json keys
    if not any(
        [
            querry_text == request.args["filter"].split(" ")[0]
            for querry_text in ["Satellite", "DownlinkOrbit", "PublicationDate"]
        ],
    ):
        return Response(status="400 Bad Request")

    # Normalize request (lower case / remove ')
    field, op, value = map(lambda norm: norm.replace("'", ""), request.args["filter"].split(" "))
    catalogData = json.loads(open("Catalogue/SPJ.json").read())

    # return results or the 200OK code is returned with an empty response (PSD)
    if field == "PublicationDate":
        # year-month-day
        dateplaceholder = datetime.date(2014, 1, 1)
        date = dateplaceholder.replace(*map(int, value.split("-")))
        # sntx to be changed to match -> Python 3.11
        # Maybe should use LUT for operations
        match op:
            case "eq":
                # map inside map, to be reviewed?
                respBody = map(
                    json.dumps,
                    [
                        product
                        for product in catalogData["Data"]
                        if date == datetime.date(*map(int, product[field].split("T")[0].split("-")))
                    ],
                )
            case "gt":
                respBody = map(
                    json.dumps,
                    [
                        product
                        for product in catalogData["Data"]
                        if date < datetime.date(*map(int, product[field].split("T")[0].split("-")))
                    ],
                )
            case "lt":
                respBody = map(
                    json.dumps,
                    [
                        product
                        for product in catalogData["Data"]
                        if date > datetime.date(*map(int, product[field].split("T")[0].split("-")))
                    ],
                )
            case _:
                return Response(status="404")
        return Response(status=200, response=respBody) if respBody else Response(status=404)
    else:
        querry_result = [product for product in catalogData["Data"] if value in product[field]]
        return querry_result if querry_result else Response(status="200 OK")


# 3.4
@app.route("/Files", methods=["GET"])
# @auth.login_required # Not yet
def querryFiles() -> Response | list[Any]:
    if not request.args:
        return Response(status="400 Bad Request")

    if not any(
        [
            querry_text in request.args["filter"].split(" ")[0]
            for querry_text in ["Id", "Orbit", "Name", "PublicationDate"]
        ],
    ):
        return Response(status="400 Bad Request")

    catalogData = json.loads(open("Catalogue/FileResponse.json").read())
    if "Name" in request.args["filter"]:
        op, value = request.args["filter"].split("(")
        filterBy, filterValue = re.search("('.*?', '.*?')", value).group(0).replace("'", "").split(", ")  # type: ignore
        match op:
            case "contains":
                respBody = map(
                    json.dumps,
                    [product for product in catalogData["Data"] if filterValue in product[filterBy]],
                )
            case "startswith":
                respBody = map(
                    json.dumps,
                    [product for product in catalogData["Data"] if product[filterBy].startswith(filterValue)],
                )
            case "endswith":
                respBody = map(
                    json.dumps,
                    [product for product in catalogData["Data"] if product[filterBy].endswith(filterValue)],
                )
        return Response(status=200, response=respBody) if respBody else Response(status=404)
    else:  # SessionId / Orbit
        field, op, value = request.args["filter"].split(" ")
        # only op = eq at the moment
        # import pdb
        # pdb.set_trace()
        matching = map(
            json.dumps,
            [product for product in catalogData["Data"] if value == product[field]],
        )
        return Response(response=matching, status=200) if matching else Response(status=404)


# 3.5
# Not sure if download should be requested only with ID or with a json request?
# v1.0.0 takes id from route GET and filters FPJ (json outputs of file querry) in order to download a file
# Is possible / how to download multiple files
@app.route("/Files(<Id>)", methods=["GET"])
# @auth.login_required # Not yet
def downloadFile(Id) -> Response:
    catalogData = json.loads(open("Catalogue/FileResponse.json").read())

    files = [product for product in catalogData["Data"] if Id.replace("'", "") == product["Id"]]
    return (
        send_file("S3Mock/" + files[0]["Name"]) if len(files) == 1 else Response(status="404 None/Multiple files found")
    )
    # if files:
    #    return send_file("S3Mock/" + files[0]["Name"]) if len(files) == 1 else Response(status="200 not implemented")
    # else:
    #    return Response(status=404)


# 3.6
@app.route("/Sessions(<Id>)", methods=["GET"])
def qualityInfo(Id) -> Response | list[Any]:
    if "expand" in request.args:
        if request.args["expand"] == "qualityInfo":
            catalogData = json.loads(open("Catalogue/FileResponse.json").read())
            QIData = map(
                json.dumps,
                [QIData for QIData in catalogData["Data"] if Id.replace("'", "") == QIData["Id"]],
            )
            return Response(status=200, response=QIData)
    return Response(status="405 Request denied, need qualityInfo")


if __name__ == "__main__":
    if len(sys.argv) > 1:  # script
        host, port = sys.argv[1:]
        app.run(debug=True, host=host, port=int(port))

    app.run(debug=True)  # local
    # app.run(debug=True, host="0.0.0.0", port=8443) # loopback for LAN
