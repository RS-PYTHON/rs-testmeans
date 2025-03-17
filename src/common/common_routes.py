# Copyright 2024 CS Group
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import os
from flask import Flask, request, Response, current_app
import json
import random
import string
from datetime import datetime
import pathlib
import logging
from functools import wraps
from http import HTTPStatus
import multiprocessing
from flask_httpauth import HTTPBasicAuth
from flask_bcrypt import Bcrypt

auth = HTTPBasicAuth()

logger = logging.getLogger(__name__)

# Create a global lock to synchronize the access to the json authentication file between the different processes
LOCK = multiprocessing.Lock()

EMPTY_AUTH_CONFIG = {
    "client_id": "client_id",
    "client_secret": "client_secret",
    "username" : "test",
    "password" : "test",
    "grant_type" : "password",
    "access_token_list": [],
    "access_token_creation_date": [],
    "expires_in_list": [],
    "refresh_token_list": [],
    "refresh_token_creation_date": [],
    "refresh_expires_in_list": []
}

EMPTY_TOKEN_DICT = {
    "client_id": str,
    "client_secret": str,
    "username": str,
    "password": str,
    "grant_type": str,
    "access_token_list": list,
    "access_token_creation_date": list,
    "expires_in_list": list,
    "refresh_token_list": list,
    "refresh_token_creation_date": list,
    "refresh_expires_in_list": list,
}

KEYS_TO_UPDATE = [
    "access_token_list", 
    "access_token_creation_date", 
    "expires_in_list", 
    "refresh_token_list", 
    "refresh_token_creation_date", 
    "refresh_expires_in_list"
]

# Set validity period (in seconds) for access and refresh tokens
EXPIRES_IN = 1200
REFRESH_EXPIRES_IN = 3600


def clean_token_dict(config_auth_dict: dict[list], auth_path: str):
    """
    Function to remove expired tokens from the list of token dictionaries: for each token, 
    we check if it is expired by comparing its creation date + its life duration with the 
    current date. If it is expired, we remove information related to this token from all
    lists of the dictionary
    
    Args:
        config_auth_dict (dict[list]): token information dictionary
    Return:
        config_auth_dict (dict[list]): the updated token information dictionary
    """
    index_to_delete = []
    current_time = datetime.now()
    
    # Check that the file containing the token information exist
    if not os.path.isfile(auth_path):
        raise FileNotFoundError(f"The file {auth_path} does not exist")
        
    # Check that the token dictionary contains all mandatory keys
    # And the right value types
    for key, value in EMPTY_TOKEN_DICT.items():
        if key not in config_auth_dict:
            raise KeyError(f"Mandatory key {key} is missing from the json token dictionary")
        if not isinstance(config_auth_dict[key], EMPTY_TOKEN_DICT[key]):
            raise TypeError(f"""Value from key {key} doesn't have the right type:""" 
                            f"""got {type(config_auth_dict[key])}, expected {value}""")

    # Get index of elements from the dictionary to delete
    for i in range(len(config_auth_dict["access_token_list"])):
        if (current_time - datetime.fromisoformat(config_auth_dict["access_token_creation_date"][i])).total_seconds() >= config_auth_dict["expires_in_list"][i] \
        and ((current_time - datetime.fromisoformat(config_auth_dict["refresh_token_creation_date"][i])).total_seconds() >= config_auth_dict["refresh_expires_in_list"][i]):
            index_to_delete.append(i)
    # Delete elements with selected indexes
    if index_to_delete:
        logger.info(f"{len(index_to_delete)} token(s) have expired. Deleting them ...")
        for key in KEYS_TO_UPDATE:
            config_auth_dict[key] = [value for index, value in enumerate(config_auth_dict[key]) if index not in index_to_delete]
    
    # Write the new token dictionary in the auth.json file
    try:
        with open(auth_path, "w", encoding="utf-8") as f:
            json.dump(config_auth_dict, f, indent=4, ensure_ascii=False)
    except FileNotFoundError:
        raise FileNotFoundError(f"The file '{auth_path}' cannot be found.")
    except json.JSONDecodeError:
        raise ValueError(f"The file '{auth_path}' is not valid Json.")


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
        # Remove tokens information if both access_token and refresh_token are expired
        # Here we use "current_app" variable because we cannot directly pass the current application
        # as a parameter to the decorator
        auth_path = str(current_app.config["configuration_path"] / "auth.json")
        with LOCK:        
            config_auth = json.loads(open(auth_path).read())  
            clean_token_dict(config_auth, auth_path)
        token = None        
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split()[1]
            logger.info(f"{request.headers['Authorization']}")
        else:
            logger.info("NO AUTHORIZATION IN HEADERS")

        if not token:
            logger.error("Returning HTTP_UNAUTHORIZED. Token is missing")
            return Response(status=HTTPStatus.UNAUTHORIZED, response=json.dumps({"message": "Token is missing!"}))
        
        # Raise an error if the given token doesn't exist in the token dictionary
        if token not in config_auth["access_token_list"]:
            logger.error("Returning HTTP_UNAUTHORIZED. Token is invalid!")
            return Response(status=HTTPStatus.UNAUTHORIZED, response=json.dumps({"message": "Token is invalid!"}))

        # Raise an error if the given access token is expired
        token_index = config_auth["access_token_list"].index(token)
        if (datetime.now() - datetime.fromisoformat(config_auth["access_token_creation_date"][token_index])).total_seconds() >= config_auth["expires_in_list"][token_index]:
            return Response(status=HTTPStatus.UNAUTHORIZED, response=json.dumps({"message": "Token is valid but is expired!"}))
        
        return f(*args, **kwargs)

    return decorated

def register_token_route(app: Flask):
    """Register route /oauth2/token on a Flask instance"""
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
        # Remove tokens information if both access_token and refresh_token are expired
        auth_path = str(app.config["configuration_path"] / "auth.json")
        
        # Get the form data
        logger.info("Endpoint oauth2/token called")
        client_id = request.form.get("client_id")
        client_secret = request.form.get("client_secret")
        username = request.form.get("username")
        password = request.form.get("password")
        grant_type = request.form.get("grant_type")
        scope = request.form.get("scope")    

        # Optional Authorization header check
        # auth_header = request.headers.get('Authorization')
        # logger.info(f"auth_header {auth_header}")

        # Allow only one process at a time toread and update the authentication configuration file 
        with LOCK:        
            config_auth = json.loads(open(auth_path).read())    
            clean_token_dict(config_auth, auth_path)

            logger.info("Token requested")    
            if request.headers.get("Authorization", None):
                logger.debug(f"Authorization in request.headers = {request.headers['Authorization']}")
            
            # Validate required fields
            if not client_id or not client_secret or not username or not password:
                logger.error("Invalid client. The token is not granted")
                return Response(status=HTTPStatus.UNAUTHORIZED, response=json.dumps({"error": "Invalid client"}))

            if client_id != config_auth["client_id"] or client_secret != config_auth["client_secret"]:
                logger.error("Invalid client id and/or secret. The token is not granted")
                return Response(status=HTTPStatus.UNAUTHORIZED, response=json.dumps({"error": 
                                                                            f"Invalid client id and/or secret: {client_id} | {client_secret}"}))
            if username != config_auth["username"] or password != config_auth["password"]:
                logger.error("Invalid username and/or password. The token is not granted")
                return Response(status=HTTPStatus.UNAUTHORIZED, response=json.dumps({"error": "Invalid username and/or password"}))
            # Validate the grant_type
            if grant_type != config_auth["grant_type"]:
                logger.error("Unsupported grant_type. The token is not granted")
                return json.dumps({"error": "Unsupported grant_type"}), HTTPStatus.BAD_REQUEST
            
            # Add new access token and refresh token to the token dictionary
            config_auth["access_token_list"].append(''.join(random.choices(string.ascii_letters, k=59)))
            config_auth["access_token_creation_date"].append(datetime.now().isoformat())
            config_auth["expires_in_list"].append(EXPIRES_IN)
            config_auth["refresh_token_list"].append(''.join(random.choices(string.ascii_letters, k=59)))
            config_auth["refresh_token_creation_date"].append(datetime.now().isoformat())
            config_auth["refresh_expires_in_list"].append(REFRESH_EXPIRES_IN)

            # Update the authentification configuration file with 
            with open(auth_path, "w", encoding="utf-8") as f:
                json.dump(config_auth, f, indent=4, ensure_ascii=False) 
        
        # Send back the last created token to the the client
        response = {
            "access_token": config_auth["access_token_list"][-1],
            "token_type": "Bearer", 
            "expires_in": config_auth["expires_in_list"][-1],
            "refresh_token": config_auth["refresh_token_list"][-1],
            "refresh_expires_in": config_auth["refresh_expires_in_list"][-1],
        }
        
        logger.info("Grant type validated. Token sent back")
        logger.info(f"CURRENT DATE: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        logger.info(f"-------------------- ACCESS TOKEN SENT BACK: {config_auth['access_token_list'][-1]}")
        return Response(status=HTTPStatus.OK, response=json.dumps(response))

@auth.verify_password
def verify_password(app, username: str, password: str) -> bool:
    """Verify the password for a given username.

    :param username: The username for which the password is being verified.
    :type username: str

    :param password: The password to be verified.
    :type password: str

    :return: True if the password is valid, False otherwise.
    :rtype: Optional[bool]
    """
    bcrypt = Bcrypt(app)
    auth_path = app.config["configuration_path"] / "auth.json"
    users = json.loads(open(auth_path).read())
    if username in users.keys():
        return bcrypt.check_password_hash(users.get(username), password)
    return False