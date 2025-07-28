"""Docstring to be added."""
import json
from functools import wraps
from typing import Any
from flask import request

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

def additional_options(func):
    """Common function to paginate requests with top, skip, count, orderby"""

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