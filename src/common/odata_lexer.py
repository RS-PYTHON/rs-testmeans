# Copyright 2023-2026 Airbus, CS Group
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

import re

from odata_query.ast import (
    Attribute,
    Boolean,
    BoolOp,
    Call,
    CollectionLambda,
    Compare,
    DateTime,
    Identifier,
    List,
    String,
)
from odata_query.exceptions import ParsingException, UnknownFunctionException
from odata_query.grammar import ODataLexer, ODataParser
from odata_query.visitor import NodeVisitor


class FilterExtractor(NodeVisitor):
    """AST visitor that extracts filters from an OData query AST into a dictionary.

    The extracted filters map attribute paths to conditions, e.g.:
    {
        "ContentDate/Start": {"op": "Gt", "value": "2019-01-01T00:00:00.000Z"},
        "Name": {"op": "contains", "value": "S2__OPER_AUX_ECMWFD_PDMC_20190216T1"}
    }
    """

    def __init__(self):
        # Dictionary to hold extracted filters keyed by attribute path
        self.result = {}

    def _get_attr_path(self, node):
        """Recursively constructs the full attribute path from AST nodes.

        ContentDate['Start'] -> 'ContentDate/Start'.

        Args:
            node (Attribute | Identifier): The AST node representing an attribute or identifier.

        Returns:
            str: The full attribute path as a string separated by '/'.

        """
        parts = []
        # Traverse upward through Attribute nodes collecting attribute names
        while isinstance(node, Attribute):
            parts.insert(0, node.attr)
            node = node.owner
        # Prepend the root identifier name if present
        if isinstance(node, Identifier):
            parts.insert(0, node.name)
        # Join all parts with slash delimiter to form the path string
        return "/".join(parts)

    def visit_Compare(self, node: Compare):
        """Visits a comparison node (e.g. ContentDate/Start gt '2019-01-01T00:00:00.000Z')
        and extracts the attribute, operator, and value.

        Stores the condition in self.result. Handles multiple conditions on the
        same attribute by storing a list.

        Args:
            node (Compare): The comparison AST node.

        """
        attr_path = self._get_attr_path(node.left)
        # Only handle comparisons where right side is a literal or identifier
        if isinstance(node.right, (String, DateTime, Boolean, List, Identifier)):
            value = node.right.val if hasattr(node.right, "val") else node.right.name
            cond = {"op": type(node.comparator).__name__, "value": value}
            # Append to existing conditions for the attribute if needed
            if attr_path in self.result:
                if isinstance(self.result[attr_path], list):
                    self.result[attr_path].append(cond)
                else:
                    self.result[attr_path] = [self.result[attr_path], cond]
            else:
                self.result[attr_path] = cond

    def visit_BoolOp(self, node: BoolOp):
        """Visits boolean operation nodes (AND, OR) and recursively visits both sides.

        Args:
            node (BoolOp): The boolean operation AST node.

        """
        self.visit(node.left)
        self.visit(node.right)

    def visit_Call(self, node: Call):
        """Visits function call nodes such as contains(), startswith(), endswith().

        Extracts the attribute and value arguments and stores them similarly
        to comparison nodes in self.result.

        Args:
            node (Call): The function call AST node.

        """
        func_name = node.func.name if isinstance(node.func, Identifier) else None
        if func_name in {"contains", "startswith", "endswith"} and len(node.args) == 2:
            arg0 = node.args[0]
            # Extract attribute path from first argument if valid
            attr_path = self._get_attr_path(arg0) if isinstance(arg0, (Identifier, Attribute)) else None
            arg1 = node.args[1]
            # Extract string value from second argument
            value = arg1.val if isinstance(arg1, String) else None

            if attr_path and value is not None:
                cond = {"op": func_name, "value": value}
                # Append or create condition in the result dict
                if attr_path in self.result:
                    if isinstance(self.result[attr_path], list):
                        self.result[attr_path].append(cond)
                    else:
                        self.result[attr_path] = [self.result[attr_path], cond]
                else:
                    self.result[attr_path] = cond
        else:
            # Visit all arguments recursively if not a recognized function call
            for arg in node.args:
                self.visit(arg)

    def visit_CollectionLambda(self, node: CollectionLambda):
        """Visits collection lambda expressions (e.g. any() in OData).

        Specifically extracts key-value pairs from lambdas that compare 'Name' and 'Value' properties,

        any(att: att/Name eq 'productType' and att/Value eq 'MSI_L1C_TL')

        Args:
            node (CollectionLambda): The collection lambda AST node.

        """
        if isinstance(node.lambda_.expression, BoolOp):
            left = node.lambda_.expression.left
            right = node.lambda_.expression.right

            def extract_key_and_value(expr):
                if not isinstance(expr, Compare):
                    return None, None
                attr_path = self._get_attr_path(expr.left)
                if "Name" in attr_path:
                    return "key", expr.right.val
                elif "Value" in attr_path:
                    return "value", expr.right.val
                return None, None

            parts = {}
            # Extract 'key' and 'value' from both sides of the AND expression
            for expr in [left, right]:
                k, v = extract_key_and_value(expr)
                if k and v:
                    parts[k] = v

            # Store the extracted key-value pair in the result dict as an equality condition
            if "key" in parts and "value" in parts:
                self.result[parts["key"]] = {"op": "Eq", "value": parts["value"]}

        else:
            self.visit(node.lambda_.expression)


def parse_odata_filter(query: str):
    """Parses an OData $filter query string and extracts filters into a dictionary.

    Args:
        query (str): The OData $filter query string, optionally starting with "$filter=".

    Returns:
        dict: Dictionary of extracted filters keyed by attribute paths.

    """
    # Strip leading "$filter=" if present
    if query.startswith("$filter="):
        query = query[len("$filter=") :]
    # Normalize unquoted UUIDs for Id eq/in so the parser can handle them.
    query = quote_unquoted_uuid_in_id_filter(query)
    try:
        # Tokenize the query string using ODataLexer
        lexer = ODataLexer()
        tokens = lexer.tokenize(query)

        # Parse tokens into an AST using ODataParser
        parser = ODataParser()
        ast = parser.parse(tokens)

        # Extract filters from the AST using FilterExtractor visitor
        extractor = FilterExtractor()
        extractor.visit(ast)
    except (UnknownFunctionException, ParsingException):
        return {}

    return extractor.result


# UUID matcher used to normalize unquoted Id values before OData parsing.
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-" r"[0-9a-fA-F]{4}-" r"[0-9a-fA-F]{4}-" r"[0-9a-fA-F]{4}-" r"[0-9a-fA-F]{12}")


def quote_unquoted_uuid_in_id_filter(query: str) -> str:
    """Normalize Id eq/in filters so UUIDs without quotes parse as strings."""

    def _normalize_token(token: str) -> str:
        # Keep already-quoted tokens; only quote bare UUIDs.
        token = token.strip()
        if not token:
            return token
        if token.startswith(("'", '"')) or token.lower().startswith("guid'"):
            return token
        if UUID_RE.fullmatch(token):
            return f"'{token}'"
        return token

    def _eq_repl(match: re.Match) -> str:
        # Rewrite "Id eq <uuid>" to "Id eq '<uuid>'" for the lexer.
        value = _normalize_token(match.group("value"))
        return f"Id eq {value}"

    def _in_repl(match: re.Match) -> str:
        # Rewrite "Id in (<uuid>,...)" to quote bare UUIDs for the lexer.
        # Some callers send lists as (['a','b']); strip brackets to match OData list syntax.
        raw_values = match.group("values").replace("[", "").replace("]", "")
        values = [_normalize_token(v) for v in raw_values.split(",")]
        return f"Id in ({', '.join(values)})"

    query = re.sub(r"\bId\s+eq\s+(?P<value>[^ )]+)", _eq_repl, query)
    query = re.sub(r"\bId\s+in\s*\(\s*(?P<values>[^)]+)\)", _in_repl, query)
    return query
