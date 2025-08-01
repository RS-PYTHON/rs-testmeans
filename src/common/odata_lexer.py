from odata_query.grammar import ODataLexer, ODataParser
from odata_query.visitor import NodeVisitor
from odata_query.ast import String, DateTime, Boolean, Compare, Identifier, Attribute, BoolOp, Call, CollectionLambda


class FilterExtractor(NodeVisitor):
    """
    AST visitor that extracts filters from an OData query AST into a dictionary.

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
        """
        Recursively constructs the full attribute path from AST nodes.

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
        """
        Visits a comparison node (e.g. ContentDate/Start gt '2019-01-01T00:00:00.000Z')
        and extracts the attribute, operator, and value.

        Stores the condition in self.result. Handles multiple conditions on the
        same attribute by storing a list.

        Args:
            node (Compare): The comparison AST node.
        """
        attr_path = self._get_attr_path(node.left)
        # Only handle comparisons where right side is a string or datetime literal

        if isinstance(node.right, (String, DateTime, Boolean)):
            cond = {
                "op": type(node.comparator).__name__,
                "value": node.right.val
            }
            # Append to existing conditions for the attribute if needed
            if attr_path in self.result:
                if isinstance(self.result[attr_path], list):
                    self.result[attr_path].append(cond)
                else:
                    self.result[attr_path] = [self.result[attr_path], cond]
            else:
                self.result[attr_path] = cond

    def visit_BoolOp(self, node: BoolOp):
        """
        Visits boolean operation nodes (AND, OR) and recursively visits both sides.

        Args:
            node (BoolOp): The boolean operation AST node.
        """
        self.visit(node.left)
        self.visit(node.right)

    def visit_Call(self, node: Call):
        """
        Visits function call nodes such as contains(), startswith(), endswith().

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
                cond = {
                    "op": func_name,
                    "value": value
                }
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
        """
        Visits collection lambda expressions (e.g. any() in OData).

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
                self.result[parts["key"]] = {
                    "op": "Eq",
                    "value": parts["value"]
                }

        else:
            self.visit(node.lambda_.expression)


def parse_odata_filter(query: str):
    """
    Parses an OData $filter query string and extracts filters into a dictionary.

    Args:
        query (str): The OData $filter query string, optionally starting with "$filter=".

    Returns:
        dict: Dictionary of extracted filters keyed by attribute paths.
    """
    # Strip leading "$filter=" if present
    if query.startswith("$filter="):
        query = query[len("$filter="):]

    # Tokenize the query string using ODataLexer
    lexer = ODataLexer()
    tokens = lexer.tokenize(query)

    # Parse tokens into an AST using ODataParser
    parser = ODataParser()
    ast = parser.parse(tokens)

    # Extract filters from the AST using FilterExtractor visitor
    extractor = FilterExtractor()
    extractor.visit(ast)

    return extractor.result
