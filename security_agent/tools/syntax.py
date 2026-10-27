"""C/C++ syntax observations. Never claim dataflow, dominance or call resolution."""
from pathlib import PurePosixPath
from tree_sitter import Language, Parser
import tree_sitter_c
import tree_sitter_cpp

KINDS = {'dereference': {'pointer_expression', 'field_expression', 'subscript_expression'},
         'null_guard': {'if_statement', 'conditional_expression', 'binary_expression'},
         'return': {'return_statement'}, 'assignment': {'assignment_expression', 'init_declarator'},
         'call': {'call_expression'}}


def observe(source, file, operation, request):
    grammar = tree_sitter_c if PurePosixPath(file).suffix == '.c' else tree_sitter_cpp
    language = Language(grammar.language()); parser = Parser(language)
    data = source.encode(); tree = parser.parse(data)
    observations = []
    symbol = request.get('symbol', '').split('::')[-1]
    kind = 'assignment' if operation == 'find_assignments' else request.get('kind')
    types = {'function_definition'} if operation == 'find_definition' else KINDS.get(kind, set())
    def visit(node):
        start, end = node.start_point.row + 1, node.end_point.row + 1
        if end < request.get('start', 1) or start > request.get('end', 10**9):
            return
        if node.type in types:
            text = node.text.decode()
            match = True
            if operation == 'find_definition':
                decl = node.child_by_field_name('declarator')
                while decl and decl.type != 'function_declarator':
                    decl = decl.child_by_field_name('declarator')
                name = decl.child_by_field_name('declarator') if decl else None
                match = bool(name and name.text.decode().split('::')[-1] == symbol)
            elif operation == 'find_assignments':
                match = bool(symbol and symbol in text)
            elif kind == 'dereference':
                match = '*' in text or '->' in text or '[' in text
            elif kind == 'null_guard':
                match = node.type in ('if_statement', 'conditional_expression') or any(s in text for s in ('nullptr', 'NULL', '==', '!='))
            if match and not node.has_error:
                observations.append((file, start, end, 'syntax-observation', {'syntax_kind': node.type}))
        for child in node.named_children:
            visit(child)
    visit(tree.root_node)
    return observations, tree.root_node.has_error
