"""Locate a C/C++ function in frozen source using syntax, not model guesses."""
from pathlib import PurePosixPath
from tree_sitter import Language, Parser
import tree_sitter_c
import tree_sitter_cpp


def locate(source, file, selector, line=None):
    grammar = tree_sitter_c if PurePosixPath(file).suffix == '.c' else tree_sitter_cpp
    language = Language(grammar.language())
    parser = Parser(language)
    data = source.encode('utf-8')
    tree = parser.parse(data)
    matches = []

    def visit(node, parents):
        scope = parents
        if node.type in ('namespace_definition', 'class_specifier', 'struct_specifier'):
            name = node.child_by_field_name('name')
            if name:
                scope = parents + [name.text.decode()]
        if node.type == 'function_definition':
            declarator = node.child_by_field_name('declarator')
            while declarator and declarator.type != 'function_declarator':
                declarator = declarator.child_by_field_name('declarator')
            name = declarator.child_by_field_name('declarator') if declarator else None
            body = node.child_by_field_name('body')
            if name and body:
                short = name.text.decode()
                prefix = '::'.join(parents)
                full = short if not prefix or short.startswith(prefix + '::') else prefix + '::' + short
                start, end = node.start_point.row + 1, node.end_point.row + 1
                if (full == selector or full.endswith('::' + selector)) and (line is None or start <= line <= end):
                    if node.has_error:
                        raise ValueError(f'function has syntax errors: {full}; cannot establish its scope')
                    matches.append({'name': full, 'start': start, 'end': end,
                                    'start_byte': node.start_byte, 'end_byte': node.end_byte,
                                    'parser': 'tree-sitter-c' if grammar is tree_sitter_c else 'tree-sitter-cpp'})
            # Lambdas/local classes inside a function are not independent top-level selectors here.
            return
        for child in node.named_children:
            visit(child, scope)

    visit(tree.root_node, [])
    if not matches:
        raise ValueError(f'function definition not found: {selector} in {file}')
    if len(matches) != 1:
        choices = ', '.join(f"{m['name']}:{m['start']}" for m in matches)
        raise ValueError(f'ambiguous function: {selector}; use a qualified name and/or --line ({choices})')
    return matches[0]

