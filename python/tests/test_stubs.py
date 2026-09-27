"""The ``.pyi`` stubs, which editors read for hover text, document every public
member with the same text as the runtime ``__doc__`` that ``help()`` shows."""

import ast
import importlib
import inspect
from pathlib import Path

import pytest

import dryoc

PACKAGE = Path(dryoc.__file__).parent
STUBS = sorted(path for path in PACKAGE.rglob("*.pyi") if not path.name.startswith("_"))

# Dunders whose behavior is implied by the protocol; they need no docstring.
UNDOCUMENTED = {"__enter__", "__eq__", "__exit__", "__hash__", "__iter__", "__len__", "__repr__"}


def module_name(stub: Path) -> str:
    return ".".join(("dryoc", *stub.relative_to(PACKAGE).with_suffix("").parts))


def members(stub: Path) -> list[tuple[str, str | None, list[object]]]:
    """Returns ``(name, stub docstring, runtime owners)`` for every public
    class, function, method, property and constant in ``stub``.

    Members of a private stub base class (``_Hash`` and friends, which do
    not exist at runtime) are checked on each public subclass. ``__new__`` and
    constants have no runtime owners: PyO3 does not expose their docs.
    """
    module = importlib.import_module(module_name(stub))
    tree = ast.parse(stub.read_text())
    subclasses: dict[str, list[object]] = {}
    for node in tree.body:
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                if isinstance(base, ast.Name):
                    subclasses.setdefault(base.id, []).append(getattr(module, node.name))
    found: list[tuple[str, str | None, list[object]]] = []
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            found.append((node.name, ast.get_docstring(node), [getattr(module, node.name)]))
        if not isinstance(node, ast.ClassDef):
            continue
        if node.name.startswith("_"):
            owners = subclasses[node.name]
        else:
            owners = [getattr(module, node.name)]
            found.append((node.name, ast.get_docstring(node), owners))
        for index, item in enumerate(node.body):
            if isinstance(item, ast.FunctionDef) and item.name not in UNDOCUMENTED:
                attrs = [] if item.name == "__new__" else [getattr(o, item.name) for o in owners]
                found.append((f"{node.name}.{item.name}", ast.get_docstring(item), attrs))
            elif (
                isinstance(item, ast.AnnAssign)
                and isinstance(item.target, ast.Name)
                and item.target.id != "__hash__"
            ):
                following = node.body[index + 1] if index + 1 < len(node.body) else None
                doc = None
                if isinstance(following, ast.Expr) and isinstance(following.value, ast.Constant):
                    value = following.value.value
                    doc = value if isinstance(value, str) else None
                found.append((f"{node.name}.{item.target.id}", doc, []))
    return found


@pytest.mark.parametrize("stub", STUBS, ids=module_name)
def test_every_public_member_has_a_docstring(stub: Path) -> None:
    missing = [name for name, doc, _ in members(stub) if not doc]
    assert not missing, f"{module_name(stub)}: add docstrings to {missing}"


@pytest.mark.parametrize("stub", STUBS, ids=module_name)
def test_stub_docstrings_match_runtime(stub: Path) -> None:
    for name, doc, owners in members(stub):
        for owner in owners:
            assert doc == inspect.cleandoc(owner.__doc__ or ""), f"{module_name(stub)}.{name}"
