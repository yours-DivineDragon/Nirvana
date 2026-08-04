from __future__ import annotations

import argparse
import copy
import hashlib
import json
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from nirvana.evm import (
    SolcAstCandidateScanner,
    _compiler_operation_summaries,
    _condition_words,
    _direct_call_declarations,
    _guard_conditions,
    _modifier_words,
    _regular_source_path,
    _state_write_declarations,
    _walk_ast,
    classify_guard_text,
)
from nirvana.symmetry import OperationSummary, SymmetryAnalyzer, _inverse_match
from nirvana.util import atomic_write_json


MAX_DOCUMENT_BYTES = 100 * 1024 * 1024
FACT_FIELDS = frozenset({"state_reads", "state_writes", "guards", "effects"})
REMOVABLE_NODE_TYPES = frozenset(
    {
        "EmitStatement",
        "ExpressionStatement",
        "IfStatement",
        "InlineAssembly",
        "ModifierInvocation",
        "Return",
        "RevertStatement",
        "TryStatement",
        "VariableDeclarationStatement",
        "WhileStatement",
        "DoWhileStatement",
        "ForStatement",
    }
)


@dataclass(frozen=True, slots=True)
class _NodePathItem:
    node: object
    parent: object | None
    key: str | int | None


def normalized_ast_document(combined: object) -> dict[str, object]:
    if not isinstance(combined, dict):
        raise ValueError("combined-json input must be one JSON object")
    sources = combined.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("combined-json input lacks a sources object")
    normalized_sources: dict[str, dict[str, object]] = {}
    for source_name, source_record in sources.items():
        if not isinstance(source_name, str) or not isinstance(source_record, dict):
            continue
        ast = source_record.get("AST")
        if isinstance(ast, dict):
            normalized_sources[source_name] = {"ast": ast}
    if not normalized_sources:
        raise ValueError("combined-json input contains no compiler ASTs")
    return {"sources": normalized_sources}


def canonical_ast_bytes(document: dict[str, object]) -> bytes:
    return (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def apply_mutation(
    combined: dict[str, object], mutation: dict[str, object]
) -> dict[str, object]:
    kind = _required_string(mutation, "kind", "mutation")
    function_id = _required_integer(mutation, "function_id", "mutation")
    node_src = _required_string(mutation, "node_src", "mutation")
    source_name, function = _unique_function(combined, function_id)

    if kind == "remove_guard":
        category = _required_string(mutation, "category", "mutation")
        target = _unique_guard_node(function, node_src, category)
        removed = _remove_enclosing_node(function, target)
        details = {"category": category}
    elif kind == "remove_write":
        state_name = _required_string(mutation, "state", "mutation")
        state_ids = _state_ids_by_name(combined, state_name)
        target = _unique_descendant(
            function.get("body"),
            lambda node: isinstance(node, dict)
            and node.get("src") == node_src
            and bool(_state_write_declarations(node, state_ids)),
            f"state write {state_name!r} at {node_src}",
        )
        removed = _remove_enclosing_node(function, target)
        details = {"state": state_name}
    elif kind == "remove_call":
        callee_id = _required_integer(mutation, "callee_id", "mutation")
        target = _unique_descendant(
            function.get("body"),
            lambda node: isinstance(node, dict)
            and node.get("nodeType") == "FunctionCall"
            and node.get("src") == node_src
            and callee_id in _direct_call_declarations(node),
            f"call to declaration {callee_id} at {node_src}",
        )
        removed = _remove_enclosing_node(function, target)
        details = {"callee_id": callee_id}
    else:
        raise ValueError(f"unsupported mutation kind: {kind}")

    return {
        "kind": kind,
        "function_id": function_id,
        "function_name": str(function.get("name") or function.get("kind") or "function"),
        "source": source_name,
        "selected_node_src": node_src,
        "removed_node_type": str(removed.get("nodeType") or "unknown"),
        "removed_node_src": str(removed.get("src") or node_src),
        **details,
    }


def measure_case(
    workspace: Path,
    case: dict[str, object],
    mutated_directory: Path,
) -> dict[str, object]:
    case_id = _required_string(case, "case_id", "case")
    repository = _required_string(case, "repository", f"case {case_id}")
    expected_ast_sha256 = _required_sha256(
        case, "expected_ast_sha256", f"case {case_id}"
    )
    combined_path = _regular_workspace_file(
        workspace,
        _required_string(case, "combined_json", f"case {case_id}"),
        f"case {case_id} combined-json",
    )
    target_root = _workspace_directory(
        workspace,
        _required_string(case, "target_root", f"case {case_id}"),
        f"case {case_id} target root",
    )
    combined = _load_json_object(combined_path, f"case {case_id} combined-json")
    baseline_document = normalized_ast_document(combined)
    baseline_bytes = canonical_ast_bytes(baseline_document)
    baseline_sha256 = hashlib.sha256(baseline_bytes).hexdigest()
    if baseline_sha256 != expected_ast_sha256:
        raise ValueError(
            f"case {case_id} AST digest mismatch: expected {expected_ast_sha256}, "
            f"observed {baseline_sha256}"
        )

    baseline_ast_path = mutated_directory / f"{case_id}-baseline.ast.json"
    baseline_ast_path.write_bytes(baseline_bytes)
    baseline_scanner = SolcAstCandidateScanner()
    baseline_hypotheses = baseline_scanner.scan_file(baseline_ast_path, target_root)
    baseline_symmetry = [
        item
        for item in baseline_hypotheses
        if item.generator.startswith("symmetry-analysis:")
    ]
    expected_baseline = case.get("expected_baseline_symmetry_hypotheses", 0)
    if not isinstance(expected_baseline, int) or isinstance(expected_baseline, bool):
        raise ValueError(
            f"case {case_id} expected_baseline_symmetry_hypotheses must be an integer"
        )
    if len(baseline_symmetry) != expected_baseline:
        raise ValueError(
            f"case {case_id} baseline drift: expected {expected_baseline} symmetry "
            f"hypotheses, observed {len(baseline_symmetry)}"
        )

    mutated_combined = copy.deepcopy(combined)
    mutation = case.get("mutation")
    if not isinstance(mutation, dict):
        raise ValueError(f"case {case_id} mutation must be an object")
    mutation_result = apply_mutation(mutated_combined, mutation)
    mutated_document = normalized_ast_document(mutated_combined)
    mutated_bytes = canonical_ast_bytes(mutated_document)
    mutated_ast_path = mutated_directory / f"{case_id}-mutated.ast.json"
    mutated_ast_path.write_bytes(mutated_bytes)

    mutated_scanner = SolcAstCandidateScanner()
    mutated_hypotheses = mutated_scanner.scan_file(mutated_ast_path, target_root)
    mutated_symmetry = [
        item
        for item in mutated_hypotheses
        if item.generator.startswith("symmetry-analysis:")
    ]

    baseline_summaries = _summaries(baseline_document, target_root)
    mutated_summaries = _summaries(mutated_document, target_root)
    pair = case.get("pair")
    if not isinstance(pair, dict):
        raise ValueError(f"case {case_id} pair must be an object")
    left_id = _required_integer(pair, "left_operation_id", f"case {case_id} pair")
    right_id = _required_integer(pair, "right_operation_id", f"case {case_id} pair")
    expected_generator = _required_string(
        pair, "expected_generator", f"case {case_id} pair"
    )
    baseline_left = _summary(baseline_summaries, left_id, case_id)
    baseline_right = _summary(baseline_summaries, right_id, case_id)
    mutated_left = _summary(mutated_summaries, left_id, case_id)
    mutated_right = _summary(mutated_summaries, right_id, case_id)

    observation = case.get("observation")
    if not isinstance(observation, dict):
        raise ValueError(f"case {case_id} observation must be an object")
    observed_id = _required_integer(
        observation, "operation_id", f"case {case_id} observation"
    )
    field = _required_string(observation, "field", f"case {case_id} observation")
    if field not in FACT_FIELDS:
        raise ValueError(f"case {case_id} observation field is unsupported: {field}")
    value = _required_string(observation, "value", f"case {case_id} observation")
    baseline_observed = _summary(baseline_summaries, observed_id, case_id)
    mutated_observed = _summary(mutated_summaries, observed_id, case_id)
    baseline_facts = getattr(baseline_observed, field)
    mutated_facts = getattr(mutated_observed, field)
    reached = value in baseline_facts
    triggered = reached and value not in mutated_facts

    exact_pair_hypotheses = SymmetryAnalyzer().analyze([mutated_left, mutated_right])
    exact_generators = sorted({item.generator for item in exact_pair_hypotheses})
    detected = expected_generator in exact_generators
    if detected and not triggered:
        raise ValueError(
            f"case {case_id} reports detection without a triggered semantic mutation"
        )

    inverse = _inverse_match(mutated_left.name, mutated_right.name)
    relation = inverse[0].label if inverse is not None else None
    paired = bool(
        inverse is not None
        and mutated_left.dialect == mutated_right.dialect
        and mutated_left.module == mutated_right.module
    )
    return {
        "case_id": case_id,
        "repository": repository,
        "baseline_ast_sha256": baseline_sha256,
        "mutated_ast_sha256": hashlib.sha256(mutated_bytes).hexdigest(),
        "mutation": mutation_result,
        "pair": {
            "left": _summary_record(baseline_left, mutated_left),
            "right": _summary_record(baseline_right, mutated_right),
            "relation": relation,
            "paired": paired,
            "expected_generator": expected_generator,
            "observed_generators": exact_generators,
        },
        "observation": {
            "operation_id": f"solc:{observed_id}",
            "field": field,
            "value": value,
            "baseline_present": value in baseline_facts,
            "mutated_present": value in mutated_facts,
        },
        "magma": {
            "reached": reached,
            "triggered": triggered,
            "detected": detected,
        },
        "baseline_symmetry_hypotheses": len(baseline_symmetry),
        "mutated_symmetry_hypotheses": len(mutated_symmetry),
        "mutated_symmetry_generators": sorted(
            {item.generator for item in mutated_symmetry}
        ),
        "warnings": sorted(set(baseline_scanner.warnings + mutated_scanner.warnings)),
    }


def run_measurement(
    workspace: Path,
    manifest_path: Path,
    output_path: Path,
    mutated_directory: Path | None = None,
) -> dict[str, object]:
    workspace = workspace.resolve(strict=True)
    if not stat.S_ISDIR(workspace.lstat().st_mode) or workspace.is_symlink():
        raise ValueError("measurement workspace must be a non-symlink directory")
    manifest = _load_json_object(manifest_path, "mutation manifest")
    if manifest.get("schema_version") != "1.0.0":
        raise ValueError("mutation manifest schema_version must be 1.0.0")
    raw_cases = manifest.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("mutation manifest must contain at least one case")
    cases: list[dict[str, object]] = []
    identifiers: set[str] = set()
    for raw_case in raw_cases:
        if not isinstance(raw_case, dict):
            raise ValueError("every mutation case must be an object")
        case_id = _required_string(raw_case, "case_id", "case")
        if case_id in identifiers:
            raise ValueError(f"duplicate mutation case id: {case_id}")
        identifiers.add(case_id)
        cases.append(raw_case)

    if mutated_directory is None:
        with tempfile.TemporaryDirectory(prefix="nirvana-symmetry-mutations-") as directory:
            result = _measure_all(workspace, cases, Path(directory))
    else:
        mutated_directory.mkdir(parents=True, exist_ok=True)
        if mutated_directory.is_symlink() or not stat.S_ISDIR(
            mutated_directory.lstat().st_mode
        ):
            raise ValueError("mutated AST output must be a non-symlink directory")
        result = _measure_all(workspace, cases, mutated_directory)
    atomic_write_json(output_path, result)
    return result


def _measure_all(
    workspace: Path,
    cases: list[dict[str, object]],
    mutated_directory: Path,
) -> dict[str, object]:
    results = [measure_case(workspace, case, mutated_directory) for case in cases]
    reached = sum(bool(item["magma"]["reached"]) for item in results)
    triggered = sum(bool(item["magma"]["triggered"]) for item in results)
    detected = sum(bool(item["magma"]["detected"]) for item in results)
    if not (detected <= triggered <= reached <= len(results)):
        raise ValueError("measurement violates detected subset triggered subset reached")
    return {
        "schema_version": "1.0.0",
        "cases": results,
        "summary": {
            "repositories": len(results),
            "baseline_symmetry_hypotheses": sum(
                int(item["baseline_symmetry_hypotheses"]) for item in results
            ),
            "reached": reached,
            "triggered": triggered,
            "detected": detected,
            "detection_fraction": f"{detected}/{len(results)}",
        },
    }


def _summaries(
    document: dict[str, object], target_root: Path
) -> list[OperationSummary]:
    sources = document.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("normalized AST document lacks sources")
    source_units: list[tuple[str, dict[str, object], bytes]] = []
    for source_name, source_record in sorted(sources.items()):
        if not isinstance(source_name, str) or not isinstance(source_record, dict):
            continue
        ast = source_record.get("ast")
        if not isinstance(ast, dict):
            continue
        source_path = _regular_source_path(target_root, source_name)
        source_units.append((source_name, ast, source_path.read_bytes()))
    summaries, truncated = _compiler_operation_summaries(source_units)
    if truncated:
        raise ValueError("interprocedural summary closure was truncated")
    return summaries


def _summary(
    summaries: list[OperationSummary], declaration_id: int, case_id: str
) -> OperationSummary:
    operation_id = f"solc:{declaration_id}"
    matches = [item for item in summaries if item.operation_id == operation_id]
    if len(matches) != 1:
        raise ValueError(
            f"case {case_id} operation {operation_id} is not uniquely available"
        )
    return matches[0]


def _summary_record(
    baseline: OperationSummary, mutated: OperationSummary
) -> dict[str, object]:
    return {
        "operation_id": baseline.operation_id,
        "module": baseline.module,
        "name": baseline.name,
        "baseline": {
            "state_writes": sorted(baseline.state_writes),
            "guards": sorted(baseline.guards),
            "effects": sorted(baseline.effects),
        },
        "mutated": {
            "state_writes": sorted(mutated.state_writes),
            "guards": sorted(mutated.guards),
            "effects": sorted(mutated.effects),
        },
    }


def _unique_function(
    combined: dict[str, object], function_id: int
) -> tuple[str, dict[str, object]]:
    sources = combined.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("combined-json input lacks sources")
    matches: list[tuple[str, dict[str, object]]] = []
    for source_name, source_record in sources.items():
        if not isinstance(source_name, str) or not isinstance(source_record, dict):
            continue
        ast = source_record.get("AST")
        if not isinstance(ast, dict):
            continue
        for node in _walk_ast(ast):
            if (
                node.get("nodeType") == "FunctionDefinition"
                and node.get("id") == function_id
            ):
                matches.append((source_name, node))
    if len(matches) != 1:
        raise ValueError(
            f"function declaration {function_id} is not uniquely available"
        )
    return matches[0]


def _state_ids_by_name(combined: dict[str, object], state_name: str) -> set[int]:
    sources = combined.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("combined-json input lacks sources")
    matches = {
        int(node["id"])
        for source_record in sources.values()
        if isinstance(source_record, dict)
        and isinstance(source_record.get("AST"), dict)
        for node in _walk_ast(source_record["AST"])
        if node.get("nodeType") == "VariableDeclaration"
        and node.get("stateVariable") is True
        and node.get("name") == state_name
        and isinstance(node.get("id"), int)
    }
    if not matches:
        raise ValueError(f"state declaration is not available: {state_name}")
    return matches


def _unique_guard_node(
    function: dict[str, object], node_src: str, category: str
) -> dict[str, object]:
    candidates: list[dict[str, object]] = []
    modifiers = function.get("modifiers")
    if isinstance(modifiers, list):
        for modifier in modifiers:
            if not isinstance(modifier, dict) or modifier.get("src") != node_src:
                continue
            words = _modifier_words({"modifiers": [modifier]})
            if category in classify_guard_text(" ".join(sorted(words))):
                candidates.append(modifier)
    body = function.get("body")
    if isinstance(body, dict):
        for condition in _guard_conditions(list(_walk_ast(body))):
            if condition.get("src") != node_src:
                continue
            words = _condition_words(condition)
            if category in classify_guard_text(" ".join(sorted(words))):
                candidates.append(condition)
    if len(candidates) != 1:
        raise ValueError(
            f"guard {category!r} at {node_src} is not uniquely available"
        )
    return candidates[0]


def _unique_descendant(
    root: object,
    predicate: Callable[[object], bool],
    label: str,
) -> dict[str, object]:
    matches = [
        node
        for node in _walk_ast(root)
        if predicate(node) and isinstance(node, dict)
    ]
    if len(matches) != 1:
        raise ValueError(f"{label} is not uniquely available")
    return matches[0]


def _remove_enclosing_node(
    function: dict[str, object], target: dict[str, object]
) -> dict[str, object]:
    path = _path_to(function, target)
    for item in reversed(path):
        if (
            isinstance(item.node, dict)
            and item.node.get("nodeType") in REMOVABLE_NODE_TYPES
            and isinstance(item.parent, list)
            and isinstance(item.key, int)
        ):
            removed = item.parent.pop(item.key)
            if not isinstance(removed, dict):
                raise ValueError("selected AST mutation did not remove an object")
            return removed
    raise ValueError("selected AST node has no removable statement or modifier ancestor")


def _path_to(root: object, target: object) -> list[_NodePathItem]:
    stack: list[tuple[object, object | None, str | int | None, list[_NodePathItem]]] = [
        (root, None, None, [])
    ]
    visited = 0
    while stack:
        node, parent, key, prefix = stack.pop()
        visited += 1
        if visited > 2_000_000:
            raise ValueError("solc AST exceeds the two-million-node safety limit")
        path = [*prefix, _NodePathItem(node, parent, key)]
        if node is target:
            return path
        if isinstance(node, dict):
            stack.extend(
                (value, node, child_key, path)
                for child_key, value in reversed(list(node.items()))
            )
        elif isinstance(node, list):
            stack.extend(
                (value, node, index, path)
                for index, value in reversed(list(enumerate(node)))
            )
    raise ValueError("selected AST node is outside the function")


def _regular_workspace_file(workspace: Path, value: str, label: str) -> Path:
    path = _workspace_path(workspace, value, label)
    item_stat = path.lstat()
    if stat.S_ISLNK(item_stat.st_mode) or not stat.S_ISREG(item_stat.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    if item_stat.st_size > MAX_DOCUMENT_BYTES:
        raise ValueError(f"{label} exceeds the 100 MB safety limit")
    return path


def _workspace_directory(workspace: Path, value: str, label: str) -> Path:
    path = _workspace_path(workspace, value, label)
    if path.is_symlink() or not stat.S_ISDIR(path.lstat().st_mode):
        raise ValueError(f"{label} must be a non-symlink directory")
    return path


def _workspace_path(workspace: Path, value: str, label: str) -> Path:
    relative = Path(value)
    if relative.is_absolute() or not relative.parts or ".." in relative.parts:
        raise ValueError(f"{label} must be a safe relative path")
    current = workspace
    for part in relative.parts:
        current = current / part
        current_stat = current.lstat()
        if stat.S_ISLNK(current_stat.st_mode):
            raise ValueError(f"{label} path must not contain symlinks")
    return current


def _load_json_object(path: Path, label: str) -> dict[str, object]:
    item_stat = path.lstat()
    if stat.S_ISLNK(item_stat.st_mode) or not stat.S_ISREG(item_stat.st_mode):
        raise ValueError(f"{label} must be a regular non-symlink file")
    if item_stat.st_size > MAX_DOCUMENT_BYTES:
        raise ValueError(f"{label} exceeds the 100 MB safety limit")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except RecursionError as error:
        raise ValueError(f"{label} exceeds the nesting limit") from error
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be one JSON object")
    return value


def _required_string(value: dict[str, object], key: str, label: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item.strip():
        raise ValueError(f"{label} {key} must be a non-empty string")
    return item


def _required_integer(value: dict[str, object], key: str, label: str) -> int:
    item = value.get(key)
    if not isinstance(item, int) or isinstance(item, bool):
        raise ValueError(f"{label} {key} must be an integer")
    return item


def _required_sha256(value: dict[str, object], key: str, label: str) -> str:
    item = _required_string(value, key, label).lower()
    if len(item) != 64 or any(character not in "0123456789abcdef" for character in item):
        raise ValueError(f"{label} {key} must be a lowercase SHA-256 digest")
    return item


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Inject pinned Solidity AST asymmetries and measure reached, triggered, "
            "and detected symmetry outcomes"
        )
    )
    parser.add_argument("workspace", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--mutated-directory",
        type=Path,
        help="retain canonical baseline and mutated ASTs in this directory",
    )
    args = parser.parse_args()
    result = run_measurement(
        args.workspace,
        args.manifest,
        args.output,
        args.mutated_directory,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
