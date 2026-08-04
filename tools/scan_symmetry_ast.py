from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from nirvana.evm import SolcAstCandidateScanner


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Measure Nirvana symmetry hypotheses from solc combined-json AST output"
    )
    parser.add_argument("repository", type=Path)
    parser.add_argument("combined_json", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    combined = json.loads(args.combined_json.read_text(encoding="utf-8"))
    sources = combined.get("sources")
    if not isinstance(sources, dict):
        raise ValueError("combined-json document lacks a sources object")
    ast_document = {
        "sources": {
            source_name: {"ast": source_record["AST"]}
            for source_name, source_record in sources.items()
            if isinstance(source_name, str)
            and isinstance(source_record, dict)
            and isinstance(source_record.get("AST"), dict)
        }
    }
    ast_bytes = (
        json.dumps(ast_document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    ast_path = args.output.with_suffix(".ast.json")
    ast_path.write_bytes(ast_bytes)

    scanner = SolcAstCandidateScanner()
    hypotheses = scanner.scan_file(ast_path, args.repository)
    result = {
        "ast_sha256": hashlib.sha256(ast_bytes).hexdigest(),
        "source_units": len(ast_document["sources"]),
        "all_hypotheses": len(hypotheses),
        "symmetry_hypotheses": [
            {
                "hypothesis_id": item.hypothesis_id,
                "generator": item.generator,
                "suspected_violation": item.suspected_violation,
                "locations": [
                    {
                        "path": location.path,
                        "line": location.line_start,
                        "symbol": location.symbol,
                    }
                    for location in item.candidate_locations
                ],
            }
            for item in hypotheses
            if item.generator.startswith("symmetry-analysis:")
        ],
        "warnings": scanner.warnings,
    }
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
