.PHONY: test check audit-fixture

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

check:
	PYTHONPATH=src python3 -m compileall -q src tests
	PYTHONPATH=src python3 -m unittest discover -s tests -v
	python3 -c 'import json, pathlib; [json.loads(path.read_text()) for path in pathlib.Path("schemas").glob("*.json")]'
	python3 -c 'import json, pathlib; [json.loads(path.read_text()) for path in pathlib.Path(".agents/skills/nirvana-audit/assets").glob("*.json")]'

audit-fixture:
	PYTHONPATH=src python3 -m nirvana audit tests/fixtures/evm --output nirvana-runs
