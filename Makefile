.PHONY: test check audit-fixture

test:
	PYTHONPATH=src python3 -m unittest discover -s tests -v

check:
	PYTHONPATH=src python3 -m compileall -q src tests
	PYTHONPATH=src python3 -m unittest discover -s tests -v
	python3 -m json.tool schemas/common.schema.json >/dev/null
	python3 -m json.tool schemas/hypothesis.schema.json >/dev/null
	python3 -m json.tool schemas/evidence.schema.json >/dev/null
	python3 -m json.tool schemas/execution-request.schema.json >/dev/null
	python3 -m json.tool schemas/execution-receipt.schema.json >/dev/null
	python3 -m json.tool schemas/finding.schema.json >/dev/null
	python3 -m json.tool schemas/differential-report.schema.json >/dev/null

audit-fixture:
	PYTHONPATH=src python3 -m nirvana audit tests/fixtures/evm --output nirvana-runs
