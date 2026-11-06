PYTHONPATH := src
export PYTHONPATH

.PHONY: test demo evaluate check simulate

test:
	python3 -m pytest -q

demo:
	python3 -m privacy_gateway demo

evaluate:
	python3 -m privacy_gateway evaluate

check:
	python3 -m privacy_gateway check --role guest --service chat --text "My SSN is 123-45-6789"

simulate:
	python3 -m privacy_gateway.simulator run
