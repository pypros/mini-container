.PHONY: run test rm mypy lint

IMAGE ?= alpine:latest

# Run the container
# Usage: make run [image-name] (e.g., make run ubuntu:latest)
run:
	@ARGS="$(filter-out $@,$(MAKECMDGOALS))"; \
	if [ -z "$$ARGS" ]; then \
		ARGS="$(IMAGE)"; \
	fi; \
	echo "--- Running Container ---"; \
	sudo python3 -m src.docker_tool.docker run -it $$ARGS

# Run all tests
test:
	@echo "--- Running Tests ---"
	python3 -m unittest discover -b tests

# Run mypy type checking
mypy:
	@echo "--- Running mypy type checking ---"
	venv/bin/mypy src/

# Run ruff linting and formatting
lint:
	@echo "--- Running ruff linting ---"
	venv/bin/ruff check --fix src/
	venv/bin/ruff format src/
	venv/bin/ruff check src/

# Clean up leftover resources
# This is a manual cleanup command.
rm:
	@ARGS="$(filter-out $@,$(MAKECMDGOALS))"; \
	if [ -z "$$ARGS" ]; then \
		ARGS="$(IMAGE)"; \
	fi; \
	echo "--- Cleaning up resources ---"; \
	sudo python3 -m src.docker_tool.docker rm $$ARGS

%:
	@:
