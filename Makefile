.PHONY: run test rm mypy lint install clean

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

# Install development dependencies
install:
	@echo "--- Installing development dependencies ---"
	python3 -m venv venv
	venv/bin/pip install -r requirements.txt

# Clean up build artifacts and cache
clean:
	@echo "--- Cleaning up ---"
	rm -rf venv/ .mypy_cache/ .ruff_cache/
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete 2>/dev/null || true
	find . -name "*.pyo" -delete 2>/dev/null || true
	find . -name "*.pyd" -delete 2>/dev/null || true
	find . -name ".coverage" -delete 2>/dev/null || true
	find . -name "*.cover" -delete 2>/dev/null || true
	find . -name "*.log" -delete 2>/dev/null || true
	rm -rf *.tar my_image_root/ .docker_temp/
	rm -rf build/ dist/ *.egg-info/
	rm -rf .pytest_cache/ .tox/ htmlcov/
