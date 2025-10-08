.PHONY: run test rm

IMAGE ?= alpine:latest

# Run the container
# Usage: make run IMAGE=ubuntu:latest
run:
	@echo "--- Running Container ---"
	sudo python3 -m src.docker_tool.docker run -it $(IMAGE)

# Run all tests
test:
	@echo "--- Running Tests ---"
	python3 -m unittest discover -b tests

# Clean up leftover resources
# This is a manual cleanup command.
rm:
	@echo "--- Cleaning up resources ---"
	sudo python3 -m src.docker_tool.docker rm
