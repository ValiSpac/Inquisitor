DOCKER := docker compose
DOCKER_DIR := ./docker_test/docker-compose.yml
PYTHON_VENV := venv

all:
	@python3 -m venv ${PYTHON_VENV}
	@${PYTHON_VENV}/bin/pip3 install -r requirements.txt
	@sysctl -w net.ipv4.ip_forward=1
	@${DOCKER} -f $(DOCKER_DIR) build
	@${DOCKER} -f $(DOCKER_DIR) up -d
	@docker ps -q | xargs -L 1 docker logs
	@echo "Now you can run source venv/bin/activate and then sudo inquisitor.py"

up-no-detached:
	@${DOCKER} -f $(DOCKER_DIR) up

down:
	@${DOCKER} -f $(DOCKER_DIR) down

clean:
	@docker rm -vf $$(docker ps -aq) & sleep 1
	@docker rmi -f $$(docker images -aq) & sleep 1

fclean: clean
	@rm -rf ${PYTHON_VENV}

.PHONY: all down fclean
