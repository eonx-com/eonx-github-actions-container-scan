#!/usr/bin/env bash
set -eo pipefail

export CONTAINER="${1}"
export DOCKER_COMPOSE_YAML_PATH="${2}"
export IGNORE_YAML_PATH="${3}"
export OPSGENIE_API_KEY="${4}"
export OPSSGENIE_ALERT_PREFIX="${5}"
export OPSSGENIE_ALERT_TEAMS="${6}"
export OPSSGENIE_ALERT_LEVEL="${7}"
export OPSSGENIE_ENTITY="${8}"
export ALERT_DEFCON1="${9}"
export ALERT_CRITICAL="${10}"
export ALERT_HIGH="${11}"
export ALERT_MEDIUM="${12}"
export ALERT_LOW="${13}"
export ALERT_NEGLIGIBLE="${14}"
export ALERT_UNKNOWN="${15}"
export DOCKER_BASE_IMAGE_REPOSITORY="${16}"
export DOCKER_BASE_IMAGE="${17}"
export DOCKER_BASE_IMAGE_REPOSITORY_USERNAME="${18}"
export DOCKER_BASE_IMAGE_REPOSITORY_PASSWORD="${19}"

if [[ ! -f "${DOCKER_COMPOSE_YAML_PATH}" ]]; then
  echo "ERROR: The requested docker-compose.yml file (${DOCKER_COMPOSE_YAML_PATH}) could not be found";
  exit 1;
fi

if [[ ! -f "${IGNORE_YAML_PATH}" ]]; then
  if [[ ! -z "${IGNORE_YAML_PATH}" ]]; then
    echo "WARNING: The requested ignore file (${IGNORE_YAML_PATH}) could not be found";
  fi
  export IGNORE_YAML_PATH=""
fi

if [[ ! -z "${DOCKER_BASE_IMAGE_REPOSITORY}" ]]; then
  echo "Pulling base Docker image: ${DOCKER_BASE_IMAGE_REPOSITORY}/${DOCKER_BASE_IMAGE}";
  echo "${DOCKER_BASE_IMAGE_REPOSITORY_PASSWORD}" | docker login "${DOCKER_BASE_IMAGE_REPOSITORY}" --username ${DOCKER_BASE_IMAGE_REPOSITORY_USERNAME} --password-stdin
  docker pull "${DOCKER_BASE_IMAGE_REPOSITORY}/${DOCKER_BASE_IMAGE}"
fi

./scripts/docker-compose.sh build ${REPOSITORY}
docker-compose -f ./docker/clair/docker-compose.yaml run --rm scanner eonx/payment-gateway-${REPOSITORY}:latest >scan-results.json || true
./docker/containers/scan.py
