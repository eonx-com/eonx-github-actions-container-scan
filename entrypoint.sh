#!/usr/bin/env bash
set -eo pipefail

redirect_stderr() {
    if [ "$VERBOSE" = 1 ]; then
        "$@"
    else
        "$@" 2>/dev/null
    fi
}

redirect_all() {
    if [ "$VERBOSE" = 1 ]; then
        "$@"
    else
        "$@" 2>/dev/null >/dev/null
    fi
}

export CONTAINER_ID="${1}"
export CONTAINER_IMAGE="${2}"
export DOCKER_COMPOSE_YAML_PATH="${3}"
export IGNORE_YAML_PATH="${4}"
export OPSGENIE_API_KEY="${5}"
export OPSSGENIE_ALERT_PREFIX="${6}"
export OPSSGENIE_ALERT_TEAMS="${7}"
export OPSSGENIE_ALERT_LEVEL="${8}"
export OPSSGENIE_ENTITY="${9}"
export ALERT_DEFCON1="${10}"
export ALERT_CRITICAL="${11}"
export ALERT_HIGH="${12}"
export ALERT_MEDIUM="${13}"
export ALERT_LOW="${14}"
export ALERT_NEGLIGIBLE="${15}"
export ALERT_UNKNOWN="${16}"
export DOCKER_BASE_IMAGE_REPOSITORY="${17}"
export DOCKER_BASE_IMAGE="${18}"
export DOCKER_BASE_IMAGE_REPOSITORY_USERNAME="${19}"
export DOCKER_BASE_IMAGE_REPOSITORY_PASSWORD="${20}"

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

# Build the container
echo "Building container"
docker-compose -f "${DOCKER_COMPOSE_YAML_PATH}" build "${CONTAINER_ID}"

# Scan the resulting image
echo "Scanning image"
redirect_stderr docker-compose -f /opt/clair/docker-compose.yaml run --rm scanner "${CONTAINER_IMAGE}" > scan-results-raw.json || true
echo "xxx"
cat scan-results-raw.json
echo "xxx"
cat scan-results-raw.json | jq -r . > scan-results.json
return_value=$?
cat scan-results.json

# Parse the scan results and generated OpsGenie alerts (if applicable)
echo "Parsing scan results"
/opt/scan-parser/main.py

exit $return_value