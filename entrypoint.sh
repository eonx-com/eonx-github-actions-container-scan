#!/usr/bin/env bash
set -eo pipefail

export CONTAINER_ID="${1}"
export CONTAINER_IMAGE="${2}"
export DOCKER_COMPOSE_YAML_PATH="${3}"
export IGNORE_YAML_PATH="${4}"
export OPSGENIE_API_KEY="${5}"
export OPSGENIE_ALERT_PREFIX="${6}"
export OPSGENIE_ALERT_TEAMS="${7}"
export OPSGENIE_ALERT_LEVEL="${8}"
export OPSGENIE_ENTITY="${9}"
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
export COMPOSER_PRIVATE_TOKEN="${21}"

if [[ ! -f "${DOCKER_COMPOSE_YAML_PATH}" ]]; then
  echo "ERROR: The requested docker-compose.yml file (${DOCKER_COMPOSE_YAML_PATH}) could not be found"
  exit 1
fi

echo "Ignore file: ${IGNORE_YAML_PATH}";
if [[ ! -z "${IGNORE_YAML_PATH}" ]]; then
  if [[ ! -f "${IGNORE_YAML_PATH}" ]]; then
    echo "WARNING: The requested ignore file (${IGNORE_YAML_PATH}) could not be found"
  else
    cat ${IGNORE_YAML_PATH};
    cp ${IGNORE_YAML_PATH} /opt/scan-parser/ignore.yml
  fi
fi

if [[ ! -z "${DOCKER_BASE_IMAGE_REPOSITORY}" ]]; then
  echo "Pulling base Docker image: ${DOCKER_BASE_IMAGE_REPOSITORY}/${DOCKER_BASE_IMAGE}"
  echo "${DOCKER_BASE_IMAGE_REPOSITORY_PASSWORD}" | docker login "${DOCKER_BASE_IMAGE_REPOSITORY}" --username ${DOCKER_BASE_IMAGE_REPOSITORY_USERNAME} --password-stdin
  docker pull "${DOCKER_BASE_IMAGE_REPOSITORY}/${DOCKER_BASE_IMAGE}"
fi

# Build the container
echo "Building container"
docker-compose -f "${DOCKER_COMPOSE_YAML_PATH}" build "${CONTAINER_ID}"

# Scan the resulting image
echo "Scanning image"
docker pull arminc/clair-db:latest
docker pull arminc/clair-local-scan:v2.0.5
docker pull quay.io/usr42/clair-container-scan:latest
docker-compose -f /opt/clair/docker-compose.yaml run --rm scanner "${CONTAINER_IMAGE}" >scan-results-raw.json 2>/tmp/stderr.log || true
cat scan-results-raw.json | jq -r . >scan-results.json

# Parse the scan results and generated OpsGenie alerts (if applicable)
echo "Parsing scan results"
/opt/scan-parser/main.py
exit 0
