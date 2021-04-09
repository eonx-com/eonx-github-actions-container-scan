#!/usr/bin/env python3
import hashlib
import json
import opsgenie_sdk
import os
import yaml

from datetime import datetime

vulnerabilities_by_severity = {}
alerts_by_severity = {}
alerts_ignored_by_severity = {}
ignored_vulnerabilities_by_id = {}

# Create an array of severities that will trigger alerts
severities = []
truthy = ('true', '1', 'yes', 'y')
if str(os.environ['ALERT_DEFCON1']).strip().lower() in truthy:
    severities.append('defcon1')
if str(os.environ['ALERT_CRITICAL']).strip().lower() in truthy:
    severities.append('critical')
if str(os.environ['ALERT_HIGH']).strip().lower() in truthy:
    severities.append('high')
if str(os.environ['ALERT_MEDIUM']).strip().lower() in truthy:
    severities.append('medium')
if str(os.environ['ALERT_LOW']).strip().lower() in truthy:
    severities.append('low')
if str(os.environ['ALERT_NEGLIGIBLE']).strip().lower() in truthy:
    severities.append('negligible')
if str(os.environ['ALERT_UNKNOWN']).strip().lower() in truthy:
    severities.append('unknown')

# Make sure at least one severity level is selected
if len(severities) == 0:
    print('ERROR: No alert levels were selected, at least one alert level must be set to true')
    exit(1)

# Load any ignored alert details
ignore_yaml_path = os.environ['IGNORE_YAML_PATH'].strip()

if len(ignore_yaml_path) > 0:
    # Make sure the ignore file exists we one was specified
    if os.path.exists(ignore_yaml_path) is False:
        print(f'ERROR: Ignore file ({ignore_yaml_path}) could not be found')
        exit(1)

    # Load the details of ignored vulnerabilities
    try:
        with open(ignore_yaml_path) as scan_config_file:
            ignore_yaml = yaml.load(scan_config_file.read(), Loader=yaml.FullLoader)

            # Setup arrays with severity levels that we are tracking
            for severity in severities:
                vulnerabilities_by_severity[str(severity).upper()] = []
                alerts_by_severity[str(severity).upper()] = []
                alerts_ignored_by_severity[str(severity).upper()] = []

            # Store the ignored vulnerabilities by their ID
            if 'ignored_vulnerabilities' in ignore_yaml.keys():
                for ignored_vulnerability in ignore_yaml['ignored_vulnerabilities']:
                    # Only interested in non-expired ignore directives
                    if ignored_vulnerability['expiry'] <= datetime.now().date():
                        ignored_vulnerabilities_by_id[str(ignored_vulnerability['id']).upper()] = ignored_vulnerability

    except Exception as exception:
        print('ERROR: Failed to parse ignore YAML file ({exception})')
        exit(1)

# Parse scan results and generated alerts where applicable
if os.path.exists('./scan-results.json') is False:
    print('ERROR: Could not load scan results')
    exit(1)

with open('./scan-results.json') as scan_results_file:
    scan_results = json.loads(scan_results_file.read())
    for vulnerability in scan_results[0]['vulnerabilities']:
        vulnerability_id = str(vulnerability['vulnerability']).upper()
        severity = str(vulnerability['severity']).upper()
        if severity in vulnerabilities_by_severity.keys():
            if vulnerability_id in ignored_vulnerabilities_by_id.keys():
                alerts_ignored_by_severity[severity].append(vulnerability)
                continue
            alerts_by_severity[severity].append(vulnerability)

# Create output message
count = 0
alert_content = ''
if len(alerts_by_severity) > 0:
    for severity in alerts_by_severity:
        for vulnerability in alerts_by_severity[severity]:
            count += 1
            alert_content += f'{str(vulnerability["severity"]).upper()}: {vulnerability["vulnerability"]} ({vulnerability["featurename"]} {vulnerability["featureversion"]}) - {vulnerability["description"]}\n\n'

# Check if we should be raising an OpsGenie alert
if 'OPSGENIE_CONTAINER_SCAN_API_KEY' in os.environ.keys() and len(os.environ["OPSGENIE_CONTAINER_SCAN_API_KEY"].strip()) > 0:
    if count > 0:
        print('Raising OpsGenie alert')
        opsgenie_configuration = opsgenie_sdk.configuration.Configuration()
        opsgenie_configuration.api_key['Authorization'] = os.environ['OPSGENIE_CONTAINER_SCAN_API_KEY']
        opsgenie_api_client = opsgenie_sdk.api_client.ApiClient(configuration=opsgenie_configuration)
        opsgenie_alert_api = opsgenie_sdk.AlertApi(api_client=opsgenie_api_client)
        opsgenie_alert_prefix = os.environ["OPSGENIE_ALERT_PREFIX"].strip()
        opsgenie_alert_teams = os.environ["OPSGENIE_ALERT_TEAMS"].strip().split(',')
        opsgenie_alert_level = os.environ["OPSGENIE_ALERT_LEVEL"].strip().upper()
        opsgenie_entity = os.environ["OPSGENIE_ENTITY"].strip()
        alert_hash = hashlib.md5(f'{opsgenie_alert_prefix}\n{alert_content}'.encode('utf-8')).hexdigest()

        if len(opsgenie_entity) == 0:
            opsgenie_entity = 'GitHub Actions'
        if len(opsgenie_alert_level) == 0:
            opsgenie_alert_level = 'P3'
        if len(opsgenie_alert_prefix) > 0:
            opsgenie_alert_prefix = f'{opsgenie_alert_prefix}: '

        # If an invalid alert level was specified error out
        if opsgenie_alert_level not in ('P1', 'P2', 'P3', 'P4', 'P5'):
            print('WARNING: Invalid OpsGenie alert level specified')
            exit(1)

        # Setup responders
        responders = []
        for opsgenie_alert_team in opsgenie_alert_teams:
            responders.append({
                'type': 'team',
                'name': opsgenie_alert_team
            })

        alert_payload = opsgenie_sdk.CreateAlertPayload(
            message=f'{opsgenie_alert_prefix}{count} Container vulnerabilities identified',
            alias=alert_hash,
            description=alert_content,
            responders=responders,
            entity=opsgenie_entity,
            priority=opsgenie_alert_level
        )
        opsgenie_response = opsgenie_alert_api.create_alert(create_alert_payload=alert_payload)
        print(alert_content)

if count > 0:
    print(f'WARNING: {count} vulnerabilities were identified in container image, please review items listed above and take appropriate action.')
    exit(1)
