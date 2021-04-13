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
ignore_yaml_path = '/opt/scan-parser/ignore.yml'

print('Loading ignored vulnerabilities file')
# Make sure the ignore file exists we one was specified
if os.path.exists(ignore_yaml_path) is True:

    # Load the details of ignored vulnerabilities
    try:
        with open(ignore_yaml_path) as scan_config_file:
            print('Reading YAML')
            ignore_yaml = yaml.load(scan_config_file.read(), Loader=yaml.FullLoader)
            print(ignore_yaml)
            # Setup arrays with severity levels that we are tracking
            for severity in severities:
                vulnerabilities_by_severity[str(severity).upper()] = []
                alerts_by_severity[str(severity).upper()] = []
                alerts_ignored_by_severity[str(severity).upper()] = []

            # Store the ignored vulnerabilities by their ID
            if 'ignored_vulnerabilities' in ignore_yaml.keys():
                for ignored_vulnerability in ignore_yaml['ignored_vulnerabilities']:
                    # Only interested in non-expired ignore directives
                    if ignored_vulnerability['expiry'] >= datetime.now().date():
                        ignored_vulnerabilities_by_id[str(ignored_vulnerability['id']).upper()] = ignored_vulnerability
    except Exception as exception:
        print('ERROR: Failed to parse ignore YAML file ({exception})')
        exit(1)

# Parse scan results and generated alerts where applicable
if os.path.exists('./scan-results.json') is False:
    print('ERROR: Could not load scan results')
    exit(1)

print('Ignored vulnerabilities')
print(ignored_vulnerabilities_by_id)

print('Loading scan results')
with open('./scan-results.json') as scan_results_file:
    scan_results_raw = scan_results_file.read().strip()
    scan_results = json.loads(scan_results_raw)
    for vulnerability in scan_results[0]['vulnerabilities']:
        vulnerability_id = str(vulnerability['vulnerability']).upper()
        severity = str(vulnerability['severity']).upper()
        if severity in vulnerabilities_by_severity.keys():
            if vulnerability_id in ignored_vulnerabilities_by_id.keys():
                print(f'Ignoring CVE: {vulnerability_id}')
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
if 'OPSGENIE_API_KEY' in os.environ.keys() and len(os.environ["OPSGENIE_API_KEY"].strip()) > 0:
    if count > 0:
        try:
            print('Raising OpsGenie alert')
            if 'OPSGENIE_ALERT_TEAMS' not in os.environ.keys():
                print('ERROR: No OPSGENIE_ALERT_TEAMS value specified')
                exit(1)
            opsgenie_configuration = opsgenie_sdk.configuration.Configuration()
            opsgenie_configuration.api_key['Authorization'] = os.environ['OPSGENIE_API_KEY']
            opsgenie_api_client = opsgenie_sdk.api_client.ApiClient(configuration=opsgenie_configuration)
            opsgenie_alert_api = opsgenie_sdk.AlertApi(api_client=opsgenie_api_client)
            if 'OPSGENIE_ALERT_PREFIX' not in os.environ.keys():
                os.environ['OPSGENIE_ALERT_PREFIX'] = ''
            opsgenie_alert_prefix = os.environ["OPSGENIE_ALERT_PREFIX"].strip()
            opsgenie_alert_teams = os.environ["OPSGENIE_ALERT_TEAMS"].strip().split(',')
            if 'OPSGENIE_ALERT_LEVEL' not in os.environ.keys():
                os.environ['OPSGENIE_ALERT_LEVEL'] = 'P3'
            opsgenie_alert_level = os.environ["OPSGENIE_ALERT_LEVEL"].strip().upper()
            if 'OPSGENIE_ENTITY' not in os.environ.keys():
                os.environ['OPSGENIE_ENTITY'] = 'GitHub Actions'
            opsgenie_entity = os.environ["OPSGENIE_ENTITY"].strip()
            alert_hash = hashlib.md5(f'{opsgenie_alert_prefix}\n{alert_content}'.encode('utf-8')).hexdigest()

            if len(opsgenie_alert_level) == 0:
                opsgenie_alert_level = 'P3'
            if len(opsgenie_entity) == 0:
                opsgenie_entity = 'GitHub Actions'
            if len(opsgenie_alert_prefix) > 0:
                opsgenie_alert_prefix = f'{opsgenie_alert_prefix}: '

            # If an invalid alert level was specified error out
            if opsgenie_alert_level not in ('P1', 'P2', 'P3', 'P4', 'P5'):
                print('WARNING: Invalid OpsGenie alert level specified')
                exit(1)

            # Setup responders
            responders = []
            for opsgenie_alert_team in opsgenie_alert_teams:
                print(f'Adding team: {opsgenie_alert_team}')
                responders.append({
                    'type': 'team',
                    'name': opsgenie_alert_team
                })

            print('Creating alert payload')
            alert_payload = opsgenie_sdk.CreateAlertPayload(
                message=f'{opsgenie_alert_prefix}{count} Container vulnerabilities identified',
                alias=alert_hash,
                description=alert_content,
                responders=responders,
                entity=opsgenie_entity,
                priority=opsgenie_alert_level
            )

            opsgenie_response = opsgenie_alert_api.create_alert(create_alert_payload=alert_payload)
            print(opsgenie_response)
        except Exception as exception:
            print(f'ERROR: Failed to raise OpsGenie alert ({exception})')
            exit(1)

if count > 0:
    print(alert_content)
    print(f'WARNING: {count} vulnerabilities were identified in container image, please review items listed above and take appropriate action.')
