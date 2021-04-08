#!/usr/bin/env python3
import hashlib
import json
import os

import opsgenie_sdk
import yaml

from datetime import datetime

# Setup OpsGenie API
opsgenie_configuration = opsgenie_sdk.configuration.Configuration()
opsgenie_configuration.api_key['Authorization'] = os.environ['OPSGENIE_CONTAINER_SCAN_API_KEY']
opsgenie_api_client = opsgenie_sdk.api_client.ApiClient(configuration=opsgenie_configuration)
opsgenie_alert_api = opsgenie_sdk.AlertApi(api_client=opsgenie_api_client)

# Track vulnerabilities in a dictionary indexed by severity
vulnerabilities = {}
alerts = {}
alerts_ignored = {}

# Track any mitigated vulnerabilities so we dont raise alerts for them
mitigations = {}

# Retrieve scan config
if os.path.exists('./scan.yml') is False:
    print('ERROR: Scan configuration file not found')
    exit(1)
with open('./scan.yml') as scan_config_file:
    scan_config = yaml.load(scan_config_file.read(), Loader=yaml.FullLoader)
    if 'alert_levels' not in scan_config.keys():
        print('ERROR: Malformed scan configuration file')
        exit(1)
    for severity in scan_config['alert_levels']:
        vulnerabilities[str(severity).upper()] = []
        alerts[str(severity).upper()] = []
        alerts_ignored[str(severity).upper()] = []
    if 'mitigations' in scan_config.keys():
        for mitigation in scan_config['mitigations']:
            vulerability_id = str(mitigation['vulnerability']).upper()
            expiry = mitigation['expiry']
            if expiry <= datetime.now().date():
                mitigations[vulerability_id] = mitigation
if len(vulnerabilities) == 0:
    print('ERROR: No alert levels have been defined in container scanning configuration file')
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
        if severity in vulnerabilities.keys():
            if vulnerability_id in mitigations.keys():
                alerts_ignored[severity].append(vulnerability)
                continue
            alerts[severity].append(vulnerability)

alert_content = ''
count = 0
if len(alerts) > 0:
    for severity in alerts:
        if len(alerts[severity]) > 0:
            for vulnerability in alerts[severity]:
                count += 1
                alert_content += f'{str(vulnerability["severity"]).upper()}: {vulnerability["vulnerability"]} ({vulnerability["featurename"]} {vulnerability["featureversion"]}) - {vulnerability["description"]}\n\n'

if count > 0:
    print('Raising OpsGenie alert')
    alert_hash = hashlib.md5(f'{os.environ["SCAN_PROJECT"]}\n{alert_content}'.encode('utf-8')).hexdigest()
    alert_payload = opsgenie_sdk.CreateAlertPayload(
        message=f'{os.environ["SCAN_PROJECT"]}: {count} Container vulnerabilities identified',
        alias=f'container_vulnerabilities_{alert_hash}',
        description=alert_content,
        responders=[{
            'type': 'team',
            'name': 'ShitIsOnFire'
        }],
        entity='GitHub Actions',
        priority='P5'
    )
    opsgenie_response = opsgenie_alert_api.create_alert(create_alert_payload=alert_payload)
    print(alert_content)
    print(f'WARNING: {count} vulnerabilities were identified in container image, please review items listed above and take appropriate action.')
    exit(1)
