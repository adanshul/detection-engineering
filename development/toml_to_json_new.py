import requests
import os
import tomllib

url = "https://8d7b9aa7e1424c6e9c1a1e71a8c2425c.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules"
api_key = os.environ['ELASTIC_KEY']
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}

for root, dirs, files in os.walk("detections/"):
    for file in files:
        if file.endswith(".toml"):
            full_path = os.path.join(root, file)
            print(full_path)
            with open(full_path, "rb") as toml_file:
                alert = tomllib.load(toml_file)

                # Initialize the data dictionary
                data = {}

                # Check the rule type and set required fields accordingly
                if alert['rule']['type'] == "query":  # query-based alert
                    required_fields = ['author', 'description', 'name',  'rule_id',  'risk_score', 'severity', 'type', 'query', 'threat']
                elif alert['rule']['type'] == "eql":  # event correlation alert
                    required_fields = ['author', 'description', 'name', 'rule_id',  'risk_score', 'severity', 'type', 'query', 'language', 'threat']
                elif alert['rule']['type'] == "threshold":  # threshold-based alert
                    required_fields = ['author', 'description', 'name',  'rule_id', 'risk_score', 'severity', 'type', 'query', 'threshold', 'threat']
                else:
                    print("Unsupported rule type found in: " + full_path)
                    continue

                # Populate the data dictionary with required fields
                for field in required_fields:
                    if field in alert['rule']:
                        data[field] = alert['rule'][field]

                # Add the 'enabled' field
                data['enabled'] = True

                # Print the data dictionary (JSON equivalent) for debugging
                print(data)

                # Send the data dictionary as JSON
                response = requests.post(url, headers=headers, json=data)
                elastic_data = response.json()
                print(elastic_data)
