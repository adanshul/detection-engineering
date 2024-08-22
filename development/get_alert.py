import requests

url = "https://8d7b9aa7e1424c6e9c1a1e71a8c2425c.us-central1.gcp.cloud.es.io:9243/api/detection_engine/rules?rule_id="
id = "2f2f4939-0b34-40c2-a0a3-844eb7889f43"
full_path = url + id

api_key = "ajZFZ2JwRUJpZE0zQl92TW1ZaG06TGlvbWgyR2VRNHVWcHNxQkwtQVRpZw=="
headers = {
    'Content-Type': 'application/json;charset=UTF-8',
    'kbn-xsrf': 'true',
    'Authorization': 'ApiKey ' + api_key
}


response = requests.get(full_path, headers=headers)
elastic_data = response.json()  # Use parentheses to call the json() method
print(elastic_data)
