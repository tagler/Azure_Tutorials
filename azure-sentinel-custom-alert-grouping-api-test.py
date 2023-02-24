import json
import requests

# api request test 
with requests.Session() as ses:
    resp = ses.post(
        url="http://127.0.0.1:5000", 
        data=json.dumps(
            {
                "scope" : "https://management.core.windows.net/",
                "api_base_url" : "https://management.azure.com",
                "subscription_id" : "YOUR_SUBSCRIPTION_ID",
                "resource_group_name" : "YOUR_RESOURCE_GROUP_NAME",
                "workspace_name" : "YOUR_LOG_ANALYTICS_WORKSPACE",
                "title" : "YOUR_ALERT_TITLE",
                "group_key" : "YOUR_INCIDENT_GROUPING_KEY",
                "severity" : "High"
            }
        ), 
        headers = {"Content-Type" : "application/json"}
    )
    
print(resp.text)