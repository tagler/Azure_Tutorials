import json
import uuid
import requests
import logging

from typing import List, Dict
from azure.identity import DefaultAzureCredential
from flask import Flask, request 

app = Flask(__name__)

def get_incidents(
    api_base_url: str,
    subscription_id: str, 
    resource_group_name: str, 
    workspace_name: str,
    token: DefaultAzureCredential,
) -> List[Dict]:
    """
    Function that will return all open incidents 
    Args:
        api_base_url
        subscription_id
        resrouce_group_name
        worksapce_name
        token: azure identity default credential object
    Returns:
        List of dictionaries
    """
    # api request
    with requests.Session() as ses:
        resp = ses.get(
            url=f"{api_base_url}/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents?api-version=2021-10-01",
            headers={'Authorization': 'Bearer ' + token.token}
        )
        if not resp.ok:
            raise Exception(f"{resp.status_code} {resp.content}")
        resp_json = json.loads(resp.content)
    # get open incidents only
    open_incidents = []
    for each_incident in resp_json["value"]:
        if each_incident["properties"]["status"] != "Closed":
            open_incidents.append(each_incident)
    return open_incidents

def get_incident(
    token: DefaultAzureCredential,
    api_base_url: str,
    incident_id: str,
    subscription_id: str, 
    resource_group_name: str, 
    workspace_name: str,
) -> Dict:
    """
    Function that will return an incident details
    Args:
        token: azure identity default credential object
        api_base_url
        incident_id
        subscription_id
        resrouce_group_name
        worksapce_name
    Returns:
        List of dictionaries
    """
    # api request
    with requests.Session() as ses:
        resp = ses.get(
            url=f"{api_base_url}/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents/{incident_id}?api-version=2021-10-01",
            headers={'Authorization': 'Bearer ' + token.token}
        )
        if not resp.ok:
            raise Exception(f"{resp.status_code} {resp.content}")
        resp_json = json.loads(resp.content)
        return resp_json

def create_incident(
    api_base_url: str,
    title: str, 
    group_key: str, 
    severity: str,
    subscription_id: str, 
    resource_group_name: str, 
    workspace_name: str,
    token: DefaultAzureCredential, 
) -> str:
    """
    Function to create a new incident
    Args:
        api_base_url
        title: incident title
        group_key: string that groups alerts into same incident 
        severity: level of incident 
        subscription_id
        resrouce_group_name
        worksapce_name
        token: azure default credential token object
    Returns:
        incident id
    """
    # api request
    new_uuid = str(uuid.uuid4())
    payload = {
        "properties": {
            "title": f"{title} - {group_key}",
            "severity": severity,
            "status": "New"
        }
    }
    with requests.Session() as ses:
        resp = ses.put(
            url=f"{api_base_url}/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents/{new_uuid}?api-version=2021-10-01",
            headers={
                'Authorization': 'Bearer ' + token.token,
                'Content-Type': 'application/json',
            },
            data=json.dumps(payload)
        )
        if not resp.ok:
            raise Exception(f"{resp.status_code} {resp.content}")
        resp_json = json.loads(resp.content)
        return new_uuid

def delete_incident(
    token:DefaultAzureCredential,
    api_base_url: str,
    incident_id: str,
    subscription_id: str, 
    resource_group_name: str, 
    workspace_name: str,
) -> None:
    """
    Function that will delete an incident  
    Args:
        token: azure identity default credential object
        api_base_url
        incident_id
        subscription_id
        resrouce_group_name
        worksapce_name
    Returns:
        List of dictionaries
    """
    # api request
    with requests.Session() as ses:
        resp = ses.delete(
            url=f"{api_base_url}/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents/{incident_id}?api-version=2021-10-01",
            headers={'Authorization': 'Bearer ' + token.token}
        )
        if not resp.ok:
            raise Exception(f"{resp.status_code} {resp.content}")
        
def get_or_create_incident_id(    
    token:DefaultAzureCredential,
    api_base_url: str,
    subscription_id: str, 
    resource_group_name: str, 
    workspace_name: str,
    title: str,
    group_key: str,
    severity: str,
) -> str:
    """
    Function that checks if incident already exists. 
    If yes, returns existing id. If no, creates new incident. 
    Args:
        token: azure identity default credential object
        api_base_url
        subscription_id
        resrouce_group_name
        worksapce_name
        title: incident title
        group_key: string that groups alerts into same incident 
        severity: level of incident 
    Returns:
        incident id 
    """
    title_and_group_key = f"{title} - {group_key}"
    # get incidents
    incidents = get_incidents(
        api_base_url,
        subscription_id, 
        resource_group_name,
        workspace_name, 
        token
    )
    for each_incident in incidents:
        # incident group exists -> return existing id
        if each_incident["properties"]["title"] == title_and_group_key:
            existing_incident_id = each_incident["name"]
            logging.info(f"Incident Exists: {existing_incident_id}")
            return existing_incident_id
    # incident group does not exist -> create new incident
    created_incident_id = create_incident(
        api_base_url,
        title, 
        group_key, 
        severity, 
        subscription_id, 
        resource_group_name, 
        workspace_name, 
        token
    )
    logging.info(f"New Incident Created: {created_incident_id}")
    return created_incident_id
        
@app.route("/", methods=['GET', 'POST'])
def main() -> str:
    """
    Entry point for flask api
    This function will check for open sentinel incidents with provided title - group_key
    If yes, returns existing id. If no, creates new incident. 
    Args:
        http request 
    Returns:
        string
    """
    if request.method == 'POST':
        # extract from request
        body = request.get_json()
        scope = body['scope']
        api_base_url = body['api_base_url']
        subscription_id = body['subscription_id']
        resource_group_name = body['resource_group_name']
        workspace_name = body['workspace_name']
        title = body['title']
        group_key = body['group_key']
        severity = body['severity']
        # get token
        # note: need to first auth your enviorment via az cli or service principal env variables
        credential = DefaultAzureCredential()
        token = credential.get_token(scope)
        # get incident id
        incident_id = get_or_create_incident_id(
            token=token,
            api_base_url=api_base_url,
            subscription_id=subscription_id,
            resource_group_name=resource_group_name, 
            workspace_name=workspace_name,
            title=title, 
            group_key=group_key,
            severity=severity,
        )
        return incident_id
    return "Successful GET request - web server is running"

if __name__ == "__main__":
    app.debug=True
    app.run()