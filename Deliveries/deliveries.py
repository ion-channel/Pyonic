from json.decoder import JSONDecodeError
from typing import IO
import requests
import json
import os
import logging

from requests.api import request
from requests.models import requote_uri


# This handler is currently under testing much like many of the endpoints: CAUTION ADVISED FOR USAGE
def response_handler(response):
    code = response.status_code
    try:
        json.loads(response.content)
    except JSONDecodeError as e:
        # print("Error: Invalid Request")
        raise RuntimeError("Failed to send Invalid Request") from e

    if code < 200 or code >= 300:
        error_message = json.loads(response.content)
        error_message = error_message["message"]
        # print(f"Error {code}: {error_message}")
        raise Exception(f"Error {code}: {error_message}")
    return 0


# This class as of the current, keeps track of the baseURL and eventually the API token - once they login
class Deliv:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None


# Will need more information before commenting on this endpoints functionality
def get_delivery_destinations(self, team_id):
    endpoint = "teams/getDeliveryDestinations"
    head = {"Authorization": "Bearer " + self.token}
    URL = self.baseURL + endpoint
    parameters = {"id": team_id}
    logging.debug(f"Http Destination: {URL}")
    r = requests.get(URL, headers=head, params=parameters)
    logging.debug(f"Request Type: {r.request}")
    logging.debug(f"Status Code: {r.status_code}")
    check = response_handler(r)
    if check != 0:
        return -1
    dictionary_data = json.loads(r.content)
    return dictionary_data


Deliv.get_delivery_destinations = get_delivery_destinations

# Will need more information before commenting on this endpoints functionality
def delete_delivery_destination(self, teamid):
    endpoint = "teams/deleteDeliveryDestination"
    head = {"Authorization": "Bearer " + self.token}
    URL = self.baseURL + endpoint
    parameters = {"id": teamid}
    logging.debug(f"Http Destination: {URL}")
    r = requests.delete(URL, headers=head, params=parameters)
    logging.debug(f"Request Type: {r.request}")
    logging.debug(f"Status Code: {r.status_code}")
    # check = response_handler(r)
    # if check != 0:
    #     return -1
    # dictionary_data = json.loads(r.content)
    return r.content


Deliv.delete_delivery_destination = delete_delivery_destination

# Will need more information before commenting on this endpoints functionality
def create_delivery_destination(self, teamid, location, region, name, desttype):
    endpoint = "teams/createDeliveryDestination"
    head = {"Authorization": "Bearer " + self.token}
    URL = self.baseURL + endpoint
    logging.debug(f"Http Destination: {URL}")
    json_data = json.dumps(
        {
            "team_id": teamid,
            "Location": location,
            "Region": region,
            "Name": name,
            "type": desttype,
        }
    )
    r = requests.post(URL, headers=head, data=json_data)
    logging.debug(f"Request Type: {r.request}")
    logging.debug(f"Status Code: {r.status_code}")
    check = response_handler(r)
    if check != 0:
        return -1
    dictionary_data = json.loads(r.content)
    return dictionary_data


Deliv.create_delivery_destination = create_delivery_destination
