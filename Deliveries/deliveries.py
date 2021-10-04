from json.decoder import JSONDecodeError
from typing import IO
import requests
import json
import os
import logging

from requests.api import request
from requests.models import requote_uri


class API_Error(Exception):
    def __init__(self, message) -> None:
        self.message = message
        super().__init__(self.message)


def response_handler(response):
    code = response.status_code
    try:
        json.loads(response.content)
    except JSONDecodeError as e:
        # print("Error: Invalid Request")
        raise RuntimeError("Failed to send Invalid Request") from e

    if code < 200 or code >= 300:

        # print(f"Error {code}: {error_message}")
        # raise Exception(f"Error {code}: {error_message}")
        error_message = json.loads(response.content)
        error_message = error_message["message"]
        message = "Error " + str(code) + ": " + str(error_message)
        raise API_Error(message)
    return 0


class Delivery:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    def get_delivery_destinations(self, team_id):
        """
        Will get delivery destination for a specified team

        :param team_id: (String) This is the team id for the team in which destination information will be retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object with a corresponding delivery destination retrieved from the API, if errored will return -1 or throw an Exception
        """
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

    def delete_delivery_destination(self, teamid):
        """
        Will delete delivery destination for a specified team

        :param teamid: (String) This is the team id for the team in which destination information will be deleted
        :return: (Byte/String) Will return an empty type siginifying the deletion of the corresponding destination
        """
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

    def create_delivery_destination(self, teamid, location, region, name, desttype):
        """
        Will create a delivery destination for a team

        :param teamid: (String) This is the team id for the team in which the destination will be created
        :param location: (String) This is the location of the destination
        :param region: (String) This the region of the destination
        :param name: (String) This is the name of the destination
        :param desttype: (String) This is the specified destination type of the destination
        :return: (Dictionary) or (Integer) Will return a dictionary object with a created delivery destination retrieved from the API, if errored will return -1 or throw an Exception
        """
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
