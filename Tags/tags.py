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


class Tag:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This endpoint will create a new tag when inputted with a corresponidng team - teamid,
    # name, and description
    def create_tag(self, teamid, name, description):
        """
        Will create a new tag for a specified team

        :param teamid: (String) This is the team id for the team that the tag is to be created for
        :param name: (String) This is the name of the tag
        :param description: (String) This is the description of the tag
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a newly created tag retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/createTag"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps(
            {"team_id": teamid, "Name": name, "description": description}
        )
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will update a tag's information when inputted with a corresponding, tagid,
    # teamid, name, and description
    def update_tag(self, tagid, teamid, name, description):
        """
        Will update a tag for a specified team

        :param tagid: (String) This is the tag id for the tag that is to be updated
        :param teamid: (String) This is the team id for the team that the tag is to be updated for
        :param name: (String) This is the updated name of the tag
        :param description: (String) This is the updated description of the tag
        :return: (Dictionary) or (Integer) Will return a dictionary object containing an updated tag retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/updateTag"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps(
            {"ID": tagid, "team_id": teamid, "Name": name, "Description": description}
        )
        logging.debug(f"Http Destination: {URL}")
        r = requests.put(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return information about a respective tag when inputted with a correspondiing
    # tagid - tag identifier, and teamid - team identifier
    def get_tag(self, tagid, teamid):
        """
        Will retrieve information about a specified tag

        :param tagid: (String) This is the tag id for the tag that data will be retrieved for
        :param teamid: (String) This is the team id for the team the corresponding tag is located within
        :return: (Dictionary) or (Integer) Will return a dictionary object with tag data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/getTag"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": tagid, "team_id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return raw information about a respective tag when inputted with a correspondiing
    # tagid - tag identifier, and teamid - team identifier
    def get_raw_tag(self, tagid, teamid):
        """
        Will retrieve raw information about a specified tag

        :param tagid: (String) This is the tag id for the tag that data will be retrieved for
        :param teamid: (String) This is the team id for the team the corresponding tag is located within
        :return: (JSON Object) or (Integer) Will return a JSON object with tag data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/getTag"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": tagid, "team_id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content

    # This endpoint will return information regarding all tags for a corrsponding
    # team - takes in teamid
    def get_tags(self, teamid):
        """
        Will retrieve information for all tags within a specified team

        :param teamid: (String) This is the team id for the team that all tags will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with all tag data for a team retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/getTags"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return raw information regarding all tags for a corrsponding
    # team - takes in teamid
    def get_raw_tags(self, teamid):
        """
        Will retrieve raw information for all tags within a specified team

        :param teamid: (String) This is the team id for the team that all tags will be retrieved for
        :return: (JSON Object) or (Integer) Will return a JSON object with all tag data for a team retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/getTags"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content
