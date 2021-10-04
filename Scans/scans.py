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


class Scan:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This endpoint will search for a series of scans within a team - teamid
    # and return corresponding data, this endpoint has a searchParams parameters
    # which takes in a dictionary, that has two fields to help filter search results.
    # Search Parameter Example:
    # {
    #     "analysis_ids": ["analysisid1", "analysisid2"],
    #     "scan_types": ["scanfilter1", "scanfilter2"]
    # }
    def find_scans(self, searchParams, teamid):
        """
        Will search for a series of scans within a specified team

        :param searchParams: (Dictionary) This is to help filter search results: Search Parameter Example: {"analysis_ids": ["analysisid1", "analysisid2"], "scan_types": ["scanfilter1", "scanfilter2"]}
        :param teamid: (String) This is the team id for the team that the scans will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with scans retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/findScans"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid}
        json_data = json.dumps(searchParams)
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, params=parameters, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data
