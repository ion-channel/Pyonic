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


class Authentication:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This endpoint will return a series of tokens created by a corresponding user.
    # The cli parameter has a default value of True
    def get_tokens(self, cli=True):
        """
        Will retrieve a set of tokens created by a corresponding user

        :param cli: (Boolean) Optional parameter with default value set to True
        :return: (Dictionary) or (Integer) Will return a dictionary object containing token data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tokens/getTokens"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        if cli:
            cli = "true"
        elif not cli:
            cli = "false"
        parameters = {"cli": cli}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data
