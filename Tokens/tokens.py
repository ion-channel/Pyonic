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


class Token:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This endpoint will create a new token for a user and will return corresponding information.
    # The cli parameter has a default value of True
    def create_token(self, name, cli=True):
        """
        Will create a new token for a logged in user

        :param name: (String) This is the name of new token
        :param cli: (Boolean) Optional parameter with default value set to True
        :return: (Dictionary) or (Integer) Will return a dictionary object containing the newly created token from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tokens/createToken"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        if cli:
            cli = "true"
        elif not cli:
            cli = "false"
        parameters = {"name": name, "cli": cli}

        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will delete a token when inputted with a corresponding token id
    def delete_token(self, tokenid):
        """
        Will delete a specified token

        :param tokenid: (String) This is the token id for the token that is to be deleted
        :return: (Byte/String), (Dictionary) or (Integer) Will return a dictionary object or an empty byte string from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tokens/deleteToken"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": tokenid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.delete(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        if str(r.content) == "b''":
            return r.content
        else:
            check = response_handler(r)
            if check != 0:
                return -1
            dictionary_data = json.loads(r.content)
            return dictionary_data

    # This endpoint will refresh a corresponding user token
    def refresh_token(self):
        """
        Will refresh the correspondingly used bearer token

        :return: (Dictionary) or (Integer) Will return a dictionary object containing the refreshed token retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tokens/refreshToken"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data
