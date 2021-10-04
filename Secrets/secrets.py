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

class Secret:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This endpoint will return any matching secrets to the inputted text,
    # the return type - if successful - will have three fields:
    # Rule: This field describes the defined rule that was matched
    # Match: This field describes the subtext that was matched
    # Confidence: This field describes the trust in the returned result from 0.0 to 1.0
    def get_secrets(self, text):
        """
        Will retrieve any secretes that match the specified/inputted text

        :param text: (String) This is the text that secrets will be matched against
        :return: (Dictionary) or (Integer) Will return a dictionary object with secrets content retrieved from the API, if successful dictionary will have three fields, Rule: This field describes the defined rule that was matched, Match: This field describes the subtext that was matched, and Confidence: This field describes the trust in the returned result from 0.0 to 1.0. If errored will return -1 or throw an Exception
        """
        endpoint = "metadata/getSecrets"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        text_data = text
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=text_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data