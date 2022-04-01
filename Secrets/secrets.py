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

    # This endpoint returns a risk score for scope, category, and attributes based on a series of specified parameters
    # Uses purl spec https://github.com/package-url/purl-spec#purl
    def get_score(self, name, org, pkg_type, tb=None):
        """
        Will perform a search for a risk score based on a series of specified parameters
        Uses purl spec https://github.com/package-url/purl-spec#purl
        :param name: (String) The name of the package. Required.
        :param org: (String) Some name prefix such as a Maven groupid, a Docker image owner, a GitHub user or organization. Optional and type-specific.
        :param pkg_type: (String) The package "type" or package "protocol" such as maven, npm, nuget, gem, pypi, github, etc. Required.
        :param tb: (String) Optional parameter that indicates what package type is set.
        :return: (Dictionary) or (Integer) Will return a dictionary object containing score results retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "score/getScore?purl=pkg:"
        if tb == "repos":
            pkg_type = "github"
        elif tb == "products":
            pkg_type = "TBA"
        elif tb == "packages":
            pkg_type = "TBA"
        query = "/" + org + "/" + name
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint + pkg_type + query
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data
