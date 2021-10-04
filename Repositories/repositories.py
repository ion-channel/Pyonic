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

class Repository:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This endpoint will extract information about a certain repository repo_name must be path
    # after https://github.com/
    def get_repository(self, repo_name):
        """
        Will extract information about a certain repository

        :param repo_name: (String) Repository path after https://github.com/
        :return: (Dictionary) or (Integer) Will return a dictionary object with repository data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "repo/getRepo"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"repo": repo_name}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # Will need more information before commenting on this endpoints functionality
    def get_repositories_in_common(self, options):
        """
        Will get/find repositories in common

        :param options: (Dictionary) This is where options are specified for the repository, ex. (Subject, Comparand, ByActor)
        :return: (Dictionary) or (Integer) Will return a dictionary object with repository in common retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "repo/getReposInCommon"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps(options)
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # Will need more information before commenting on this endpoints functionality
    def get_repositories_for_actor(self, name):
        """
        Will get/find repositories for a specific actor

        :param name: (String) The name of the specified actor
        :return: (Dictionary) or (Integer) Will return a dictionary object with repository affiliated with an actor retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "repo/getReposForActor"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"name": name}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # Will need more information before commenting on this endpoints functionality
    def search_repository(self, query):
        """
        Will search a query through a repository

        :param query: (String) The query string to be searched in the repository
        :return: (Dictionary) or (Integer) Will return a dictionary object with contents affiliated with the query retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "repo/search"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"q": query}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data