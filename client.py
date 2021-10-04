from json.decoder import JSONDecodeError
from typing import IO
import requests
import json
import os
import logging
import sys

from requests.api import request
from requests.models import encode_multipart_formdata, requote_uri

from Analyses.analyses import Analysis
from Authentication.authentication import Authentication
from Deliveries.deliveries import Delivery
from Dependencies.dependencies import Dependency
from Products.products import Product
from Projects.projects import Project
from Reports.reports import Report
from Repositories.repositories import Repository
from Rulesets.rulesets import Ruleset
from Scans.scans import Scan
from Searches.searches import Search
from Secrets.secrets import Secret
from Tags.tags import Tag
from Teams.teams import Team
from Tokens.tokens import Token
from Users.users import User
from Vulnerabilities.vulnerabilities import Vulnerability

# from requests.api import get
# sys.path.insert(0, 'Deliveries')
# from Deliveries.deliveries import *

#### These functions are to ensure that the core/critical SDK features are working, eventually these funtions will be formatted/reorganized

# Custom exception in the event an API error occurs
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


# This class as of the current, keeps track of the baseURL and eventually the API token - once they login
class IonChannel(
    Authentication,
    Analysis,
    Delivery,
    Dependency,
    Project,
    Product,
    Report,
    Repository,
    Ruleset,
    Secret,
    Search,
    Scan,
    Team,
    Tag,
    Token,
    User,
    Vulnerability,
):
    """Python SDK for the Ion-Channel API"""

    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This function will allow the user to login
    def login(self, username=None, password=None):
        """
        Will allow a user to login to their Ion account via environment variables IONUSER - username - and IONPASSWORD - password -

        :param username: (String) Optional parameter to pass through username credentials
        :param password: (String) Optional parameter to pass through password credentials
        :return: (Dictionary) or (Integer) Will return a dictionary if proper authentication has been provided, otherwise will return -1 or throw an Exception
        """
        try:
            token = os.environ["IONTOKEN"]

        except KeyError:
            if username is None:
                try:
                    username = os.environ["IONUSER"]
                except KeyError as e:
                    # username = input(
                    #     "Since you have not set ENV variable (IONUSER): What is your username: "
                    # )
                    raise KeyError("You have not set ENV variable (IONUSER)") from e
            if password is None:
                try:
                    password = os.environ["IONPASSWORD"]
                except KeyError as e:
                    # password = input(
                    #     "Since you have not set ENV variable (IONPASSWORD): What is your password: "
                    # )
                    raise KeyError("You have not set ENV variable (IONPASSWORD)") from e

            endpoint = "sessions/login"
            URL = self.baseURL + endpoint
            logging.debug(f"Http Destination: {URL}")
            r = requests.post(URL, json={"username": username, "password": password})
            logging.debug(f"Request Type: {r.request}")
            logging.debug(f"Status Code: {r.status_code}")
            check = response_handler(r)
            # if check is not None:
            #    return -1
            if check != 0:
                return -1

            try:
                token = r.json()["data"]["jwt"]
            except KeyError as e:
                # print("login Error: Invalid authentication credentials - An account doesn't exist with this username or password")

                raise RuntimeError(
                    "Invalid authentication credentials - An account doesn't exist with this username or password"
                ) from e

                # return -1

        self.token = token
        # return token
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will logout and a user's running session
    def logout(self):
        """
        Will logout a user's running session

        :return: (Byte/String), (Dictionary) (or (Integer) Will return a dictionary object or empty byte string, if errored will return -1 or throw an Exception
        """
        endpoint = "sessions/logout"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.delete(URL, headers=head)
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


# This function will create a new client object so that the user can interact with the API
def new_client(baseURL):
    """Will create a new client object so that the user can interact with the Ion API

    :param baseURL: (String) Base URL to interact with API
    :return: (IonChannel Object) Creates and returns a new client object
    """
    client = IonChannel(baseURL)
    return client
