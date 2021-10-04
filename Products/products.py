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

class Product:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This endpoint will return product versions with a correspondingly specific name and version.
    # The name parameter is required, however, the version parameter is optional with a default set to None
    def get_product_versions(self, name, version=None):
        """
        Will retrieve product versions when provided with a specified name/version

        :param name: (String) This is the name of the product that version content will be retrieved for
        :param version: (String) Optional parameter to specify product version that will be retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object with project versions data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "product/getProductVersions"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"name": name}
        if version is not None:
            parameters["version"] = version
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will take in a search query - searchInput - and return all
    # corresponding matching products within the Bunsen Dependencies Table
    def get_product_search(self, searchInput):
        """
        Will take in a specified search query and retrieve all corresponding matching products within the Bunsen Dependencies Table

        :param searchInput: (String) This is the search query that data will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with product search data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "product/search"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"q": searchInput}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint takes in a product name and returns raw information with
    # regards to the corresponding product
    def get_raw_product(self, productname):
        """
        Will retrieve raw product infomation for a specified product

        :param productname: (String) This is the product name for the product that data is to be retrieved for
        :return: (JSON Object) or (Integer) Will return a JSON object with product data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "vulnerability/getProducts"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"product": productname}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content

    # This endpoint takes in a product name and returns information with
    # regards to the corresponding product
    def get_product(self, productname):
        """
        Will retrieve product infomation for a specified product

        :param productname: (String) This is the product name for the product that data is to be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with product data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "vulnerability/getProducts"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"product": productname}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

