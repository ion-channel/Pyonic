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


class Vulnerability:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This endpoint will return vulnerability statistics from a series of projects
    def get_vulnerability_statistics(self, projectids):
        """
        Will get vulnerability statistics for a set of specified projects

        :param projectids: (String Array) This is a set of project ids for projects that are to have vulnerability statistics retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object with vulnerability statistics retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getVulnerabilityStats"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"ids": projectids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return raw vulnerability statistics from a series of projects
    def get_raw_vulnerability_statistics(self, projectids):
        """
        Will get raw vulnerability statistics for a set of specified projects

        :param projectids: (String Array) This is a set of project ids for projects that are to have vulnerability statistics retrieved
        :return: (JSON Object) or (Integer) Will return a JSON object with vulnerability statistics retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getVulnerabilityStats"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"ids": projectids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content

    def get_vulnerability_metrics(self, metric, projectids):
        """
        Will get vulnerability metrics for a set of specified projects

        :param metric: (String) This is the metric that vulnerabilities will be identified with eg. "vulnerability"
        :param projectids: (String Array) This is a set of project ids that pertain to specific projects that will have vulnerability metrics retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object with vulnerability metrics retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getScanMetrics"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"metric": metric, "project_ids": projectids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    def get_raw_vulnerability_metrics(self, metric, projectids):
        """
        Will get raw vulnerability metrics for a set of specified projects

        :param metric: (String) This is the metric that vulnerabilities will be identified with eg. "vulnerability"
        :param projectids: (String Array) This is a set of project ids that pertain to specific projects that will have vulnerability metrics retrieved
        :return: (JSON Object) or (Integer) Will return a JSON object with vulnerability metrics retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getScanMetrics"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"metric": metric, "project_ids": projectids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content

    # This endpoint takes in a dependency file path and will return vulnerabilities within the file
    def get_vulnerabilities_in_file(self, file):
        """
        Will retrieve vulnerabilities within a specified file

        :param file: (String) This is the relative path of the file that vulnerabilities are to be identified for
        :return: (Dictionary) or (Integer) Will return a dictionary object with file extracted vulnerability data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "vulnerability/getVulnerabilitiesInFile"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        file_data = {"file": open(file, "r")}
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, files=file_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return information regarding a given vulnerability
    # based on its correspondingly inputted vulnerabilityid
    def get_vulnerability(self, vulnerabilityid):
        """
        Will retrieve information for a specified vulnerability

        :param vulnerabilityid: (String) This is the vulnerability id for the vulnerability that data is to be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with vulnerability data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "vulnerability/getVulnerability"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"external_id": vulnerabilityid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return raw information regarding a given vulnerability
    # based on its correspondingly inputted vulnerabilityid
    def get_raw_vulnerability(self, vulnerabilityid):
        """
        Will retrieve raw information for a specified vulnerability

        :param vulnerabilityid: (String) This is the vulnerability id for the vulnerability that data is to be retrieved for
        :return: (JSON Object) or (Integer) Will return a JSON object with vulnerability data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "vulnerability/getVulnerability"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"external_id": vulnerabilityid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content

    # This endpoint will reuturn a set of vulnerabilities attached to a specific
    # product with a corresponding version number. Offset - for pagination purposes -
    # describes where the starting point would be to return records, is by default 0.
    # Limit - for pagination purposes - describes how many possible records to be returned,
    # is by default 10
    def get_vulnerabilities(self, product, version, offset=0, limit=10):
        """
        Will retrieve a set of vulnerabilities attached to a specified product with a corresponding version number

        :param product: (String) This is the name of the product that vulnerabilties will be retrieved for
        :param version: (String) This is the version of the product that vulnerabilities will be retrieved for
        :param offset: (Integer) Optional parameter for pagination purposes, it describes where the starting point would be to return records, is by default set to 0
        :param limit: (Integer) Optional parameter for pagination purposes, it describes how many possible records are to be returned, is by default 10
        :return: (Dictionary) or (Integer) Will return a dictionary object with product vulnerability data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "vulnerability/getVulnerabilities"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {
            "product": product,
            "version": version,
            "offset": offset,
            "limit": limit,
        }
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data
