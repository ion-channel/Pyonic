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


class Dependency:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    def get_versions_for_dependency(self, package_name, ecosystem):
        """
        Will get version data for specified dependencies

        :param package_name: (String) This is the name of the dependency for which version information will be retrieved
        :param ecosystem: (String) This is the ecosystem of the corresponding dependency
        :return: (Dictionary) or (Integer) Will return a dictionary object with dependency versions retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "dependency/getVersions"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"name": package_name, "type": ecosystem}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    def search_dependencies(self, org):
        """
        Will search a query through a series of dependencies

        :param org: (String) This is the query that will be searched through the dependencies
        :return: (Dictionary) or (Integer) Will return a dictionary object with searched dependency content retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "dependency/search"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"q": org}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    def get_latest_version_for_dependency(self, package_name, ecosystem):
        """
        Will get the latest version for a specified dependency

        :param package_name: (String) This is the name of the dependency for which version information will be retrieved
        :param ecosystem: (String) This is the ecosystem of the corresponding dependency
        :return: (Dictionary) or (Integer) Will return a dictionary object with the latest dependency versions retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "dependency/getLatestVersionForDependency"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"name": package_name, "type": ecosystem}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint needs verification
    def resolve_dependencies_in_file(self, file, flatten, ecosystem):
        """
        This endpoint will resplve/identify a set of dependencies within a specified file

        :param file: (String) This is the file path through which dependencies will be identified/resolved
        :param flatten: (Bool) This is to specify whether dependencies are flattened
        :param ecosystem: (String) This is the dependency ecosystem for the file
        :return: (Dictionary) or (Integer) Will return a dictionary object with resolved/identified dependencies in file retrieved from the API, if errored will return -1 or throw an Exception
        """
        f = open(file)
        if f.name == "Gemfile.lock.lock":
            endpoint = (
                "dependency/resolveFromFile?"
                + "Flatten="
                + str(flatten)
                + "&type="
                + str(ecosystem)
            )
        else:
            endpoint = (
                "dependency/resolveDependenciesInFile?"
                + "Flatten="
                + str(flatten)
                + "&type="
                + str(ecosystem)
            )
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        # json_data = {"file": file}
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

    # This endpoint will return depenency statisitics for a set of corresponding
    # inputted projects - projectids
    def get_dependency_statistics(self, projectids):
        """
        Will retrieve dependency statistics for a set of specified projects

        :param projectids: (String Array) This is a set of project ids for projects that dependency statistics are to be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with project dependency statistics retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getDependencyStats"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"Ids": projectids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return raw dependency information for a set of projects - projectids,
    # can be sorted by listType - name/impact - and a limit of returned results can also
    # be passed through - limit. ListType and limit are optional and are default set to None.
    def get_raw_dependency_list(self, projectids, listType=None, limit=None):
        """
        Will retrieve raw dependency information for a set of projects

        :param projectids: (String Array) This is a set of projectids for projects that dependency information is to be retrieved for
        :param listType: (String) Optional parameter that showcases the way retrieved content is to be sorted, eg. name, impact, etc.
        :param limit: (String) Optional parameter to specify the limit of retrieved results
        :return: (JSON Object) or (Integer) Will return a JSON object with project dependency data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getDependencyList"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint

        json_data = {"ids": projectids}

        if listType is not None:
            json_data["list_type"] = listType

        if limit is not None:
            json_data["limit"] = limit

        json_data = json.dumps(json_data)
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content

    # This endpoint will return dependency information for a set of projects - projectids,
    # can be sorted by listType - name/impact - and a limit of returned results can also
    # be passed through - limit. ListType and limit are optional and are default set to None.
    def get_dependency_list(self, projectids, listType=None, limit=None):
        """
        Will retrieve dependency information for a set of projects

        :param projectids: (String Array) This is a set of project ids for projects that dependency information is to be retrieved for
        :param listType: (String) Optional parameter that showcases the way retrieved content is to be sorted, eg. name, impact, etc.
        :param limit: (String) Optional parameter to specify the limit of retrieved results
        :return: (Dictionary) or (Integer) Will return a dictionary object with project dependency data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getDependencyList"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint

        json_data = {"ids": projectids}

        if listType is not None:
            json_data["list_type"] = listType

        if limit is not None:
            json_data["limit"] = limit

        json_data = json.dumps(json_data)
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data
