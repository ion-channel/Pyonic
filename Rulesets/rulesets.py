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


class Ruleset:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This endpoint will get the data about an applied ruleset
    def get_applied_ruleset(self, teamid, projectid, analysisid):
        """
        Will get the applied ruleset for an analysis

        :param teamid: (String) This is the team id for the team in which the corresponding project that went underwent analysis is located
        :param projectid: (String) This is the project id for the project that has been analyzed
        :param analysisid: (String) This is the analysis id for the completed analysis
        :return: (Dictionary) or (Integer) Will return a dictionary object with data corresponding to the applied ruleset for an analysis from the API, if errored will return -1 or throw an Exception
        """

        endpoint = "ruleset/getAppliedRulesetForProject"
        head = {"Authorization": "Bearer " + self.token}
        parameters = {
            "team_id": teamid,
            "project_id": projectid,
            "analysis_id": analysisid,
        }
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1

        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return raw data about an applied ruleset
    def get_raw_applied_ruleset(self, teamid, projectid, analysisid):
        """
        Will get the raw applied ruleset for an analysis

        :param teamid: (String) This is the team id for the team in which the corresponding project that went underwent analysis is located
        :param projectid: (String) This is the project id for the project that has been analyzed
        :param analysisid: (String) This is the analysis id for the completed analysis
        :return: (JSON Object) or (Integer) Will return a JSON object with data corresponding to the applied ruleset for an analysis from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/getAppliedRulesetForProject"
        head = {"Authorization": "Bearer " + self.token}
        parameters = {
            "team_id": teamid,
            "project_id": projectid,
            "analysis_id": analysisid,
        }
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1

        return r.content

    # This endpoint will get information regarding a specific ruleset
    def get_ruleset(self, teamid, rulesetid):
        """
        Will get specific ruleset information for a specified team

        :param teamid: (String) This is the team id for the team in which the corresponding project's ruleset is located
        :param rulesetid: (String) This is the ruleset id for the ruleset that content is to be returned for
        :return: (Dictionary) or (Integer) Will return a dictionary object with ruleset data from the API, if errored will return -1 or throw an Exception

        """
        endpoint = "ruleset/getRuleset"
        head = {"Authorization": "Bearer " + self.token}
        parameters = {"team_id": teamid, "id": rulesetid}
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1

        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will output a set of rules that could potentially used in a ruleset
    def get_rules(self):
        """
        Will output a set of rules that could potentially be used within a ruleset

        :return: (Dictionary) or (Integer) Will return a dictionary object containing a set of rules retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/getRules"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint fetches all rulesets that were in use for a given team
    def get_rulesets(self, teamid):
        """
        Will fetch all rulesets that are in use for a specified team

        :param teamid: (String) This is the team id for the team that rulesets will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a team's ruleset data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/getRulesets"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint fetches the global default rulesets available to all teams
    def get_default_rulesets(self):
        """
        Will fetch global default rulesets available to all teams

        :return: (Dictionary) or (Integer) Will return a dictionary object containing global default ruleset data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/getDefaultRulesets"
        head = {"Authorization": "Bearer " + self.token}
        url = self.baseURL + endpoint

        logging.debug(f"Http Destination: {url}")
        response = requests.get(url, headers=head)
        logging.debug(f"Request Type: {response.request}")
        logging.debug(f"Status Code: {response.status_code}")

        check = response_handler(response)
        if check != 0:
            return -1

        dictionary_data = json.loads(response.content)

        return dictionary_data

    # This ednpoint will fetch the analysis history of a project
    def get_pass_fail_history(self, projectid):
        """
        Will fetch analysis histiry for a specified project

        :param projectid: (String) This is the project id for the project that analysis history will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a project's analysis history data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/getProjectHistory"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"project_id": projectid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will take in a teamid, ruleset name, ruleset description, and
    # a set of rules - ruleids, and return a created ruleset
    def create_ruleset(self, teamid, name, description, ruleids):
        """
        Will create a new ruleset

        :param teamid: (String) This is the team id for the team in which the ruleset is to be located/applied
        :param name: (String) This is the name for the newly created ruleset
        :param description: (String) This is the description for the newly created ruleset
        :param ruleids: (String Array) This is a set of rule ids for rules that will be applied to the newly created ruleset
        :return: (Dictionary) or (Integer) Will return a dictionary object containing the newly created ruleset from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/createRuleset"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps(
            {
                "team_id": teamid,
                "rule_ids": ruleids,
                "name": name,
                "description": description,
            }
        )
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will delete a ruleset when inputted with a corresponding team - teamid,
    # and ruleset - rulesetid
    def delete_ruleset(self, teamid, rulesetid):
        """
        Will delete a specified ruleset

        :param teamid: (String) This is the team id for the team that utilizes the ruleset that will be deleted
        :param rulesetid: (String) This is the rulesetid for the ruleset that is to be deleted
        :return: (Dictionary) or (Integer) Will return a dictionary object containing the deleted ruleset data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/deleteRuleset"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "ruleset_id": rulesetid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.delete(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint takes an array of tuples (a, b), where index "a" (0) of the tuple is
    # the teamid, and index "b" (1) of the tuple is the projectid, the endpoint will then
    # return respective applied rulesets on inputted projects
    def get_applied_rulesets(self, appliedRequestBatch):
        """
        Will retrieve applied rulesets for specified projects

        :param appliedRequestBatch: This parameter takes an array of tuples (a, b), where index "a" (0) of the tuple is the teamid, and index "b" (1) of the tuple is the projectid
        :return: (Dictionary) or (Integer) Will return a dictionary object with corresponding applied rulesets retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/getAppliedRulesets"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = []
        for item in appliedRequestBatch:
            json_data.append({"team_id": item[0], "project_id": item[1]})

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

    # This endpoint takes an array of tuples (a, b), where index "a" (0) of the tuple is
    # the teamid, and index "b" (1) of the tuple is the projectid, the endpoint will then
    # return briefed results on the corresponding applied rulesets
    def get_applied_rulesets_brief(self, appliedRequestBatch):
        """
        Will retrieve breifed applied rulesets for specified projects

        :param appliedRequestBatch: This parameter takes an array of tuples (a, b), where index "a" (0) of the tuple is the teamid, and index "b" (1) of the tuple is the projectid
        :return: (Dictionary) or (Integer) Will return a dictionary object with correspondingly breifed applied rulesets retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/getAppliedRulesets"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"summarized": "true"}
        json_data = []
        for item in appliedRequestBatch:
            json_data.append({"team_id": item[0], "project_id": item[1]})

        json_data = json.dumps(json_data)
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, params=parameters, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return True if the ruleset exists, and False if the ruleset
    # doesn't exist or an error occurs
    def ruleset_exists(self, teamid, rulesetid):
        """
        Will determine whether a ruleset exists

        :param teamid: (String) This is the team id for the team that the ruleset's existence is checked within
        :param rulesetid: (String) This is the ruleset id for the ruleset that is checked for existing within the corresponding team
        :return: (Boolean) Will return True if the ruleset exists, and False if the ruleset doesn't exist or if an error occurs, may also throw Exception based on error
        """
        endpoint = "ruleset/getRuleset"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "id": rulesetid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")

        if r.status_code < 200 or r.status_code >= 300:
            return False

        return True

    # This endpoint will return the names of rulesets when passed through with their corresponding
    # rulesetids - array
    def get_ruleset_names(self, rulesetids):
        """
        Will retrieve the names for a set of specified rulesets

        :param rulesetids: (String) This is the set of ruleset ids for rulesets that will have their names retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object with ruleset names retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/getRulesetNames"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"IDs": rulesetids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return used rulesetids for a corresponding team - teamid
    def get_used_ruleset_ids(self, teamid):
        """
        Will retrieve currently used rulesets for a specified team

        :param teamid: (String) This is the team id for the team that the rulesets are applied for
        :return: (Dictionary) or (Integer) Will return a dictionary object with used rulesetids retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "project/getUsedRulesetIds"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data
