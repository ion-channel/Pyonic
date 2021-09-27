from json.decoder import JSONDecodeError
from typing import IO
import requests
import json
import os
import logging
import sys

from requests.api import request
from requests.models import encode_multipart_formdata, requote_uri

# from requests.api import get
# sys.path.insert(0, 'Deliveries')
# from Deliveries.deliveries import *

#### These functions are to ensure that the core/critical SDK features are working, eventually these funtions will be formatted/reorganized

# Custom exception in the event an API error occurs
class API_Error(Exception):
    def __init__(self, message) -> None:
        self.message = message
        super().__init__(self.message)


# This handler is currently under testing much like many of the endpoints
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
class IonChannel:
    """Python SDK for the Ion-Channel API"""

    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This function will allow the user to login
    def login(self, username=None, password=None):
        """Will allow a user to login to their Ion account via environment variables IONUSER - username - and IONPASSWORD - password -

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

    # This function will list all the teams
    def get_teams(self):
        """
        Will get a list of all teams for a logged in user
        :return: (Dictionary) or (Integer) Will return a dictionary object with team data from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teams/getTeams"
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

    # This endpoint allows a list of projects to be viewed by a user
    def get_projects(self, teamid):
        """
        Will get a list of projects for a specific team

        :param teamid: (String) This is the team id for which projects will be listed
        :return: (Dictionary) or (Integer) Will return a dictionary object with project data from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "project/getProjects"
        URL = self.baseURL + endpoint
        head = {"Authorization": "Bearer " + self.token}
        ids = {"team_id": teamid}

        r = requests.get(URL, headers=head, params=ids)

        check = response_handler(r)
        if check != 0:
            return -1

        json_data = json.loads(r.content)
        meta_data = json_data["meta"]

        total_count = meta_data["total_count"]
        updated_req = {"team_id": teamid, "limit": total_count}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=updated_req)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        dictionary_data = json.loads(r.content)
        return dictionary_data
        # content = json_data["data"]
        # print(content)
        # for i in content:
        #     print(f'{i["name"]} and id: {i["id"]} \n')

    # This endpoint allows an analysis to be run on a selected project
    def analyze_project(self, teamid, projectid, branch=None):
        """
        Will allow an analysis to be run on a user specified project

        :param teamid: (String) This is the team id for the team in which the corresponding project is located
        :param projectid: (String) This is the project id for the project that needs to be analyzed
        :param branch: (String) Optional parameter to analyze a specific branch within the project
        :return: (Dictionary) or (Integer) Will return a dictionary object with analysis data from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "scanner/analyzeProject"
        head = {"Authorization": "Bearer " + self.token}
        if branch != 0:
            json_data = json.dumps(
                {"team_id": teamid, "project_id": projectid, "branch": branch}
            )
        else:
            json_data = json.dumps({"team_id": teamid, "project_id": projectid})
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1

        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return the status of an analysis
    def analysis_status(self, teamid, projectid, analysisid):
        """
        Will get the status of an analysis

        :param teamid: (String) This is the team id for team in which the corresponding project that went underwent analysis is located
        :param projectid: (String) This is the project id for the project that has been analyzed
        :param analysisid: (String) This is the analysis id for the ongoing or completed analysis
        :return: (Dictionary) or (Integer) Will return a dictionary object with analysis status data from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "scanner/getAnalysisStatus"
        head = {"Authorization": "Bearer " + self.token}
        parameters = {"team_id": teamid, "project_id": projectid, "id": analysisid}
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1

        json_data = json.loads(r.content)
        return json_data
        # return r.content

    # This endpoint will return analysis data
    def get_analysis(self, teamid, projectid, analysisid):
        """
        Will get analysis data for an analyzed project

        :param teamid: (String) This is the team id for the team in which the corresponding project that went underwent analysis is located
        :param projectid: (String) This is the project id for the project that has been analyzed
        :param analysisid: (String) This is the analysis id for the completed analysis
        :return: (Dictionary) or (Integer) Will return a dictionary object with analysis data and results from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getAnalysis"
        head = {"Authorization": "Bearer " + self.token}
        parameters = {"team_id": teamid, "project_id": projectid, "id": analysisid}
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

    # This endpoint will return raw analysis data
    def get_raw_analysis(self, teamid, projectid, analysisid):
        """
        Will get raw analysis data for an analyzed project

        :param teamid: (String) This is the team id for the team in which the corresponding project that went underwent analysis is located
        :param projectid: (String) This is the project id for the project that has been analyzed
        :param analysisid: (String) This is the analysis id for the completed analysis
        :return: (JSON Object) or (Integer) Will return a JSON object with analysis data and results from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getAnalysis"
        head = {"Authorization": "Bearer " + self.token}
        parameters = {"team_id": teamid, "project_id": projectid, "id": analysisid}
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1

        return r.content

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

    # This endpoint will create a project object
    def create_project(self, teamid, project):
        """
        Will create a project for a specified team

        :param teamid: (String) This is the team id for the team in which the new project will be created
        :project: (Dictionary) This is the project object that will be created under the corrsponding team
        :return: (Dictionary) or (Integer) Will return a dictionary object with the created project data from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "project/createProject"
        head = {"Authorization": "Bearer " + self.token}
        project["team_id"] = teamid

        json_data = json.dumps(project)
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will update a project and its contents based on the values within the JSON project parameter,
    # also handles the nauture of the project - whether it should be archived or not, add "active" setting (boolean) to JSON
    # object as either True or False depending on whether the project needs to be archived or not
    def update_project(self, teamid, project):
        """
        Will update a project and its contents based on the values within the JSON project parameter, also handles the nauture of the project add "active" setting (boolean) to JSON object as either True or False depending on whether the project needs to be archived or not

        :param teamid: (String) This is the team id for the team in which the project will be updated
        :param project: (Dictionary) This is the project object that will be updated under the corrsponding team
        :return: (Dictionary) or (Integer) Will return a dictionary object with the updated project data from the API, if errored will return -1 or throw an Exception
        """

        endpoint = "project/updateProject"
        head = {"Authorization": "Bearer " + self.token}
        project["team_id"] = teamid

        json_data = json.dumps(project)
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.put(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1

        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will add a scan result to an analysis
    def add_scan(self, analysisid, teamid, projectid, param_value, scan="coverage"):
        """
        Will add a scan result to an analysis

        :param analysisid: (String) This is the analysis id for the analysis in which scan results will be pulled
        :param teamid: (String) This is the team id for the team in which the analyzed project is located
        :param projectid: (String) This is the project id for the project that has been analyzed
        :param param_value: (Integer) This is the coverage value for a speicified scan
        :param scan: (String) This is an optional parameter that is preset to update coverage scans to an analysis
        :return: (Dictionary) or (Integer) Will return a dictionary object with the updated analysis scan data from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "scanner/addScanResult"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps(
            {
                "team_id": teamid,
                "project_id": projectid,
                "analysis_id": analysisid,
                "scan_type": scan,
                "status": "accepted",
                "results": {"value": param_value},
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

    # This endpoint will export an SBOM report
    def get_SBOM(self, id_set, team_id, options):
        """
        Will export an SBOM report for a set of projects

        :param id_set: (String Array) This is an array with a set of projectids for SBOM creation
        :param team_id: (String) This is the team id for the team in which the corresponding projects are located
        :param options: (Dictionary) This is where SBOM options/types are specified
        :return: (Dictionary) or (Integer) Will return a dictionary object with the SBOM report from the API, if errored will return -1 or throw an Exception
        """
        sbom_type = options["sbom_type"]
        include_dependencies = options["include_dependencies"]

        endpoint = (
            "report/getSBOM?sbom_type="
            + str(sbom_type)
            + "&include_dependencies="
            + str(include_dependencies)
        )
        head = {"Authorization": "Bearer " + self.token}
        json_data = json.dumps({"team_id": team_id, "ids": id_set})

        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will result a series of analyses run on a project
    def get_analyses(self, teamid, projectid):
        """
        Will get all analysis data for an analyzed project

        :param teamid: (String) This is the team id for the team in which the corresponding project that went underwent analysis is located
        :param projectid: (String) This is the project id for the project that has been analyzed
        :return: (Dictionary) or (Integer) Will return a dictionary object with analysis data and results from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getAnalyses"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "project_id": projectid}

        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will result a series of raw analyses data run on a project
    def get_raw_analyses(self, teamid, projectid):
        """
        Will get all raw analysis data for an analyzed project

        :param teamid: (String) This is the team id for the team in which the corresponding project that went underwent analysis is located
        :param projectid: (String) This is the project id for the project that has been analyzed
        :return: (JSON object) or (Integer) Will return a JSON object with analysis data and results from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getAnalyses"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "project_id": projectid}

        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content

    # This endpoint will return the results of the latest run analysis
    def get_latest_analysis(self, teamid, projectid):
        """
        Will get the results of of the latest analysis run on a specified project

        :param teamid: (String) This is the team id for the team in which the corresponding project that went underwent analysis is located
        :param projectid: (String) This is the project id for the project that has been analyzed
        :return: (Dictionary) or (Integer) Will return a dictionary object with latest analysis data and results from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getLatestAnalysis"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "project_id": projectid}

        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return the latest analysis IDs for a project
    # projectids must be passed through as an array of strings
    def get_latest_ids(self, teamid, projectids):
        """
        Will return the latest analysis IDs for a series of projects

        :param teamid: (String) This is the team id for the team in which the corresponding projects that went underwent analysis is located
        :param projectids: (String Array) This is an array of project ids that have been analyzed
        :return: (Dictionary) or (Integer) Will return a dictionary object with latest analysis ids from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getLatestAnalysisIDs"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"team_id": teamid, "IDs": projectids})

        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return the summary for the latest analysis run on a project
    def get_latest_analysis_summary(self, teamid, projectid):
        """
        Will return the summary for the latest analysis run on a project

        :param teamid: (String) This is the team id for the team in which the corresponding project that went underwent analysis is located
        :param projectid: (String) This is the project id for the project that has been analyzed
        :return: (Dictionary) or (Integer) Will return a dictionary object with latest analysis summary data and results from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getLatestAnalysisSummary"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "project_id": projectid}

        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return raw summary data for the latest analysis run on a project
    def get_raw_latest_analysis_summary(self, teamid, projectid):
        """
        Will return the raw summary for the latest analysis run on a project

        :param teamid: (String) This is the team id for the team in which the corresponding project that went underwent analysis is located
        :param projectid: (String) This is the project id for the project that has been analyzed
        :return: (JSON Object) or (Integer) Will return a JSON object with latest analysis summary data and results from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getLatestAnalysisSummary"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "project_id": projectid}

        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content

    # This endpoint will return a series of summaries for an analysis run on a project
    # projectids must be passed through as an array of strings
    def get_latest_analysis_summaries(self, teamid, projectids):
        """
        Will return summaries for the latest analysis run on a set of projects

        :param teamid: (String) This is the team id for the team in which the corresponding projects that went underwent analysis is located
        :param projectids: (String Array) This is the array of project ids that correspond to a set of projects that has been analyzed
        :return: (Dictionary) or (Integer) Will return a dictionary object with latest analysis summary data and results from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getLatestAnalysisSummaries"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"team_id": teamid, "IDs": projectids})

        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return a sliced portion of the data exported from an analysis
    # analysisids must be passed through as an array of strings
    def get_analyses_export_data(self, teamid, analysisids):
        """
        Will get a sliced portion of the data exported from an analysis

        :param teamid: (String) This is the team id for the team in which the corresponding projects that went underwent analysis is located
        :param analysisids: (String Array) This is the array of analysis ids that correspond to set of completed analyses
        :return: (Dictionary) or (Integer) Will return a dictionary object with latest analysis export data and results from the API, if errored will return -1 or throw an Exception
        """

        endpoint = "animal/getAnalysesExportData"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"team_id": teamid, "IDs": analysisids})

        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return a sliced portion of vulnerabilities data exported from an analysis
    def get_analyses_vulnerability_export_data(self, teamid, analysisids):
        """
        Will get a sliced portion of vulnerabilities data exported from an analysis

        :param teamid: (String) This is the team id for the team in which the corresponding projects that went underwent analysis is located
        :param analysisids: (String Array) This is the array of analysis ids that correspond to set of completed analyses
        :return: (Dictionary) or (Integer) Will return a dictionary object with latest analysis vulnerabilityy export data and results from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getAnalysesVulnerabilityExportData"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"team_id": teamid, "IDs": analysisids})

        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

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

    # Will need more information before commenting on this endpoints functionality
    def get_delivery_destinations(self, team_id):
        """
        Will get delivery destination for a specified team

        :param team_id: (String) This is the team id for the team in which destination information will be retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object with a corresponding delivery destination retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teams/getDeliveryDestinations"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": team_id}
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
    def delete_delivery_destination(self, teamid):
        """
        Will delete delivery destination for a specified team

        :param teamid: (String) This is the team id for the team in which destination information will be deleted
        :return: (Byte/String) Will return an empty type siginifying the deletion of the corresponding destination
        """
        endpoint = "teams/deleteDeliveryDestination"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.delete(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        # check = response_handler(r)
        # if check != 0:
        #     return -1
        # dictionary_data = json.loads(r.content)
        return r.content

    # Will need more information before commenting on this endpoints functionality
    def create_delivery_destination(self, teamid, location, region, name, desttype):
        """
        Will create a delivery destination for a team

        :param teamid: (String) This is the team id for the team in which the destination will be created
        :param location: (String) This is the location of the destination
        :param region: (String) This the region of the destination
        :param name: (String) This is the name of the destination
        :param desttype: (String) This is the specified destination type of the destination
        :return: (Dictionary) or (Integer) Will return a dictionary object with a created delivery destination retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teams/createDeliveryDestination"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        json_data = json.dumps(
            {
                "team_id": teamid,
                "Location": location,
                "Region": region,
                "Name": name,
                "type": desttype,
            }
        )
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

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

    def add_alias(self, teamid, projectid, name, version, org):
        """
        Will add an alias to a project

        :param teamid: (String) This is the team id of the team in which a project is to be aliased
        :param projectid: (String) This is the projectid of the project that is to be aliased
        :param name: (String) This is the specified name of the alias
        :param version: (String) This is the specified version of the alias
        :param org: (String) This is the specified organization for the alias
        :return: (Dictionary) or (Integer) Will return a dictionary object with added alias content retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = (
            "project/addAlias?team_id=" + str(teamid) + "&project_id=" + str(projectid)
        )
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"Name": name, "Version": version, "Org": org})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
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
        :parm ecosystem: (String) This is the dependency ecosystem for the file
        :return: (Dictionary) or (Integer) Will return a dictionary object with resolved/identified dependencies in file retrieved from the API, if errored will return -1 or throw an Exception
        """
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

    # This endpoint will return a pass fail summary for a series of projects
    def get_portfolio_pass_fail_summary(self, projectids):
        """
        Will get a pass fail summary for a set of specified projects

        :param projectids: (String Array) This is a set of project ids for projects that are to have pass fail summaries retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object with pass fail summaries retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/getStatuses"
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

    # This endpoint will return information regarding the analysis status' for a series of projects
    def get_portfolio_started_errored_summary(self, projectids):
        """
        Will get infomation regarding the analysis status for a set of specified projects

        :param projectids: (String Array) This is a set of project ids for projects that are to have analysis status summaries retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object with analysis status summaries retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "scanner/getStatuses"
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

    def get_portfolio_affected_projects(self, teamid, externalid):
        """
        Will get portfolio information for affected projects within a specified team

        :param teamid: (String) This is the team id for the team that will have a portfolio of affected projects retrieved
        :param externalid: (String) This is the project id for the affected project
        :return: (Dictionary) or (Integer) Will return a dictionary object with portfolio of affected projects retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getAffectedProjectIds"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": teamid, "external_id": externalid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    def get_portfolio_affected_projects_info(self, ids):
        """
        Will get portfolio information for affected projects within a specified team

        :param ids: (String Array) This array takes in two values, at index 0 is the teamid, and at index 1 is the respective project id
        :return: (Dictionary) or (Integer) Will return a dictionary object with portfolio of affected projects retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "project/getAffectedProjectsInfo"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"ids": ids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

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

    # This endpoint will return project data from the API when passed a teamid and projectid
    def get_project_report(self, teamid, projectid):
        """
        Will get project report for a user specified project

        :param teamid: (String) This is the team id for the team in which the corresponding project is located
        :param projectid: (String) This is the project id for the project that will be retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object containing corresponding project report retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getProject"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "project_id": projectid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return raw project data from the API when passed a teamid and projectid
    def get_raw_project(self, teamid, projectid):
        """
        Will get raw project data for a user specified project

        :param teamid: (String) This is the team id for the team in which the corresponding project is located
        :param projectid: (String) This is the project id for the project that will be retrieved
        :return: (JSON Object) or (Integer) Will return a JSON object containing project data retrieved from the API, if errored will return -1 or throw an Exception
        """

        endpoint = "report/getProject"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "project_id": projectid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content

    # This endpoint will update a ruleset over a set of projects - projectids
    def update_ruleset_for_project(self, rulesetid, projectids):
        """
        Will update a ruleset over a set of user specified projects

        :param rulesetid: (String) This is the ruleset id for the ruleset that will be updated
        :param projectids: (String Array) This is a set of project ids for projects that will be modified based on the specified ruleset
        :return: (Dictionary) or (Integer) Will return a dictionary object containing an updated ruleset for projects retrieved from the API, if errored will return -1 or throw an Exception
        """

        endpoint = "project/updateRulesetForProjects"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"ruleset_id": rulesetid, "project_ids": projectids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.put(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint takes an array of projectids as well as a project dictionary
    # and updates all projects based on the proposed content in the dictionary.
    # Example project content would be {"monitor": True}
    def update_projects(self, projectids, project):
        """
        WIll update a series of user specified projects

        :param projectids: (String Array) This is a set of project ids for projects that will be updated based on the specified change
        :param project: (Dictionary) This is an element that will used to update all specified projects
        :return: (Dictionary) or (Integer) Will return a dictionary object containing updated projects data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "project/updateProjects"
        head = {"Authorization": "Bearer " + self.token}

        parameters = project
        json_data = json.dumps({"project_ids": projectids})

        URL = self.baseURL + endpoint
        logging.debug(f"Http Destination: {URL}")
        r = requests.put(URL, headers=head, params=parameters, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint takes in a projectid, teamid, and analysisid and
    # returns the respective digest
    def get_digests(self, projectid, teamid, analysisid):
        """
        Will get digest information for a specified analysis

        :param projectid: (String) This is the project id for the project in which the corresponding analysis is located
        :param teamid: (String) This is the team id for the team in which the corresponding project that underwent analysis is located
        :param analysisid: (String) This is the analysis id for the analysis that digest information will be retrived for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a corresponding analysis digest data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getDigests"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"project_id": projectid, "team_id": teamid, "id": analysisid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint takes in a teamid and will return the state of the projects
    # within the corresponding team
    def get_portfolio(self, teamid):
        """
        Will retrieve portfolio content with project states for a specified team

        :param teamid: (String) This is the teamid for the team in which portfolio content will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a portfolio of project state data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getPortfolio"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint takes in a teamid and will return a list of vulnerabilities
    # that were found for any of the projects belonging to that team
    def get_vulnerability_list(self, teamid):
        """
        Will retrieve vulnerabilties for any projects within a specified team

        :param teamid: (String) This is the teamid for the team in which vulnerability content will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a set of project vulnerability data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getVulnerabilityList"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will fetch a list of projects that have been tagged with a specific
    # vulnerability within a team. The specified vulnerability is listed as the externalid
    def get_affected_projects(self, teamid, externalid):
        """
        Will retrieve a set of projects within a team that have been tagged with a specific vulnerability

        :param teamid: (String) This is the teamid for the team in which project vulnerabilities will be compared against the specified vulnerability
        :param externalid: (String) This is the vulnerability id for the vulnerability that will be cross-checked against all projects within a team
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a set of projects that contain the specified vulnerability from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getAffectedProjects"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": teamid, "external_id": externalid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will retun a project's history (pass/fail state, ruleset changes, etc.)
    # based on an inputted teamid and projectid
    def get_project_history(self, teamid, projectid):
        """
        Will retrieve project history for a specified project

        :param teamid: (String) This is the team id for the team in which the corresponding project is located
        :param projectid: (String) This is the project id for the project that history data will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing project history data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getProjectHistory"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "project_id": projectid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint is Deprecated, use CAUTIOUSLY
    def get_public_analysis(self, analysisid):
        endpoint = "report/getPublicAnalysis"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"analysis_id": analysisid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, params=parameters)
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

    # This endpoint takes in a teamid, projectid, and analysis id and outputs the
    # corresponding analysis report
    def get_analysis_report(self, teamid, projectid, analysisid):
        """
        Will retrieve an analysis report for a specified analysis

        :param teamid: (String) This is the team id for the team in which the corresponding analysis project is located
        :param projectid: (String) This is the project id for the project that underwent an analysis
        :param analysisid: (String) This is the analysis id for the analysis that a report will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing an analysis report retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getAnalysis"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {
            "team_id": teamid,
            "project_id": projectid,
            "analysis_id": analysisid,
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

    # This endpoint takes in a teamid, projectid, and analysis id and outputs the
    # raw corresponding analysis report
    def get_raw_analysis_report(self, teamid, projectid, analysisid):
        """
        Will retrieve a raw analysis report for a specified analysis

        :param teamid: (String) This is the team id for the team in which the corresponding analysis project is located
        :param projectid: (String) This is the project id for the project that underwent an analysis
        :param analysisid: (String) This is the analysis id for the analysis that a report will be retrieved for
        :return: (JSON Object) or (Integer) Will return a JSON object containing an analysis report retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getAnalysis"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {
            "team_id": teamid,
            "project_id": projectid,
            "analysis_id": analysisid,
        }
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1

        return r.content

    # This endpoint takes in a teamid and will return a list of projects
    # that belong to the corresponding team
    def get_projects_report(self, teamid):
        """
        Will retrieve a set of projects that belong to a specified team

        :param teamid: (String) This is the team id for the team that project data will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a set of all projects retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getProjects"
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

    # This endpoint will return vulnerabiltity data for a series of projects - projectids
    # within a corresponding team - teamid
    def get_exported_vulnerability_data(self, teamid, projectids):
        """
        Will retrieve vulnerability data for a set of specified projects

        :param teamid: (String) This is the team id for the team that contains the projects that vulnerability data will be retrieved for
        :param projectids: (String Array) This is a set of project ids for projects that vulnerability data will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing project vulnerability data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getExportedVulnerabilityData"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"team_id": teamid, "ids": projectids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will get exported projects data for a list of projects - ids, based
    # on an inputted team - teamid
    def get_exported_projects_data(self, teamid, ids):
        """
        Will retrieve exported projects data for a list of specified projects

        :param teamid: (String) This is the team id for the team that exported projects are located
        :param ids: (String) This is a set of project ids for projects that exported projects data will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing exported projects data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getExportedData"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"team_id": teamid, "ids": ids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return the latest analysis status of a given project,
    # when inputted with a corresponding teamid and projectid
    def get_latest_analysis_status(self, teamid, projectid):
        """
        Will retrieve the latest analysis status for a specified project

        :param teamid: (String) This is the team id for the team in which the analyzed project is located
        :param projectid: (String) This is the project id for the project that will have the latest analysis status retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object containing latest analysis status data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "scanner/getLatestAnalysisStatus"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "project_id": projectid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint returns information corresponding to a specific team
    # (based on teamid)
    def get_team(self, teamid):
        """
        Will retrieve data corresponding to a specified team

        :param teamid: (String) This is the team id for the team that will be retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object containing team data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teams/getTeam"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
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

    # This endpoint takes a series of projectids and performs an analysis
    # on each of the corresponding projects
    def analyze_projects(self, projectids):
        """
        Will run an analysis on a set of speicifed projects

        :param projectids: (String) This is a set of project ids for projects that an analysis will be run for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing analysis data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "scanner/analyzeProjects"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint

        for index in range(len(projectids)):
            projectids[index] = {"project_id": projectids[index]}

        json_data = json.dumps(projectids)
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint performs a search based on a series of parameters
    # "query" parameter is required is the text that the search will be applied upon.
    # "tbs" parameter is optional and indicates that the search will query for repositories.
    # "offset" parameter is optional and is for pagination purposes, it indicates at what
    # record to begin returning results on.
    # "limit" parameter is optional and describes the number of records to return for
    # pagination purposes.
    def search(self, query, tbs=None, offset=None, limit=None):
        """
        Will perform a search based on a series of specified parameters

        :param query: (String) This is the text that the search will be applied on
        :param tbs: (String) Optional parameter that indicates that the search will also query for repositories
        :param offset: (Integer) Optional parameter that is for pagination purposes, indicates at what record to begin retrieving results
        :param limit: (Integer) Optional parameter that describes the number of records to have retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object containing search results retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "search"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"q": query}

        if tbs is not None:
            parameters["tbs"] = tbs

        if offset is not None:
            parameters["offset"] = offset

        if limit is not None:
            parameters["limit"] = limit

        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return an array of users that are on a team
    # when inputted with the corresponding teamid
    def get_team_users(self, teamid):
        """
        Will get team users for a specified team

        :param teamid: (String) This is the team id for the team that users data will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing team user data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teamUsers/getTeamUsers"
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

    # This endpoint will create a new team when inputted with a name,
    # pocname, pocemail, and username
    def create_team(self, name, pocname, pocemail, username):
        """
        Will create a new team

        :param name: (String) This is the name of the newly created team
        :param pocnmae: (String) This is the name of the point of contact that created the team
        :param pocemail: (String) This is the email of the point of contact that created the team
        :param username: (String) This is the username of the point of contact that created the team
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a newly created team retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teams/establishTeam"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps(
            {
                "name": name,
                "poc_name": pocname,
                "poc_email": pocemail,
                "username": username,
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

    # This endpoint will update a team when inputted with teamid, name, pocname
    # pocemail, and a default deoploy key (openssh key / rsa key)
    def update_team(self, teamid, name, pocname, pocemail, defaultdeploykey):
        """
        Will update a specified team

        :param teamid: (String) This is the team id for the team that will be updated
        :param name: (String) This is the name of the team that will be updated
        :param pocnmae: (String) This is the name of the point of contact that will be updated
        :param pocemail: (String) This is the email of the point of contact that will be updated
        :param username: (String) This is the username of the point of contact that will be updated
        :param defaultdeploykey: (String) This is the default value for the deployment key, typically an openssh key/rsa key
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a updated team retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teams/updateTeam"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": teamid}
        json_data = json.dumps(
            {
                "name": name,
                "poc_name": pocname,
                "poc_email": pocemail,
                "default_deploy_key": defaultdeploykey,
            }
        )
        logging.debug(f"Http Destination: {URL}")
        r = requests.put(URL, headers=head, params=parameters, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will invite a user to a team, this endpoint requires a teamid
    # role and user id. Role can be 'memeber', 'admin', 'sysadmin' etc.
    def invite_team_user(self, teamid, role, userid, email=None):
        """
        Will invite a user to a team

        :oaram teamid: (String) This is the team id for the team that the invited user will have access to
        :param role: (String) This is the role that the invited user will have in the new team
        :param userid: (String) This is the user id for the user that is to be invited
        :param email: (String) Optional parameter to send an invite to a corresponding email
        :return: (Dictionary) or (Integer) Will return a dictionary object containing invited user data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teamUsers/inviteTeamUser"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = {"team_id": teamid, "role": role, "user_id": userid}
        if email is not None:
            json_data["email"] = email

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

    # This endpoint will return information regarding an invite when passed
    # a corresponding userid and invite token. The latter bearer token is then
    # passed through for authentication
    def get_team_invite(self, inviteid, invitetoken):
        """
        Will retrieve data regarding a specified invite

        :param inviteid: (String) This is the invite id for the invite that data is to be retrieved for
        :param invitetoken: (String) This is the bearer token of the invited user passed through for authentication
        :return: (Dictionary) or (Integer) Will return a dictionary object containing team invite data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teamUsers/getInvite"
        head = {"Authorization": "Bearer " + invitetoken}
        URL = self.baseURL + endpoint
        parameters = {"someid": inviteid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will accept an invite when passed with
    # a corresponding userid and invite token. The latter bearer token is then
    # passed through for authentication
    def accept_team_invite(self, inviteid, invitetoken):
        """
        Will accept a specified team invite

        :param inviteid: (String) This is the invite id for the invite that is to be accepted
        :param invitetoken: (String) This is the bearer token of the invited user passed through for authentication
        :return: (Byte/String), (Dictionary) or (Integer) Will return a dictionary object or empty byte string from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teamUsers/acceptInvite"
        head = {"Authorization": "Bearer " + invitetoken}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"someid": inviteid})
        logging.debug(f"Http Destination: {URL}")
        r = requests.put(URL, headers=head, data=json_data)
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

    # This endpoint will delete a user for a specific team based on the
    # corresponding teamuserid
    def delete_team_user(self, teamuserid):
        """
        Will delete a specified team user

        :param teamuserid: (String) This is the teamuser id for the team user that is to be deleted
        :return: (Dictionary) or (Integer) Will return a dictionary object containing deleted team user data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teamUsers/deleteTeamUser"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"someid": teamuserid})
        logging.debug(f"Http Destination: {URL}")
        r = requests.delete(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will resend an invite for a team user based on
    # a correspoinding invited
    def resend_invite_team_user(self, inviteid):
        """
        Will resend a specified invite

        :param inviteid: (String) This is the invite id for the invite that is to be resent
        :return: (Dictionary) or (Integer) Will return a dictionary object containing the resent team invite data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teamUsers/resendInvite"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"someid": inviteid})
        logging.debug(f"Http Destination: {URL}")
        r = requests.put(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will update a users role/status based on a corresponding
    # teamuserid, role = 'admin', 'member', 'sys_admin'?, etc.
    def update_team_user(self, teamuserid, role, status):
        """
        Will update a specified user's role and status

        :param teamuserid: (String) This is the teamuser id for the team user that is to be update
        :param role: (String) This is the role that will be authorized for the updated team user, eg. 'admin', 'member', etc.
        :param status: (String) This is the status that will be updated for the corresponding team user
        :return: (Dictionary) or (Integer) Will return a dictionary object containing updated team user data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teamUsers/updateTeamUser"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"someid": teamuserid, "role": role, "status": status})
        logging.debug(f"Http Destination: {URL}")
        r = requests.put(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

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

    # This enpoint will return a series of projects based on the corresponding
    # inputted dependency name, organization, and version
    def get_projectids_by_dependency(self, teamid, name, organization, version):
        """
        Will retrieve a series of projects based on specified parameters

        :param teamid: (String) This is the team id for the team that contains projects to be retrieived by dependency
        :param name: (String) This is the name of the dependency
        :param organization: (String) This is the name of the organization that the dependency belongs to
        :param version: (String) This is the version number of the corresponding dependency
        :return: (Dictionary) or (Integer) Will return a dictionary object containing projects that include the specified dependency from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getProjectsByDependency"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {
            "team_id": teamid,
            "name": name,
            "org": organization,
            "version": version,
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

    # This endpoint will return exported vulnerability data for a series of projects - projectids,
    # within a corresponding team - teamid, in a CSV formatted list
    def get_exported_vulnerability_data_csv(self, teamid, projectids):
        """
        Will get exported vulnerability data for a set of specified projects

        :param teamid: (String) This is the team id for the team that the corresponding projects are located within
        :param projectids: (String Array) This set of project ids correspond to projects that exported CSV data will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing exported vulnerability CSV data from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getExportedVulnerabilityData"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"team_id": teamid, "ids": projectids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

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

    # Fetches information corresponding to a user during an authenticated session
    def get_self(self):
        """
        Will retrieve user information for the current user during an authenticated session

        :return: (Dictionary) or (Integer) Will return a dictionary object containing user data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "users/getSelf"
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

    # This endpoint will fetch a list of users on a team, this information can only be viewed
    # by users with an admin or sysadmin status
    def get_users(self):
        """
        Will fetch a list of users on a team, this information can only be viewed by users with admin or sysadmin privileges

        :return: (Dictionary) or (Integer) Will return a dictionary object containing all team user data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "users/getUsers"
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

    # This endpoint will get usage information when inputted with a corresponding
    # team - teamid
    def get_usage_information(self, teamid):
        """
        Will get usage information for a specified team

        :param teamid: (String) This is the team id for the team that usage information is to be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a user's usage information retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "usage/info"
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

    # This endpoint will reset an account password, based on the user's
    # corresponding email
    def reset_password(self, email):
        """
        Will reset an account password for a currently logged in user

        :param email: (String) This is the email of the corresponding user that is resetting their password
        :return: (Dictionary) or (Integer) Will return a dictionary object confirming the reset password data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "users/resetPassword"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"email": email})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will complete signup by allowing a user to set a password after
    # they have been invited. This endpoint requires the invited user's username,
    # alongside corresponding password information
    def complete_signup(self, username, password, passwordConfirmation):
        """
        Will complete signup by allowing a user to set a password after they have been invited

        :param username: (String) This is the username of the invited user
        :param password: (String) This is the password that the invited user chooses
        :param passwordConfirmation: (String) This is where the user reenters the same password for confirmation purposes
        :return: (Dictionary) or (Integer) Will return a dictionary object showcasing completed signup data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "users/complete"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps(
            {
                "username": username,
                "password": password,
                "password_confirmation": passwordConfirmation,
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

    # This endpoint will update information corresponding to a specific user - userid,
    # If values are to be left unchanged, pass empty string: "" or don't pass the parameter
    # through to this function.
    def update_user(self, userid, email=None, username=None, password=None):
        """
        Will update a specfied user

        :param userid: (String) This is the user id for the user that is to be updated
        :param email: (String) Optional parameter to specify the updated email of the user, can also pass empty string if it's to remain unchanged
        :param username: (String) Optional parameter to specify the updated username of the user, can also pass empty string if it's to remain unchanged
        :param password: (String) Optional parameter to specify the updated password of the user, can also pass empty string if its to remain unchanged
        :return: (Dictionary) or (Integer) Will return a dictionary object showcasing updated user data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "users/updateUser"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = {"someid": userid}
        if email is not None and email != "":
            json_data["email"] = email
        if username is not None and username != "":
            json_data["username"] = username
        if password is not None and password != "":
            json_data["password"] = password
        json_data = json.dumps(json_data)
        logging.debug(f"Http Destination: {URL}")
        r = requests.put(URL, headers=head, data=json_data)
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

    # This endpoint will return the project status history for a set of
    # corresponding projects - projectids
    def get_projects_status_history(self, projectids):
        """
        Will retrieve the project status history for a set of specified projects

        :param projectids: (String Array) This is a set of project ids for projects that status history is to be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with project status-history data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/getStatusesHistory"
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

    # This endpoint takes in a teamid and an optional projectid. If projectid is given the
    # endpoint will return corresponding mttr information for the respective project, if projectid
    # is not given - defaut case set to None - the endpoint will return mttr information for all active
    # projects on the team
    def get_mttr(self, teamid, projectid=None):
        """
        Will retrieve mttr infromation for all active projects (or a specified project) on a specified team

        :param teamid: (String) This is the team id for the team that mttr information will be retrieved for
        :param projectids: (String) Optional parameter to specify a project to retrieve mttr information for
        :return: (Dictionary) or (Integer) Will return a dictionary object with mttr data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getMttr"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid}
        if projectid is not None:
            parameters["project_id"] = projectid
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return a set of projectids within a team that have the
    # corresponding dependency - name, organization, and version
    def get_projects_by_dependency(self, teamid, name, organization, version):
        """
        Will retrieve a set of projectids within a team that contain a specified dependency

        :param teamid: (String) This is the team id for the team where corresponding projects containing the specified dependency are located
        :param name: (String) This is the name of the specified dependency
        :param organization: (String) This is the organization of the specified dependency
        :param version: (String) This is the version of the specified dependency
        :return: (Dictionary) or (Integer) Will return a dictionary object with projectid sets retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/getProjectIdsByDependency"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {
            "team_id": teamid,
            "name": name,
            "org": organization,
            "version": version,
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

    # This endpoint will create a project, or a series of projects from a
    # correspondingly uploaded CSV file
    def create_projects_from_csv(self, teamid, csvfile):
        """
        Will create a project or a series of projects from a correspondingly uploaded CSV file

        :param teamid: (String) This is the team id for the team that the the CSV project will be created within
        :param csvfile: (String) This is the relative file path of the corresponding CSV file
        :return: (Dictionary) or (Integer) Will return a dictionary object with newly created project data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "project/createProjectsCSV"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid}
        file_data = {"file": open(csvfile, "r")}
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, params=parameters, files=file_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return project information when inputted with a corresponding
    # teamid and projectid
    def get_project(self, teamid, projectid):
        """
        Will get project information for a specified project

        :param teamid: (String) This is the team id for the team that the specified project is located within
        :param projectid: (String) This is the project id for the project that data will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with product data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "project/getProject"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "id": projectid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return raw project information when inputted with a corresponding
    # teamid and projectid
    def get_raw_project(self, teamid, projectid):
        """
        Will get raw project information for a specified project

        :param teamid: (String) This is the team id for the team that the specified project is located within
        :param projectid: (String) This is the project id for the project that data will be retrieved for
        :return: (JSON Object) or (Integer) Will return a JSON object with product data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "project/getProject"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid, "id": projectid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content

    # This endpoint will return project information based on a corresponding uri
    # and teamid
    def get_project_by_url(self, teamid, uri):
        """
        Will retrieve project information for a specified uri

        :param teamid: (String) This is the team id for the team that the corresponding project is located within
        :param uri: (String) This is the URI for the projects github repository
        :return: (Dictionary) or (Integer) Will return a dictionary object with URI specified product data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "project/getProjectByUrl"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"url": uri, "team_id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
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

    # This endpoint will return projectnames for all correspondingly inputted projects - projectids
    # and the team in which they are located - teamid
    def get_projects_names(self, teamid, projectids):
        """
        Will retrieve project names for all specified projects

        :param teamid: (String) This is the team id for the team that the corresponding projects are located within
        :param projectids: (String Array) This is the set of project ids for projects that will have their names retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object with project names retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "project/getProjectsNames"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"team_id": teamid, "IDs": projectids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return the related/tangential analysis to the analysis provided
    # when inputted with the corresponding teamid, projectid, and analysisid
    # This endpoint might be DEPRECATED
    def get_analysis_navigation(self, teamid, projectid, analysisid):
        """
        Will retrieve the related/tangential analysis to the specified analysis

        :param teamid: (String) This is the team id for the team that the corresponding project that underwent analysis is located
        :param projectid: (String) This is the project id for the project that underwent an analysis
        :param analysisid: (String) This is the analysis id for the analysis that tangential analysis content is to be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with related analysis data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "report/getAnalysisNav"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {
            "team_id": teamid,
            "project_id": projectid,
            "analysis_id": analysisid,
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

    # This endpoint will return the status of a series of analyses when inputted with the
    # corresponding teamid and analysisids - array
    def get_analyses_statuses(self, teamid, analysisids):
        """
        Will retrieve the statuses for a set of specified analyses

        :param teamid: (String) This is the team id for the team that the projects that underwent analysis are located
        :param analysisids: (String Array) This is the set of analysis ids for analyses that will have their status retrieved
        :return: (Dictionary) or (Integer) Will return a dictionary object with analyses statuses retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "ruleset/getAnalysesStatuses"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps({"team_id": teamid, "IDs": analysisids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return the latest analysis statuses when inputted with
    # the corresponding team - teamid
    def get_latest_analysis_statuses(self, teamid):
        """
        Will retrieve the latest analysis statuses for a specified team

        :param teamid: (String) This is the team id for the team that contains projects that underwent analysis
        :return: (Dictionary) or (Integer) Will return a dictionary object with latest analysis statuses retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "scanner/getLatestAnalysisStatuses"
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

    # This endpoint will return project states when inputted with a corresponding list of projects - projectids
    # This endpoint has an optional filter parameter which allows users to pass a string to filter state results
    def get_project_states(self, projectids, filter=None):
        """
        Will retrieve project states for a specified set of projects

        :param projectids: (String Array) This is a set of project ids for projects that will have their states retrieved
        :param filter: (String) Optional parameter to filter retrieved state results
        :return: (Dictionary) or (Integer) Will return a dictionary object with corresponding project states retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "scanner/getProjectsStates"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = {"IDs": projectids}

        if filter is not None:
            json_data["Filter"] = filter

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

    # This endpoint will search for a series of scans within a team - teamid
    # and return corresponding data, this endpoint has a searchParams parameters
    # which takes in a dictionary, that has two fields to help filter search results.
    # Search Parameter Example:
    # {
    #     "analysis_ids": ["analysisid1", "analysisid2"],
    #     "scan_types": ["scanfilter1", "scanfilter2"]
    # }
    def find_scans(self, searchParams, teamid):
        """
        Will search for a series of scans within a specified team

        :param searchParams: (Dictionary) This is to help filter search results: Search Parameter Example: {"analysis_ids": ["analysisid1", "analysisid2"], "scan_types": ["scanfilter1", "scanfilter2"]}
        :param teamid: (String) This is the team id for the team that the scans will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with scans retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "animal/findScans"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid}
        json_data = json.dumps(searchParams)
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, params=parameters, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

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

    # This endpoint will create a new tag when inputted with a corresponidng team - teamid,
    # name, and description
    def create_tag(self, teamid, name, description):
        """
        Will create a new tag for a specified team

        :param teamid: (String) This is the team id for the team that the tag is to be created for
        :param name: (String) This is the name of the tag
        :param description: (String) This is the description of the tag
        :return: (Dictionary) or (Integer) Will return a dictionary object containing a newly created tag retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/createTag"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps(
            {"team_id": teamid, "Name": name, "description": description}
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

    # This endpoint will update a tag's information when inputted with a corresponding, tagid,
    # teamid, name, and description
    def update_tag(self, tagid, teamid, name, description):
        """
        Will update a tag for a specified team

        :param tagid: (String) This is the tag id for the tag that is to be updated
        :param teamid: (String) This is the team id for the team that the tag is to be updated for
        :param name: (String) This is the updated name of the tag
        :param description: (String) This is the updated description of the tag
        :return: (Dictionary) or (Integer) Will return a dictionary object containing an updated tag retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/updateTag"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps(
            {"ID": tagid, "team_id": teamid, "Name": name, "Description": description}
        )
        logging.debug(f"Http Destination: {URL}")
        r = requests.put(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return information about a respective tag when inputted with a correspondiing
    # tagid - tag identifier, and teamid - team identifier
    def get_tag(self, tagid, teamid):
        """
        Will retrieve information about a specified tag

        :param tagid: (String) This is the tag id for the tag that data will be retrieved for
        :param teamid: (String) This is the team id for the team the corresponding tag is located within
        :return: (Dictionary) or (Integer) Will return a dictionary object with tag data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/getTag"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": tagid, "team_id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return raw information about a respective tag when inputted with a correspondiing
    # tagid - tag identifier, and teamid - team identifier
    def get_raw_tag(self, tagid, teamid):
        """
        Will retrieve raw information about a specified tag

        :param tagid: (String) This is the tag id for the tag that data will be retrieved for
        :param teamid: (String) This is the team id for the team the corresponding tag is located within
        :return: (JSON Object) or (Integer) Will return a JSON object with tag data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/getTag"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": tagid, "team_id": teamid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        return r.content

    # This endpoint will return information regarding all tags for a corrsponding
    # team - takes in teamid
    def get_tags(self, teamid):
        """
        Will retrieve information for all tags within a specified team

        :param teamid: (String) This is the team id for the team that all tags will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with all tag data for a team retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/getTags"
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

    # This endpoint will return raw information regarding all tags for a corrsponding
    # team - takes in teamid
    def get_raw_tags(self, teamid):
        """
        Will retrieve raw information for all tags within a specified team

        :param teamid: (String) This is the team id for the team that all tags will be retrieved for
        :return: (JSON Object) or (Integer) Will return a JSON object with all tag data for a team retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "tag/getTags"
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
        return r.content

    def create_user(self, email, name, username, password):
        """
        Will create a new user when inputted with specified parameters

        :param email: (String) This is the email for the new user
        :param name: (String) This is the name of the new user
        :param username: (String) This is the username for the new user
        :param password: (String) This is the password for the new user
        :return: (Dictionary) or (Integer) Will return a dictionary object with newly created user data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "users/signup"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps(
            {
                "email": email,
                "name": name,
                "username": username,
                "password": password,
                "password_confirmation": password,
            }
        )
        r = requests.post(URL, headers=head, data=json_data)

        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint takes in a dictionary with the fields:
    # status, role, team_id, and user_id, and adds a user to the latter corresponding
    # team
    def create_team_user(self, teamuseroptions):
        """
        Will create a new team user when inputted with the specified parameters

        :param teamuseroptions: (Dictionary) This is a set of parameters status, role, team_id, and user_id, that will create a new team user eg. {"team_id": "21acb344-1010-4a6c-8b63-544c9cb72c71", "user_id": "74996a06-7df8-4867-b915-8fc262167955", "role": "admin", "status": "active"}
        :return: (Dictionary) or (Integer) Will return a dictionary object with newly created team user data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "teamUsers/createTeamUser"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        json_data = json.dumps(teamuseroptions)
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint will return information regarding a user when inputted with a
    # corresponding userid
    def get_user(self, userid):
        """
        Will retrieve information for a specified user

        :param userid: (String) This is the user id for the user that data will be retrieved for
        :return: (Dictionary) or (Integer) Will return a dictionary object with user data retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "users/getUser"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"id": userid}
        logging.debug(f"Http Destination: {URL}")
        r = requests.get(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

    # This endpoint takes in an array of userids and a corresponding teamid,
    # and will return a set of respective usernames
    def get_user_names(self, userids, teamid):
        """
        Will retrieve usernames for a specified set of users

        :param userids: (String Array) This is a set of user ids for users that are to have their usernames retrieved
        :param teamid: (String) This is the team id for the team that the corresponing users are located within
        :return: (Dictionary) or (Integer) Will return a dictionary object with a set of usernames retrieved from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "users/getUserNames"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"team_id": teamid}
        json_data = json.dumps({"IDs": userids})
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, params=parameters, data=json_data)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

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


# This function will create a new client object so that the user can interact with the API
def new_client(baseURL):
    """Will create a new client object so that the user can interact with the Ion API

    :param baseURL: (String) Base URL to interact with API
    :return: (IonChannel Object) Creates and returns a new client object
    """
    client = IonChannel(baseURL)
    return client
