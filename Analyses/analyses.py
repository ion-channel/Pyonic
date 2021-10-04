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


class Analysis:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

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

    # This endpoint will return the related/tangential analysis to the analysis provided
    # when inputted with the corresponding teamid, projectid, and analysisid
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
