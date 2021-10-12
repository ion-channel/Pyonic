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


class Report:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

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

    def get_SBOMs(self, organizationid, status):
        """
        Will get content for a set of SBOMs within an organization

        :param organizationid: (String) This is the organization id for the organization that SBOMs will be retrieved for
        :param status: (String) This is the status of the organization
        :return: (Dictionary) or (Integer) Will return a dictionary object with a set of SBOMs from the API, if errored will return -1 or throw an Exception
        """
        endpoint = "project/getSBOMs"
        head = {"Authorization": "Bearer " + self.token}
        URL = self.baseURL + endpoint
        parameters = {"org_id": organizationid, "status": status}
        logging.debug(f"Http Destination: {URL}")
        r = requests.post(URL, headers=head, params=parameters)
        logging.debug(f"Request Type: {r.request}")
        logging.debug(f"Status Code: {r.status_code}")
        check = response_handler(r)
        if check != 0:
            return -1
        dictionary_data = json.loads(r.content)
        return dictionary_data

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
