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

class Project:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

    # This endpoint will create a project object
    def create_project(self, teamid, project):
        """
        Will create a project for a specified team

        :param teamid: (String) This is the team id for the team in which the new project will be created
        :param project: (Dictionary) This is the project object that will be created under the corrsponding team
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