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

class Team:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

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

    # This endpoint will create a new team when inputted with a name,
    # pocname, pocemail, and username
    def create_team(self, name, pocname, pocemail, username):
        """
        Will create a new team

        :param name: (String) This is the name of the newly created team
        :param pocname: (String) This is the name of the point of contact that created the team
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
        :param pocname: (String) This is the name of the point of contact that will be updated
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