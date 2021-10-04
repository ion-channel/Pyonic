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


class User:
    def __init__(self, baseURL):
        self.baseURL = baseURL
        self.token = None

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
