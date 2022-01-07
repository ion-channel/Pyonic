import pyonic
from pyonic.client import IonChannel
import pytest
import json

ion_client = pyonic.new_client("https://api.test.ionchannel.io/v1/")


def test_login():
    try:
        # If environment variables are set
        t_login = ion_client.login()
        assert ("data" in t_login) == True
        assert ("jwt" in t_login["data"]) == True
        assert ("user" in t_login["data"]) == True

    except KeyError:
        # If environment variables are not set
        with pytest.raises(KeyError):
            ion_client.login()


def test_create_project():
    team_id = "95d06aa3-ec21-4602-86c2-c79605d81d09"
    project = {
        "active": True,
        "description": "This is a test edit to test an endpoint, through SDK.",
        "name": "Final SDK change - Modded Project",
        "ruleset_id": "c69fcc06-154f-44c7-9c26-6484580c60bd",
        "team_id": "646fa3e5-e274-4884-aef2-1d47f029c289",
        "type": "source_unavailable",
        "id": "e2a088f0-e6eb-4666-9cdd-f915b8cb2053",
        "source": "",
    }
    t_status = ion_client.create_project(team_id, project)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("ruleset_id" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("type" in t_status["data"]) == True
    assert ("source" in t_status["data"]) == True
    assert ("id" in t_status["data"]) == True
    assert ("active" in t_status["data"]) == True
    assert ("draft" in t_status["data"]) == True
    assert ("chat_channel" in t_status["data"]) == True
    assert ("created_at" in t_status["data"]) == True
    assert ("updated_at" in t_status["data"]) == True
    assert ("deploy_key" in t_status["data"]) == True
    assert ("should_monitor" in t_status["data"]) == True
    assert ("monitor_frequency" in t_status["data"]) == True
    assert ("poc_name" in t_status["data"]) == True
    assert ("poc_email" in t_status["data"]) == True
    assert ("username" in t_status["data"]) == True
    assert ("password" in t_status["data"]) == True
    assert ("key_fingerprint" in t_status["data"]) == True
    assert ("private" in t_status["data"]) == True
    assert ("aliases" in t_status["data"]) == True
    assert ("tags" in t_status["data"]) == True
    assert ("ruleset_history" in t_status["data"]) == True
    assert ("sbom_id" in t_status["data"]) == True
    assert ("sbom_entry_id" in t_status["data"]) == True
    assert ("cpe" in t_status["data"]) == True
    assert ("purl" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["name"] == "Final SDK change - Modded Project"
    assert (
        t_status["data"]["description"]
        == "This is a test edit to test an endpoint, through SDK."
    )
    assert t_status["data"]["active"] == True


def test_get_project():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "27691314-3598-4abe-9293-e94b3eaa2287"
    t_status = ion_client.get_project(team_id, project_id)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("ruleset_id" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("type" in t_status["data"]) == True
    assert ("source" in t_status["data"]) == True
    assert ("branch" in t_status["data"]) == True
    assert ("description" in t_status["data"]) == True
    assert ("active" in t_status["data"]) == True
    assert ("draft" in t_status["data"]) == True
    assert ("chat_channel" in t_status["data"]) == True
    assert ("id" in t_status["data"]) == True
    assert ("created_at" in t_status["data"]) == True
    assert ("updated_at" in t_status["data"]) == True
    assert ("deploy_key" in t_status["data"]) == True
    assert ("should_monitor" in t_status["data"]) == True
    assert ("monitor_frequency" in t_status["data"]) == True
    assert ("poc_name" in t_status["data"]) == True
    assert ("poc_email" in t_status["data"]) == True
    assert ("username" in t_status["data"]) == True
    assert ("password" in t_status["data"]) == True
    assert ("key_fingerprint" in t_status["data"]) == True
    assert ("private" in t_status["data"]) == True
    assert ("aliases" in t_status["data"]) == True
    assert ("ruleset_history" in t_status["data"]) == True
    assert ("sbom_id" in t_status["data"]) == True
    assert ("sbom_entry_id" in t_status["data"]) == True
    assert ("cpe" in t_status["data"]) == True
    assert ("purl" in t_status["data"]) == True
    assert t_status["data"]["id"] == project_id
    assert t_status["data"]["name"] == "pepe"
    assert t_status["data"]["branch"] == "master"
    assert t_status["data"]["active"] == True


def test_get_raw_project():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "27691314-3598-4abe-9293-e94b3eaa2287"
    t_status = json.loads(ion_client.get_raw_project(team_id, project_id))
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("ruleset_id" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("type" in t_status["data"]) == True
    assert ("source" in t_status["data"]) == True
    assert ("branch" in t_status["data"]) == True
    assert ("description" in t_status["data"]) == True
    assert ("active" in t_status["data"]) == True
    assert ("draft" in t_status["data"]) == True
    assert ("chat_channel" in t_status["data"]) == True
    assert ("id" in t_status["data"]) == True
    assert ("created_at" in t_status["data"]) == True
    assert ("updated_at" in t_status["data"]) == True
    assert ("deploy_key" in t_status["data"]) == True
    assert ("should_monitor" in t_status["data"]) == True
    assert ("monitor_frequency" in t_status["data"]) == True
    assert ("poc_name" in t_status["data"]) == True
    assert ("poc_email" in t_status["data"]) == True
    assert ("username" in t_status["data"]) == True
    assert ("password" in t_status["data"]) == True
    assert ("key_fingerprint" in t_status["data"]) == True
    assert ("private" in t_status["data"]) == True
    assert ("aliases" in t_status["data"]) == True
    assert ("ruleset_history" in t_status["data"]) == True
    assert ("sbom_id" in t_status["data"]) == True
    assert ("sbom_entry_id" in t_status["data"]) == True
    assert ("cpe" in t_status["data"]) == True
    assert ("purl" in t_status["data"]) == True
    assert t_status["data"]["id"] == project_id
    assert t_status["data"]["name"] == "pepe"
    assert t_status["data"]["branch"] == "master"
    assert t_status["data"]["active"] == True


def test_get_project_by_url():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    uri = "git@github.com:ion-channel/statler.git"
    t_status = ion_client.get_project_by_url(team_id, uri)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("ruleset_id" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("type" in t_status["data"]) == True
    assert ("source" in t_status["data"]) == True
    assert ("id" in t_status["data"]) == True
    assert ("active" in t_status["data"]) == True
    assert ("draft" in t_status["data"]) == True
    assert ("chat_channel" in t_status["data"]) == True
    assert ("created_at" in t_status["data"]) == True
    assert ("updated_at" in t_status["data"]) == True
    assert ("deploy_key" in t_status["data"]) == True
    assert ("should_monitor" in t_status["data"]) == True
    assert ("monitor_frequency" in t_status["data"]) == True
    assert ("poc_name" in t_status["data"]) == True
    assert ("poc_email" in t_status["data"]) == True
    assert ("username" in t_status["data"]) == True
    assert ("password" in t_status["data"]) == True
    assert ("key_fingerprint" in t_status["data"]) == True
    assert ("private" in t_status["data"]) == True
    assert ("aliases" in t_status["data"]) == True
    assert ("tags" in t_status["data"]) == True
    assert ("ruleset_history" in t_status["data"]) == True
    assert ("sbom_id" in t_status["data"]) == True
    assert ("sbom_entry_id" in t_status["data"]) == True
    assert ("cpe" in t_status["data"]) == True
    assert ("purl" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["name"] == "Statler"
    assert t_status["data"]["description"] == "the reporting service"
    assert t_status["data"]["active"] == True


def test_get_projects():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    t_status = ion_client.get_projects(team_id)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("id" in t_status["data"][0]) == True
    assert ("team_id" in t_status["data"][0]) == True
    assert ("ruleset_id" in t_status["data"][0]) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("type" in t_status["data"][0]) == True
    assert ("source" in t_status["data"][0]) == True
    assert ("id" in t_status["data"][0]) == True
    assert ("active" in t_status["data"][0]) == True
    assert ("draft" in t_status["data"][0]) == True
    assert ("chat_channel" in t_status["data"][0]) == True
    assert ("created_at" in t_status["data"][0]) == True
    assert ("updated_at" in t_status["data"][0]) == True
    assert ("deploy_key" in t_status["data"][0]) == True
    assert ("should_monitor" in t_status["data"][0]) == True
    assert ("monitor_frequency" in t_status["data"][0]) == True
    assert ("poc_name" in t_status["data"][0]) == True
    assert ("poc_email" in t_status["data"][0]) == True
    assert ("username" in t_status["data"][0]) == True
    assert ("password" in t_status["data"][0]) == True
    assert ("key_fingerprint" in t_status["data"][0]) == True
    assert ("private" in t_status["data"][0]) == True
    assert ("aliases" in t_status["data"][0]) == True
    assert ("tags" in t_status["data"][0]) == True
    assert ("ruleset_history" in t_status["data"][0]) == True
    assert ("sbom_id" in t_status["data"][0]) == True
    assert ("sbom_entry_id" in t_status["data"][0]) == True
    assert ("cpe" in t_status["data"][0]) == True
    assert ("purl" in t_status["data"][0]) == True
    assert ("id" in t_status["data"][1]) == True
    assert ("team_id" in t_status["data"][1]) == True
    assert ("ruleset_id" in t_status["data"][1]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("type" in t_status["data"][1]) == True
    assert ("source" in t_status["data"][1]) == True
    assert ("id" in t_status["data"][1]) == True
    assert ("active" in t_status["data"][1]) == True
    assert ("draft" in t_status["data"][1]) == True
    assert ("chat_channel" in t_status["data"][1]) == True
    assert ("created_at" in t_status["data"][1]) == True
    assert ("updated_at" in t_status["data"][1]) == True
    assert ("deploy_key" in t_status["data"][1]) == True
    assert ("should_monitor" in t_status["data"][1]) == True
    assert ("monitor_frequency" in t_status["data"][1]) == True
    assert ("poc_name" in t_status["data"][1]) == True
    assert ("poc_email" in t_status["data"][1]) == True
    assert ("username" in t_status["data"][1]) == True
    assert ("password" in t_status["data"][1]) == True
    assert ("key_fingerprint" in t_status["data"][1]) == True
    assert ("private" in t_status["data"][1]) == True
    assert ("aliases" in t_status["data"][1]) == True
    assert ("tags" in t_status["data"][1]) == True
    assert ("ruleset_history" in t_status["data"][1]) == True
    assert ("sbom_id" in t_status["data"][1]) == True
    assert ("sbom_entry_id" in t_status["data"][1]) == True
    assert ("cpe" in t_status["data"][1]) == True
    assert ("purl" in t_status["data"][1]) == True


def test_update_project():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project = {
        "active": False,
        "description": "This is a test edit to test an endpoint, through SDK.",
        "name": "Final SDK change - Modded Project",
        "ruleset_id": "c69fcc06-154f-44c7-9c26-6484580c60bd",
        "team_id": "646fa3e5-e274-4884-aef2-1d47f029c289",
        "type": "source_unavailable",
        "id": "e2a088f0-e6eb-4666-9cdd-f915b8cb2053",
        "source": "",
    }
    t_status = ion_client.update_project(team_id, project)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("ruleset_id" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("type" in t_status["data"]) == True
    assert ("source" in t_status["data"]) == True
    assert ("id" in t_status["data"]) == True
    assert ("active" in t_status["data"]) == True
    assert ("draft" in t_status["data"]) == True
    assert ("chat_channel" in t_status["data"]) == True
    assert ("created_at" in t_status["data"]) == True
    assert ("updated_at" in t_status["data"]) == True
    assert ("deploy_key" in t_status["data"]) == True
    assert ("should_monitor" in t_status["data"]) == True
    assert ("monitor_frequency" in t_status["data"]) == True
    assert ("poc_name" in t_status["data"]) == True
    assert ("poc_email" in t_status["data"]) == True
    assert ("username" in t_status["data"]) == True
    assert ("password" in t_status["data"]) == True
    assert ("key_fingerprint" in t_status["data"]) == True
    assert ("private" in t_status["data"]) == True
    assert ("aliases" in t_status["data"]) == True
    assert ("tags" in t_status["data"]) == True
    assert ("ruleset_history" in t_status["data"]) == True
    assert ("sbom_id" in t_status["data"]) == True
    assert ("sbom_entry_id" in t_status["data"]) == True
    assert ("cpe" in t_status["data"]) == True
    assert ("purl" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["name"] == "Final SDK change - Modded Project"
    assert (
        t_status["data"]["description"]
        == "This is a test edit to test an endpoint, through SDK."
    )
    assert t_status["data"]["active"] == False


def test_add_alias():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    name = "name"
    version = "version"
    org = "org"
    t_status = ion_client.add_alias(team_id, project_id, name, version, org)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("org" in t_status["data"]) == True
    assert ("created_at" in t_status["data"]) == True
    assert ("updated_at" in t_status["data"]) == True
    assert ("version" in t_status["data"]) == True
    assert t_status["data"]["name"] == "name"
    assert t_status["data"]["org"] == "org"
    assert t_status["data"]["version"] == "version"


def test_update_ruleset_for_project():
    ruleset_id = "86ee6e2f-95d5-47f5-9d73-86d7712d6889"
    project_ids = ["27691314-3598-4abe-9293-e94b3eaa2287"]
    t_status = ion_client.update_ruleset_for_project(ruleset_id, project_ids)
    assert ("data" in t_status) == True
    assert ("succeeded" in t_status["data"]) == True
    assert ("failed" in t_status["data"]) == True
    try:
        assert t_status["data"]["succeeded"] == []
        assert t_status["data"]["failed"] == []
    except AssertionError:
        assert t_status["data"]["succeeded"] == project_ids[0]
        assert t_status["data"]["failed"] == []


def test_update_projects():
    project_ids = [
        "107d601d-1deb-4dcb-89c9-684ab8550565",
        "2a7398fa-ee8b-4f2c-9c58-c0b720b78441",
    ]
    project = {"monitor": True}
    t_status = ion_client.update_projects(project_ids, project)
    assert ("data" in t_status) == True
    assert ("succeeded" in t_status["data"]) == True
    assert ("failed" in t_status["data"]) == True
    assert len(t_status["data"]["succeeded"]) > 0
    assert t_status["data"]["succeeded"][0] == project_ids[0]
    assert t_status["data"]["succeeded"][1] == project_ids[1]
    assert t_status["data"]["failed"] == []


def test_get_project_names():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_ids = [
        "90360692-dfec-46ac-8248-a8be96a48ee3",
        "27691314-3598-4abe-9293-e94b3eaa2287",
        "29c4fb49-c685-473e-bfb3-6ecce155c3ad",
    ]
    t_status = ion_client.get_projects_names(team_id, project_ids)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("project_id" in t_status["data"][0]) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("product_name" in t_status["data"][0]) == True
    assert ("version" in t_status["data"][0]) == True
    assert ("org" in t_status["data"][0]) == True
    assert ("project_id" in t_status["data"][1]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("product_name" in t_status["data"][1]) == True
    assert ("version" in t_status["data"][1]) == True
    assert ("org" in t_status["data"][1]) == True
    assert ("project_id" in t_status["data"][2]) == True
    assert ("name" in t_status["data"][2]) == True
    assert ("product_name" in t_status["data"][2]) == True
    assert ("version" in t_status["data"][2]) == True
    assert ("org" in t_status["data"][2]) == True
    assert t_status["data"][0]["project_id"] == project_ids[1]
    assert t_status["data"][0]["name"] == "pepe"
    assert t_status["data"][1]["project_id"] == project_ids[2]
    assert t_status["data"][1]["name"] == "bunsen"
    assert t_status["data"][2]["project_id"] == project_ids[0]
    assert t_status["data"][2]["name"] == "angular.js"


def test_get_project_states():
    project_ids = [
        "27691314-3598-4abe-9293-e94b3eaa2287",
        "90360692-dfec-46ac-8248-a8be96a48ee3",
    ]
    t_status = ion_client.get_project_states(project_ids)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("id" in t_status["data"][0]) == True
    assert ("status" in t_status["data"][0]) == True
    assert ("analysis_id" in t_status["data"][0]) == True
    assert ("id" in t_status["data"][1]) == True
    assert ("status" in t_status["data"][1]) == True
    assert ("analysis_id" in t_status["data"][1]) == True
    assert project_ids[0] or project_ids[1] in t_status["data"][0]["id"]
    assert project_ids[0] or project_ids[1] in t_status["data"][1]["id"]


def test_get_projects_by_dependency():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    name = "lodash"
    organization = "lodash"
    version = "4.17.5"
    t_status = ion_client.get_projects_by_dependency(
        team_id, name, organization, version
    )
    assert ("data" in t_status) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("org" in t_status["data"]) == True
    assert ("version" in t_status["data"]) == True
    assert ("project_ids" in t_status["data"]) == True
    assert len(t_status["data"]["project_ids"]) > 0
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["name"] == name
    assert t_status["data"]["org"] == organization
    assert t_status["data"]["version"] == version
    assert t_status["data"]["project_ids"][0] == "90360692-dfec-46ac-8248-a8be96a48ee3"


def test_get_portfolio_affected_projects_info():
    ids = [
        "90360692-dfec-46ac-8248-a8be96a48ee3",
        "27691314-3598-4abe-9293-e94b3eaa2287",
    ]
    t_status = ion_client.get_portfolio_affected_projects_info(ids)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("id" in t_status["data"][0]) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("version" in t_status["data"][0]) == True
    assert ("vulnerabilities" in t_status["data"][0]) == True
    assert ("id" in t_status["data"][1]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("version" in t_status["data"][1]) == True
    assert ("vulnerabilities" in t_status["data"][1]) == True
    assert t_status["data"][0]["id"] == ids[1]
    assert t_status["data"][0]["name"] == "pepe"
    assert t_status["data"][0]["version"] == "all"
    assert t_status["data"][1]["id"] == ids[0]
    assert t_status["data"][1]["name"] == "angular.js"
    assert t_status["data"][1]["version"] == "version"


def test_get_portfolio_affected_projects():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    external_id = "a537c6c7-1a59-4d9b-b467-3a3fd1ca849f"
    t_status = ion_client.get_portfolio_affected_projects(team_id, external_id)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) == 0


def test_get_portfolio_pass_fail_summary():
    project_ids = [
        "90360692-dfec-46ac-8248-a8be96a48ee3",
        "27691314-3598-4abe-9293-e94b3eaa2287",
    ]
    t_status = ion_client.get_portfolio_pass_fail_summary(project_ids)
    assert ("data" in t_status) == True
    assert ("passing_projects" in t_status["data"]) == True
    assert ("failing_projects" in t_status["data"]) == True


def test_get_projects_status_history():
    project_ids = [
        "90360692-dfec-46ac-8248-a8be96a48ee3",
        "27691314-3598-4abe-9293-e94b3eaa2287",
    ]
    t_status = ion_client.get_projects_status_history(project_ids)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("status" in t_status["data"][0]) == True
    assert ("count" in t_status["data"][0]) == True
    assert ("first_created_at" in t_status["data"][0]) == True
    assert ("status" in t_status["data"][1]) == True
    assert ("count" in t_status["data"][1]) == True
    assert ("first_created_at" in t_status["data"][1]) == True
    assert ("status" in t_status["data"][2]) == True
    assert ("count" in t_status["data"][2]) == True
    assert ("first_created_at" in t_status["data"][2]) == True
