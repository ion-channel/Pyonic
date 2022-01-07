import pyonic
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


def test_analysis_status():
    analyses_id = "bf556a9e-e292-4aa9-a0c4-2b4785a66375"
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    t_status = ion_client.analysis_status(team_id, project_id, analyses_id)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert t_status["data"]["id"] == analyses_id
    assert ("team_id" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert ("project_id" in t_status["data"]) == True
    assert t_status["data"]["project_id"] == project_id
    assert ("status" in t_status["data"]) == True
    assert ("scan_status" in t_status["data"]) == True
    assert len(t_status["data"]["scan_status"]) > 0
    assert t_status["data"]["scan_status"][0]["analysis_status_id"] == analyses_id
    assert t_status["data"]["scan_status"][0]["project_id"] == project_id
    assert t_status["data"]["scan_status"][0]["team_id"] == team_id
    assert t_status["data"]["scan_status"][1]["read"] == "false"


def test_get_portfolio_started_errored_summary():
    project_ids = [
        "90360692-dfec-46ac-8248-a8be96a48ee3",
        "27691314-3598-4abe-9293-e94b3eaa2287",
    ]
    t_status = ion_client.get_portfolio_started_errored_summary(project_ids)
    assert ("data" in t_status) == True
    assert ("analyzing_projects" in t_status["data"]) == True
    assert ("errored_projects" in t_status["data"]) == True
    assert ("finished_projects" in t_status["data"]) == True
    # assert (t_status["data"]["finished_projects"] == 2)


def test_get_latest_analysis():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    t_status = ion_client.get_latest_analysis(team_id, project_id)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("project_id" in t_status["data"]) == True
    assert ("type" in t_status["data"]) == True
    assert ("source" in t_status["data"]) == True
    assert ("branch" in t_status["data"]) == True
    assert ("ruleset_id" in t_status["data"]) == True
    assert ("status" in t_status["data"]) == True
    assert ("scan_summaries" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["project_id"] == project_id
    assert t_status["data"]["name"] == "angular-js"
    assert t_status["data"]["type"] == "git"
    assert t_status["data"]["source"] == "https://github.com/cirruspath/angular.js"
    assert t_status["data"]["ruleset_id"] == "c69fcc06-154f-44c7-9c26-6484580c60bd"


def test_get_latest_analysis_status():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    t_status = ion_client.get_latest_analysis_status(team_id, project_id)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert ("project_id" in t_status["data"]) == True
    assert t_status["data"]["project_id"] == project_id
    assert ("status" in t_status["data"]) == True
    assert ("scan_status" in t_status["data"]) == True
    assert len(t_status["data"]["scan_status"]) > 0
    assert t_status["data"]["scan_status"][0]["team_id"] == team_id


def test_get_analysis():
    analyses_id = "bf556a9e-e292-4aa9-a0c4-2b4785a66375"
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    t_status = ion_client.get_analysis(team_id, project_id, analyses_id)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("analysis_id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("project_id" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("text" in t_status["data"]) == True
    assert ("type" in t_status["data"]) == True
    assert ("source" in t_status["data"]) == True
    assert ("branch" in t_status["data"]) == True
    assert ("description" in t_status["data"]) == True
    assert ("summary" in t_status["data"]) == True
    assert ("ruleset_id" in t_status["data"]) == True
    assert ("status" in t_status["data"]) == True
    assert ("created_at" in t_status["data"]) == True
    assert ("updated_at" in t_status["data"]) == True
    assert ("duration" in t_status["data"]) == True
    assert ("trigger_hash" in t_status["data"]) == True
    assert ("trigger_text" in t_status["data"]) == True
    assert ("trigger_author" in t_status["data"]) == True
    assert ("trigger" in t_status["data"]) == True
    assert ("scan_summaries" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["project_id"] == project_id
    assert t_status["data"]["name"] == "angular-js"
    assert t_status["data"]["type"] == "git"
    assert t_status["data"]["source"] == "https://github.com/cirruspath/angular.js"
    assert t_status["data"]["ruleset_id"] == "c69fcc06-154f-44c7-9c26-6484580c60bd"


def test_get_analyses():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    t_status = ion_client.get_analyses(team_id, project_id)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("id" in t_status["data"][0]) == True
    assert ("team_id" in t_status["data"][0]) == True
    assert ("project_id" in t_status["data"][0]) == True
    assert ("type" in t_status["data"][0]) == True
    assert ("source" in t_status["data"][0]) == True
    assert ("branch" in t_status["data"][0]) == True
    assert ("ruleset_id" in t_status["data"][0]) == True
    assert ("status" in t_status["data"][0]) == True
    assert ("scan_summaries" in t_status["data"][0]) == True
    assert t_status["data"][0]["team_id"] == team_id
    assert t_status["data"][0]["project_id"] == project_id
    assert t_status["data"][0]["name"] == "angular-js"
    assert t_status["data"][0]["type"] == "git"
    assert t_status["data"][0]["source"] == "https://github.com/cirruspath/angular.js"
    assert t_status["data"][0]["ruleset_id"] == "c69fcc06-154f-44c7-9c26-6484580c60bd"


def test_get_latest_analysis_summary():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    t_status = ion_client.get_latest_analysis_summary(team_id, project_id)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("analysis_id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("project_id" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("text" in t_status["data"]) == True
    assert ("type" in t_status["data"]) == True
    assert ("source" in t_status["data"]) == True
    assert ("branch" in t_status["data"]) == True
    assert ("description" in t_status["data"]) == True
    assert ("summary" in t_status["data"]) == True
    assert ("ruleset_id" in t_status["data"]) == True
    assert ("status" in t_status["data"]) == True
    assert ("created_at" in t_status["data"]) == True
    assert ("updated_at" in t_status["data"]) == True
    assert ("duration" in t_status["data"]) == True
    assert ("trigger_hash" in t_status["data"]) == True
    assert ("trigger_text" in t_status["data"]) == True
    assert ("trigger_author" in t_status["data"]) == True
    assert ("trigger" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["project_id"] == project_id
    assert t_status["data"]["name"] == "angular-js"
    assert t_status["data"]["type"] == "git"
    assert t_status["data"]["source"] == "https://github.com/cirruspath/angular.js"
    assert t_status["data"]["ruleset_id"] == "c69fcc06-154f-44c7-9c26-6484580c60bd"


def test_get_latest_analysis_statuses():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    t_status = ion_client.get_latest_analysis_statuses(team_id)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("id" in t_status["data"][0]) == True
    assert ("team_id" in t_status["data"][0]) == True
    assert ("project_id" in t_status["data"][0]) == True
    assert ("status" in t_status["data"][0]) == True
    assert ("scan_status" in t_status["data"][0]) == True
    assert ("deliveries" in t_status["data"][0]) == True
    assert t_status["data"][0]["team_id"] == team_id


def test_get_raw_analyses():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    t_status = json.loads(ion_client.get_raw_analyses(team_id, project_id))
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("id" in t_status["data"][0]) == True
    assert ("team_id" in t_status["data"][0]) == True
    assert ("project_id" in t_status["data"][0]) == True
    assert ("type" in t_status["data"][0]) == True
    assert ("source" in t_status["data"][0]) == True
    assert ("branch" in t_status["data"][0]) == True
    assert ("ruleset_id" in t_status["data"][0]) == True
    assert ("status" in t_status["data"][0]) == True
    assert ("scan_summaries" in t_status["data"][0]) == True
    assert t_status["data"][0]["team_id"] == team_id
    assert t_status["data"][0]["project_id"] == project_id
    assert t_status["data"][0]["name"] == "angular-js"
    assert t_status["data"][0]["type"] == "git"
    assert t_status["data"][0]["source"] == "https://github.com/cirruspath/angular.js"
    assert t_status["data"][0]["ruleset_id"] == "c69fcc06-154f-44c7-9c26-6484580c60bd"


def test_get_raw_latest_analysis_summary():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    t_status = json.loads(
        ion_client.get_raw_latest_analysis_summary(team_id, project_id)
    )
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("analysis_id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("project_id" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("text" in t_status["data"]) == True
    assert ("type" in t_status["data"]) == True
    assert ("source" in t_status["data"]) == True
    assert ("branch" in t_status["data"]) == True
    assert ("description" in t_status["data"]) == True
    assert ("summary" in t_status["data"]) == True
    assert ("ruleset_id" in t_status["data"]) == True
    assert ("status" in t_status["data"]) == True
    assert ("created_at" in t_status["data"]) == True
    assert ("updated_at" in t_status["data"]) == True
    assert ("duration" in t_status["data"]) == True
    assert ("trigger_hash" in t_status["data"]) == True
    assert ("trigger_text" in t_status["data"]) == True
    assert ("trigger_author" in t_status["data"]) == True
    assert ("trigger" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["project_id"] == project_id
    assert t_status["data"]["name"] == "angular-js"
    assert t_status["data"]["type"] == "git"
    assert t_status["data"]["source"] == "https://github.com/cirruspath/angular.js"
    assert t_status["data"]["ruleset_id"] == "c69fcc06-154f-44c7-9c26-6484580c60bd"


def test_get_latest_analysis_summaries():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_ids = [
        "27691314-3598-4abe-9293-e94b3eaa2287",
        "90360692-dfec-46ac-8248-a8be96a48ee3",
    ]
    t_status = ion_client.get_latest_analysis_summaries(team_id, project_ids)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("id" in t_status["data"][0]) == True
    assert ("analysis_id" in t_status["data"][0]) == True
    assert ("team_id" in t_status["data"][0]) == True
    assert ("project_id" in t_status["data"][0]) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("text" in t_status["data"][0]) == True
    assert ("type" in t_status["data"][0]) == True
    assert ("source" in t_status["data"][0]) == True
    assert ("branch" in t_status["data"][0]) == True
    assert ("description" in t_status["data"][0]) == True
    assert ("summary" in t_status["data"][0]) == True
    assert ("ruleset_id" in t_status["data"][0]) == True
    assert ("status" in t_status["data"][0]) == True
    assert ("created_at" in t_status["data"][0]) == True
    assert ("updated_at" in t_status["data"][0]) == True
    assert ("duration" in t_status["data"][0]) == True
    assert ("trigger_hash" in t_status["data"][0]) == True
    assert ("trigger_text" in t_status["data"][0]) == True
    assert ("trigger_author" in t_status["data"][0]) == True
    assert ("trigger" in t_status["data"][0]) == True
    assert ("id" in t_status["data"][1]) == True
    assert ("analysis_id" in t_status["data"][1]) == True
    assert ("team_id" in t_status["data"][1]) == True
    assert ("project_id" in t_status["data"][1]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("text" in t_status["data"][1]) == True
    assert ("type" in t_status["data"][1]) == True
    assert ("source" in t_status["data"][1]) == True
    assert ("branch" in t_status["data"][1]) == True
    assert ("description" in t_status["data"][1]) == True
    assert ("summary" in t_status["data"][1]) == True
    assert ("ruleset_id" in t_status["data"][1]) == True
    assert ("status" in t_status["data"][1]) == True
    assert ("created_at" in t_status["data"][1]) == True
    assert ("updated_at" in t_status["data"][1]) == True
    assert ("duration" in t_status["data"][1]) == True
    assert ("trigger_hash" in t_status["data"][1]) == True
    assert ("trigger_text" in t_status["data"][1]) == True
    assert ("trigger_author" in t_status["data"][1]) == True
    assert ("trigger" in t_status["data"][1]) == True
    assert t_status["data"][0]["team_id"] == team_id
    assert t_status["data"][0]["project_id"] == project_ids[0]
    assert t_status["data"][0]["name"] == "pepe"
    assert t_status["data"][0]["type"] == "git"
    assert t_status["data"][0]["source"] == "git@github.com:ion-channel/pepe.git"
    assert t_status["data"][0]["ruleset_id"] == "86ee6e2f-95d5-47f5-9d73-86d7712d6889"
    assert t_status["data"][1]["project_id"] == project_ids[1]
    assert t_status["data"][1]["name"] == "angular-js"
    assert t_status["data"][1]["type"] == "git"
    assert t_status["data"][1]["source"] == "https://github.com/cirruspath/angular.js"
    assert t_status["data"][1]["ruleset_id"] == "c69fcc06-154f-44c7-9c26-6484580c60bd"


def test_get_raw_analysis():
    analyses_id = "bf556a9e-e292-4aa9-a0c4-2b4785a66375"
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    t_status = json.loads(ion_client.get_raw_analysis(team_id, project_id, analyses_id))
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("analysis_id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("project_id" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("text" in t_status["data"]) == True
    assert ("type" in t_status["data"]) == True
    assert ("source" in t_status["data"]) == True
    assert ("branch" in t_status["data"]) == True
    assert ("description" in t_status["data"]) == True
    assert ("summary" in t_status["data"]) == True
    assert ("ruleset_id" in t_status["data"]) == True
    assert ("status" in t_status["data"]) == True
    assert ("created_at" in t_status["data"]) == True
    assert ("updated_at" in t_status["data"]) == True
    assert ("duration" in t_status["data"]) == True
    assert ("trigger_hash" in t_status["data"]) == True
    assert ("trigger_text" in t_status["data"]) == True
    assert ("trigger_author" in t_status["data"]) == True
    assert ("trigger" in t_status["data"]) == True
    assert ("scan_summaries" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["project_id"] == project_id
    assert t_status["data"]["name"] == "angular-js"
    assert t_status["data"]["type"] == "git"
    assert t_status["data"]["source"] == "https://github.com/cirruspath/angular.js"
    assert t_status["data"]["ruleset_id"] == "c69fcc06-154f-44c7-9c26-6484580c60bd"


def test_get_analyses_statuses():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    analysis_ids = ["bf556a9e-e292-4aa9-a0c4-2b4785a66375"]
    t_status = ion_client.get_analyses_statuses(team_id, analysis_ids)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert t_status["data"][0]["analysis_id"] == analysis_ids[0]
    assert ("project_id" in t_status["data"][0]) == True
    assert t_status["data"][0]["status"] == "fail"


def test_get_latest_ids():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_ids = [
        "90360692-dfec-46ac-8248-a8be96a48ee3",
        "27691314-3598-4abe-9293-e94b3eaa2287",
    ]
    t_status = ion_client.get_latest_ids(team_id, project_ids)
    assert ("data" in t_status) == True
    assert (project_ids[0] in t_status["data"]) == True
    assert (project_ids[1] in t_status["data"]) == True


def test_get_analysis_navigation():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    analysis_id = "bf556a9e-e292-4aa9-a0c4-2b4785a66375"
    t_status = ion_client.get_analysis_navigation(team_id, project_id, analysis_id)
    assert ("data" in t_status) == True
    assert ("analysis" in t_status["data"]) == True
    assert ("latest_analysis" in t_status["data"]) == True
    assert t_status["data"]["analysis"] == None
    assert t_status["data"]["latest_analysis"] == None


def test_analyze_project():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    t_status = ion_client.analyze_project(team_id, project_id)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("project_id" in t_status["data"]) == True
    assert ("message" in t_status["data"]) == True
    assert ("branch" in t_status["data"]) == True
    assert ("status" in t_status["data"]) == True
    assert ("scan_status" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["project_id"] == project_id
    assert t_status["data"]["branch"] == "master"


def test_analyze_projects():
    project_ids = [
        "27691314-3598-4abe-9293-e94b3eaa2287",
        "ab7d4bfc-dfb1-4240-ad9f-7a60f8441fbf",
    ]
    t_status = ion_client.analyze_projects(project_ids)
    assert ("data" in t_status) == True
    assert ("succeeded" in t_status["data"]) == True
    assert len(t_status["data"]["succeeded"]) > 0
    assert (
        t_status["data"]["succeeded"][0]["team_id"]
        == "646fa3e5-e274-4884-aef2-1d47f029c289"
    )
    assert (
        t_status["data"]["succeeded"][0]["project_id"]
        == "27691314-3598-4abe-9293-e94b3eaa2287"
    )
    assert (
        t_status["data"]["succeeded"][1]["team_id"]
        == "646fa3e5-e274-4884-aef2-1d47f029c289"
    )
    assert (
        t_status["data"]["succeeded"][1]["project_id"]
        == "ab7d4bfc-dfb1-4240-ad9f-7a60f8441fbf"
    )


def test_add_scan():
    analysis_id = "bf556a9e-e292-4aa9-a0c4-2b4785a66375"
    project_id = "90360692-dfec-46ac-8248-a8be96a48ee3"
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    param_value = 99
    t_status = ion_client.add_scan(analysis_id, team_id, project_id, param_value)
    assert ("data" in t_status) == True
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["project_id"] == project_id
    assert t_status["data"]["analysis_id"] == analysis_id
    assert t_status["data"]["message_type"] == "update_analysis"
    assert t_status["data"]["results"]["value"] == param_value
    assert t_status["data"]["scan_type"] == "coverage"


def test_get_analyses_vulnerability_export_data():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    analysis_ids = [
        "bf556a9e-e292-4aa9-a0c4-2b4785a66375",
        "498e1d34-6a0f-4734-a16a-752d5328f021",
    ]
    t_status = ion_client.get_analyses_vulnerability_export_data(team_id, analysis_ids)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("title" in t_status["data"][0]) == True
    assert ("external_id" in t_status["data"][0]) == True
    assert ("severity" in t_status["data"][0]) == True
    assert ("score" in t_status["data"][0]) == True
    assert ("dependency" in t_status["data"][0]) == True
    assert ("dependency_version" in t_status["data"][0]) == True
    assert t_status["data"][0]["project_id"] == "27691314-3598-4abe-9293-e94b3eaa2287"
    assert t_status["data"][0]["analysis_id"] == "498e1d34-6a0f-4734-a16a-752d5328f021"
