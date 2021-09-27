from yaml.loader import SafeLoader
import pyonic as pyonics
import json
import yaml
import time
import sys
import os

# Angular.js
# sample team_id: '646fa3e5-e274-4884-aef2-1d47f029c289'
# sample project_id: '90360692-dfec-46ac-8248-a8be96a48ee3'

# The text file that contains coverage information must be in the same working directory and
# coverage information must be on the first line
# Will still need token verification / Error checking
def analysis(filename):
    try:
        file = open(os.environ["PWD"] + "/" + (filename + ".yaml"))
    except FileNotFoundError:
        print(
            "Error: You have entered an incorrect filename, or this file is not in your working directory"
        )

    parsed_yaml = yaml.load(file, Loader=SafeLoader)

    try:
        teamid = parsed_yaml["team"]
    except KeyError:
        print("Error: You have entered an invalid key (should be team)")
        sys.exit(-1)

    try:
        projectid = parsed_yaml["project"]
    except KeyError:
        print("Error: You have entered an invalid key (should be project)")
        sys.exit(-1)

    coverage = None
    try:
        coverage = parsed_yaml["coverage"]
    except KeyError:
        print("Error: You have entered an invalid key (should be coverage)")
        sys.exit(-1)

    if coverage is not None:
        file_name = coverage
        coverage_file = open(os.environ["PWD"] + "/" + (coverage))
        coverage = coverage_file.readline()

    ion_client = pyonics.new_client("https://api.test.ionchannel.io/v1/")

    try:
        username = os.environ["IONUSER"]
    except KeyError:
        username = input(
            "Since you have not set ENV variable (IONUSER): What is your username: "
        )

    try:
        password = os.environ["IONPASSWORD"]
    except KeyError:
        password = input(
            "Since you have not set ENV variable (IONPASSWORD): What is your password: "
        )
    ion_client.login(username, password)
    # token = ion_client.login(username, password)
    # if token == -1:
    #     sys.exit(-1)
    # json_data = json.loads(ion_client.analyze_project(teamid, projectid))
    json_data = ion_client.analyze_project(teamid, projectid)

    if json_data == -1:
        sys.exit(-1)

    content = json_data["data"]
    analysis_id = content["id"]
    print("\nRun the analysis from the . file")
    print(f'Using branch {json_data["data"]["branch"]}')
    if coverage is not None:
        ion_client.add_scan(analysis_id, teamid, projectid, coverage)
        print(f"Reading coverage value from {file_name}")
        print(f"Found coverage {coverage}")
        print("Adding external coverage scan data\n")
    status = ion_client.analysis_status(teamid, projectid, analysis_id)
    if status == -1:
        sys.exit(-1)

    print("Analysis in Progress")

    while status != "finished":
        time.sleep(10)
        print("Analysis in Progress")
        status = ion_client.analysis_status(teamid, projectid, analysis_id)
        content = status["data"]
        status = content["status"]
        if status == -1:
            sys.exit(-1)
    print("Analysis Complete!\n")
    # json_data = json.loads(ion_client.get_analysis(teamid, projectid, analysis_id))
    # json_data = json.loads(
    #     ion_client.get_applied_ruleset(teamid, projectid, analysis_id)
    # )

    json_data = ion_client.get_applied_ruleset(teamid, projectid, analysis_id)

    content = json_data["data"]
    # summary = content["scan_summaries"]
    summary = content["rule_evaluation_summary"]["ruleresults"]
    # print(f"This is the scan summary array: {summary}")
    print("Checking status of scans:\n")

    for i in summary:
        if i["passed"]:
            phrase = "passed"
        else:
            phrase = "not passed"

        print(
            f'{i["summary"]} -- Rule Type: {i["type"]} -- Status: {phrase} -- Risk: {i["risk"]}'
        )
    vulnerabilities = summary[0]["summary"]
    # print(vulnerabilities)

    # ruleset_data = json.loads(
    #     ion_client.get_applied_ruleset(token, teamid, projectid, analysis_id)
    # )

    ruleset_data = ion_client.get_applied_ruleset(teamid, projectid, analysis_id)

    content = ruleset_data["data"]
    results = content["rule_evaluation_summary"]["passed"]

    # print(f"This analysis passed all of the ruleset criterion: {results}")

    if results:
        print("\nThis analysis passed all of the ruleset criterion")
        print("\nDone your build exited with Status Code: 0")
        sys.exit()
    else:
        print("This analysis did not pass all of the ruleset criterion")
        print("\nDone your build exited with Status Code: -1")
        sys.exit(-1)


# Apache Maven: SHOULD_PASS - PASSED
# analysis('646fa3e5-e274-4884-aef2-1d47f029c289', 'c5e4672e-85c2-4c35-ac3e-c08449341f12')

# Avenues: SHOULD_PASS - PASSED
# analysis('646fa3e5-e274-4884-aef2-1d47f029c289', '03b5660f-2401-43f0-b4db-355a04f05019')

# Django-Anymail: SHOULD_FAIL - FAILED
# analysis('646fa3e5-e274-4884-aef2-1d47f029c289', 'e2f34eb6-04bf-4dd6-a83e-c0e38c66f881')

analysis("pyonize")
