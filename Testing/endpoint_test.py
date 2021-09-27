from logging import info
import pyonic as pyonics
from json import JSONDecodeError


ion_client = pyonics.new_client("https://api.test.ionchannel.io/v1/")

# username = input("What is your username: ")
# password = input("What is your password: ")

token = ion_client.login()
print(token)

# token = 'garbage token'
# print("Got this login token: " + token)
# ion_client.get_projects(token, '646fa3e5-e274-4884-aef2-1d47f029c289')

# ion_client.analyze_project(token, '646fa3e5-e274-4884-aef2-1d47f029c289', '90360692-dfec-46ac-8248-a8be96a48ee3')
# json_data = json.loads(ion_client.analyze_project(token, '646fa3e5-e274-4884-aef2-1d47f029c289', '90360692-dfec-46ac-8248-a8be96a48ee3', ''))
# content = json_data["data"]
# analysis_id = content["id"]
# print(analysis_id)
# (ion_client.analysis_status(token, '646fa3e5-e274-4884-aef2-1d47f029c289', '90360692-dfec-46ac-8248-a8be96a48ee3', 'bf556a9e-e292-4aa9-a0c4-2b4785a66375'))

# print(ion_client.get_analysis('646fa3e5-e274-4884-aef2-1d47f029c289', '90360692-dfec-46ac-8248-a8be96a48ee3', '3907619c-41bd-4117-9464-ff4829f67c0a'))

# print(ion_client.get_raw_analysis('646fa3e5-e274-4884-aef2-1d47f029c289', '90360692-dfec-46ac-8248-a8be96a48ee3', '3907619c-41bd-4117-9464-ff4829f67c0a'))

# testval  = json.loads(ion_client.get_applied_ruleset(token, '646fa3e5-e274-4884-aef2-1d47f029c289', 'c5e4672e-85c2-4c35-ac3e-c08449341f12', 'b61a2d45-5368-49cf-aa8e-bdcb11513bae'))
# content = testval["data"]
# results = content["rule_evaluation_summary"]["passed"]
# print(results)


# print(ion_client.get_teams(token))

# print(ion_client.get_ruleset(token, '646fa3e5-e274-4884-aef2-1d47f029c289', '0ccb6e3e-a56d-45af-8704-c23d67a81f37'))


# file = open('project2.json')
# dict = json.load(file)
# print(ion_client.create_project(token, '646fa3e5-e274-4884-aef2-1d47f029c289', dict))


# file = open('project.json')
# dict = json.load(file)
# print(ion_client.update_project(token, '646fa3e5-e274-4884-aef2-1d47f029c289', dict))

# print('Hello World')
# print('Another test')

# print(ion_client.add_scan(token, 'c1379ca6-d151-41e4-a236-14e475dac8c3', '646fa3e5-e274-4884-aef2-1d47f029c289', '27691314-3598-4abe-9293-e94b3eaa2287'))
# print(
#     ion_client.get_analysis(
#         token,
#         "646fa3e5-e274-4884-aef2-1d47f029c289",
#         "27691314-3598-4abe-9293-e94b3eaa2287",
#         "f535bc09-3645-4185-aa9c-34b012aed1e3",
#     )
# )
# print(ion_client.get_applied_ruleset(token, '646fa3e5-e274-4884-aef2-1d47f029c289', '27691314-3598-4abe-9293-e94b3eaa2287', 'f535bc09-3645-4185-aa9c-34b012aed1e3'))

# print(ion_client.get_raw_applied_ruleset('646fa3e5-e274-4884-aef2-1d47f029c289', '27691314-3598-4abe-9293-e94b3eaa2287', 'f535bc09-3645-4185-aa9c-34b012aed1e3'))


# print(ion_client.scan_report(token, '5c00b319-f657-43fb-8f1d-4306d09bcbb1', '646fa3e5-e274-4884-aef2-1d47f029c289', '90360692-dfec-46ac-8248-a8be96a48ee3'))

# options = {"sbom_type": "SPDX", "include_dependencies": False}

# print(
#     ion_client.get_SBOM(
#         token,
#         [
#             "27691314-3598-4abe-9293-e94b3eaa2287",
#             "aa586e09-6001-410a-9a84-1d697231d0c9",
#         ],
#         "646fa3e5-e274-4884-aef2-1d47f029c289",
#         options,
#     )
# )

# print(ion_client.get_analyses("646fa3e5-e274-4884-aef2-1d47f029c289", "27691314-3598-4abe-9293-e94b3eaa2287"))

# print(ion_client.get_raw_analyses("646fa3e5-e274-4884-aef2-1d47f029c289", "27691314-3598-4abe-9293-e94b3eaa2287"))


# print(
#     ion_client.get_latest_analysis(
#         "646fa3e5-e274-4884-aef2-1d47f029c289", "27691314-3598-4abe-9293-e94b3eaa2287"
#     )
# )

# print(ion_client.get_latest_ids("646fa3e5-e274-4884-aef2-1d47f029c289", ["27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.get_latest_analysis_summary("646fa3e5-e274-4884-aef2-1d47f029c289", "27691314-3598-4abe-9293-e94b3eaa2287"))

# print(
#     ion_client.get_latest_public_analysis(
#         "90360692-dfec-46ac-8248-a8be96a48ee3", "master"
#     )
# )

# print(ion_client.get_latest_analysis_summaries("646fa3e5-e274-4884-aef2-1d47f029c289", ["27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.get_analyses_export_data("646fa3e5-e274-4884-aef2-1d47f029c289", ["0af55ffd-1794-48a4-8c5d-3ea65a89be93"]))

# print(ion_client.get_analyses_vulnerability_export_data("646fa3e5-e274-4884-aef2-1d47f029c289", ["0af55ffd-1794-48a4-8c5d-3ea65a89be93"]))

# print(ion_client.get_repository("facebook/react"))

# options = {
#     "Subject": "react",
#     "Comparands": ["other", "repo"],
#     "ByActor": True
# }
# print(ion_client.get_repositories_in_common(options))

# print(ion_client.get_repositories_for_actor("random"))

# print(ion_client.search_repository("ionic"))

# print(ion_client.get_delivery_destinations("646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.create_delivery_destination("a537c6c7-1a59-4d9b-b467-3a3fd1ca849f", "location1", "us-east-1", "endpoint_testing", "s3"))

# print(ion_client.delete_delivery_destination("a9b25d5a-1e2d-41cd-853d-2a0d9cb7ed8e"))

# print(ion_client.get_versions_for_dependency("bundler", "Ruby"))

# print(ion_client.search_dependencies(""))

# print(ion_client.get_latest_version_for_dependency("bundler", "Ruby"))

# print(ion_client.add_alias("646fa3e5-e274-4884-aef2-1d47f029c289", "90360692-dfec-46ac-8248-a8be96a48ee3", "name", "version", "org"))

# f = open("test", "w")
# print(f.name)
# f.write(
#     """<dependencies>
# 		<dependency>
# 			<groupId>junit</groupId>
# 			<artifactId>junit</artifactId>
# 			<version>3.8.1</version>
# 			<scope>test</scope>
# 		</dependency>

# 		<!-- spring-context which provides core functionality -->
# 		<dependency>
# 			<groupId>org.springframework</groupId>
# 			<artifactId>spring-context</artifactId>
# 			<version>4.1.6.RELEASE</version>
# 		</dependency>

# 		<!-- The spring-aop module provides an AOP Alliance-compliant aspect-oriented
# 			programming implementation allowing you to define -->
# 		<dependency>
# 			<groupId>org.springframework</groupId>
# 			<artifactId>spring-aop</artifactId>
# 			<version>4.1.6.RELEASE</version>
# 		</dependency>

# 		<!-- The spring-webmvc module (also known as the Web-Servlet module) contains
# 			Spring’s model-view-controller (MVC) and REST Web Services implementation
# 			for web applications -->
# 		<dependency>
# 			<groupId>org.springframework</groupId>
# 			<artifactId>spring-webmvc</artifactId>
# 			<version>4.1.6.RELEASE</version>
# 		</dependency>

# 		<!-- The spring-web module provides basic web-oriented integration features
# 			such as multipart file upload functionality and the initialization of the
# 			IoC container using Servlet listeners and a web-oriented application context -->
# 		<dependency>
# 			<groupId>org.springframework</groupId>
# 			<artifactId>spring-web</artifactId>
# 			<version>4.1.6.RELEASE</version>
# 		</dependency>
# 	</dependencies>
#     """
# )
# ---- The bottom endpoint needs to be verified
# print(ion_client.resolve_dependencies_in_file("./package.lock.json", True, "json"))

# print(ion_client.get_vulnerability_statistics(["90360692-dfec-46ac-8248-a8be96a48ee3", "27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.get_raw_vulnerability_statistics(["90360692-dfec-46ac-8248-a8be96a48ee3", "27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.get_portfolio_pass_fail_summary(["90360692-dfec-46ac-8248-a8be96a48ee3", "27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(
#     ion_client.get_portfolio_started_errored_summary(
#         ["90360692-dfec-46ac-8248-a8be96a48ee3", "27691314-3598-4abe-9293-e94b3eaa2287"]
#     )
# )

# print(ion_client.get_portfolio_affected_projects("646fa3e5-e274-4884-aef2-1d47f029c289", "a537c6c7-1a59-4d9b-b467-3a3fd1ca849f"))

# print(ion_client.get_portfolio_affected_projects_info(["90360692-dfec-46ac-8248-a8be96a48ee3", "27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(
#     ion_client.get_vulnerability_metrics(
#         "vulnerability",
#         [
#             "90360692-dfec-46ac-8248-a8be96a48ee3",
#             "27691314-3598-4abe-9293-e94b3eaa2287",
#         ],
#     )
# )

# print(ion_client.get_raw_vulnerability_metrics("vulnerability", ["90360692-dfec-46ac-8248-a8be96a48ee3", "27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.get_project_report("646fa3e5-e274-4884-aef2-1d47f029c289", "27691314-3598-4abe-9293-e94b3eaa2287"))

# print(ion_client.get_raw_project("646fa3e5-e274-4884-aef2-1d47f029c289", "27691314-3598-4abe-9293-e94b3eaa2287"))

# print(ion_client.get_applied_ruleset("646fa3e5-e274-4884-aef2-1d47f029c289", "90360692-dfec-46ac-8248-a8be96a48ee3", "f3541c16-1d30-4429-9f46-bbb95dec329b"))

# print(ion_client.update_ruleset_for_project("86ee6e2f-95d5-47f5-9d73-86d7712d6889", ["27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.update_ruleset_for_project("c69fcc06-154f-44c7-9c26-6484580c60bd", ["27691314-3598-4abe-9293-e94b3eaa2287"]))

# project = {"monitor": True}
# print(ion_client.update_projects(["90360692-dfec-46ac-8248-a8be96a48ee3", "2acf0070-94a9-4cd5-9c47-3473dddf9d2a"], project))

# print(ion_client.get_digests("27691314-3598-4abe-9293-e94b3eaa2287", "646fa3e5-e274-4884-aef2-1d47f029c289", "aed4ada6-350c-4d6e-a5f0-a338fa699602"))

# print(ion_client.get_portfolio("646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.get_vulnerability_list("646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.get_affected_projects("646fa3e5-e274-4884-aef2-1d47f029c289", "CVE-2020-28469"))

# print(ion_client.get_project_history("646fa3e5-e274-4884-aef2-1d47f029c289", "90360692-dfec-46ac-8248-a8be96a48ee3"))

# print(ion_client.get_public_analysis("0cbf19b9-0d1d-43a3-a609-2e598e9fd05e"))

# print(ion_client.get_rules())

# print(ion_client.get_rulesets("646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.get_pass_fail_history("90360692-dfec-46ac-8248-a8be96a48ee3"))

# print(ion_client.get_analysis_report("646fa3e5-e274-4884-aef2-1d47f029c289", "90360692-dfec-46ac-8248-a8be96a48ee3", "7b459857-f478-4066-b1ae-2afe058e4652"))

# print(ion_client.get_raw_analysis_report("646fa3e5-e274-4884-aef2-1d47f029c289", "90360692-dfec-46ac-8248-a8be96a48ee3", "7b459857-f478-4066-b1ae-2afe058e4652"))

# print(ion_client.get_projects_report("646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.create_ruleset("95d06aa3-ec21-4602-86c2-c79605d81d09", "Sample", "This is just for endpoint testing purposes", ["81959ec3-2b6d-4bd4-b94b-6ce2533524bb", "00be1862-959c-45d8-8fb5-2b748fe854d6"]))

# print(ion_client.delete_ruleset("95d06aa3-ec21-4602-86c2-c79605d81d09", "19252407-b420-4d9f-b420-75c63ce290c8"))

# print(ion_client.get_exported_vulnerability_data("646fa3e5-e274-4884-aef2-1d47f029c289", ["c5e4672e-85c2-4c35-ac3e-c08449341f12", "27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.get_exported_projects_data("646fa3e5-e274-4884-aef2-1d47f029c289", ["90360692-dfec-46ac-8248-a8be96a48ee3", "27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.get_latest_analysis_status("646fa3e5-e274-4884-aef2-1d47f029c289", "90360692-dfec-46ac-8248-a8be96a48ee3"))

# print(ion_client.get_team("646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.logout())

# print(ion_client.analyze_projects([{"project_id": "90360692-dfec-46ac-8248-a8be96a48ee3"}, {"project_id": "27691314-3598-4abe-9293-e94b3eaa2287"}]))
# print(ion_client.analyze_projects(["90360692-dfec-46ac-8248-a8be96a48ee3", "27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.search("ruby"))
# print(ion_client.search("ruby", offset=0, limit=2))
# print(ion_client.search("ruby", "repos", 0, 2))

# print(ion_client.get_team_users("95d06aa3-ec21-4602-86c2-c79605d81d09"))

# print(ion_client.create_team("API4team", "Nikil", "nikil.nair@ionchannel.io", "nikil"))

# For Testing Purposes Only - Not used for Anything
rsaKey = """-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""

# For Testing Purposes Only - Not used for Anything
opensshkey = """-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----"""


# print(
#     ion_client.update_team(
#         "c1e8e911-54db-49a0-bdf6-cc6bc0c15304",
#         "new name",
#         "new guy",
#         "newguy@ionchannel.io",
#         opensshkey,
#     )
# )

# uid = 55c31ba6-1fb1-4adc-804f-fa4f40cd4f1b

# 'id': '657b51df-67ea-474c-843c-c64bc61b3c90', 'email': 'nikil.nair+test@ionchannel.io', 'username': 'nikil.nair+test@ionchannel.io', 'chat_handle': '', 'created_at': '2021-08-06T18:01:38.13037Z', 'updated_at': '2021-08-06T18:01:38.13037Z', 'last_active_at': '2021-08-06T18:12:57.558398Z', 'externally_managed': False, 'metadata': None, 'sys_admin': False, 'system': False, 'organizations': {}, 'teams': {'a619b190-d76c-4228-acf8-c1859af39e94': 'admin'}}}

# teamid: 95d06aa3-ec21-4602-86c2-c79605d81d09

# b'{"data":{"id":"716286c2-78be-4258-bbd2-cf7d8d03b723","created_at":"2021-08-06T18:26:49.217Z","updated_at":"2021-08-06T18:26:49.217Z","team_id":"95d06aa3-ec21-4602-86c2-c79605d81d09","user_id":"657b51df-67ea-474c-843c-c64bc61b3c90","role":"admin","deleted_at":null,"status":"pending","inviter":"f8636445-a1ab-434b-87ef-329ab7aba37e","invited_at":"2021-08-06T18:26:49.217Z","username":"nikil.nair+test@ionchannel.io","email":"nikil.nair+test@ionchannel.io","chat_handle":null,"last_active_at":"2021-08-06T18:14:11.252Z"},"meta":{"copyright":"Copyright 2018 Ion Channel Corporation","version":"v1"},"links":{"self":"https://api.test.ionchannel.io/v1/teamUsers/inviteTeamUser","created":"https://api.test.ionchannel.io/v1/teamUsers/inviteTeamUser"},"timestamps":{"created":"2021-08-06T18:26:49.759Z","updated":"2021-08-06T18:26:49.759Z"}}'

# invite id: 716286c2-78be-4258-bbd2-cf7d8d03b723

# new invite id: 88663a0e-4bbe-44b9-880f-0d9958ae6950

# print(ion_client.invite_team_user("21acb344-1010-4a6c-8b63-544c9cb72c71", "admin", "657b51df-67ea-474c-843c-c64bc61b3c90", "nikil.nair+test@ionchannel.io"))

invite_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MjgyNzQ0MDksImp0aSI6IjI2YTY3NDk0LTdlNWEtNDNmZC05MzZjLTY4NzM3NjUwYzU5NSIsInN1YiI6IjY1N2I1MWRmLTY3ZWEtNDc0Yy04NDNjLWM2NGJjNjFiM2M5MCIsImV4cCI6MTYzMDg2NjQwOSwiaW52IjoiNzE2Mjg2YzItNzhiZS00MjU4LWJiZDItY2Y3ZDhkMDNiNzIzIn0.0Sz5Co3xQEPdsfj-kATt6HQZ6tQUrHHWTqUlMkq_0Yw"
alternate_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MjgyNzcwMDgsImp0aSI6Ijk2YmMwNzFjLTVjOTEtNGY1My1iODA4LWE2MGNmZGYxMmMyOSIsInN1YiI6IjY1N2I1MWRmLTY3ZWEtNDc0Yy04NDNjLWM2NGJjNjFiM2M5MCIsImV4cCI6MTYzMDg2OTAwOCwiaW52IjoiODg2NjNhMGUtNGJiZS00NGI5LTg4MGYtMGQ5OTU4YWU2OTUwIn0.Zb6pI2KB6Twk-NBrkOrkSPtsDcjCMABarllppz5TIZw"

# print(ion_client.get_team_invite("716286c2-78be-4258-bbd2-cf7d8d03b723", invite_token))
# print(ion_client.get_team_invite("88663a0e-4bbe-44b9-880f-0d9958ae6950", alternate_token))


# print(ion_client.accept_team_invite("716286c2-78be-4258-bbd2-cf7d8d03b723", invite_token))
# print(ion_client.accept_team_invite("88663a0e-4bbe-44b9-880f-0d9958ae6950", alternate_token))

# print(ion_client.delete_team_user("88663a0e-4bbe-44b9-880f-0d9958ae6950"))

# print(ion_client.resend_invite_team_user("4ff7d699-f272-42c2-ae41-d455686b1503"))

# print(ion_client.update_team_user("716286c2-78be-4258-bbd2-cf7d8d03b723", "admin", "active"))

# print(ion_client.get_tokens())

# print(ion_client.get_projectids_by_dependency("646fa3e5-e274-4884-aef2-1d47f029c289", "argparse", "nodeca", "1.0.10"))

# print(ion_client.get_exported_vulnerability_data_csv("646fa3e5-e274-4884-aef2-1d47f029c289", ["90360692-dfec-46ac-8248-a8be96a48ee3", "27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.create_token("a-token"))

# print(ion_client.delete_token("82246b2b-46a7-4253-9b8c-6058105580b8"))

# print(ion_client.get_self())

# print(ion_client.get_users())

# print(ion_client.refresh_token())

# print(ion_client.get_usage_information("646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.reset_password("nikil.nair+test@ionchannel.io"))

# print(ion_client.complete_signup("nikil.nair+test@ionchannel.io", "xxxx", "xxxx"))

# print(ion_client.update_user("657b51df-67ea-474c-843c-c64bc61b3c90", "", "", "xxxx"))

# print(ion_client.get_vulnerability_list("646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.get_vulnerability("CVE-2013-0248"))

# print(ion_client.get_vulnerabilities("go", "1.15.7", 0, 1))

# print(ion_client.get_product("go"))

# print(
#     ion_client.get_raw_latest_analysis_summary(
#         "646fa3e5-e274-4884-aef2-1d47f029c289", "27691314-3598-4abe-9293-e94b3eaa2287"
#     )
# )

# print(ion_client.get_dependency_statistics(["27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.get_raw_dependency_list(["11e61175-3eac-449f-9e49-be9ec30a7571"], "name"))

# print(ion_client.get_dependency_list(["27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.get_projects_status_history(["90360692-dfec-46ac-8248-a8be96a48ee3", "27691314-3598-4abe-9293-e94b3eaa2287"]))

# print(ion_client.get_mttr("646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.get_projects_by_dependency("646fa3e5-e274-4884-aef2-1d47f029c289", "@types/node", "DefinitelyTyped", "16.3.1"))

# print(ion_client.get_product_versions("jdk", "11.0"))

# print(ion_client.get_product_search("(bundler)AND1.17.3"))

# print(ion_client.get_raw_product("go"))


# file = open('./csvtest.csv')
# print(file.readline())
# dict = json.load(file)
# print(
#     ion_client.create_projects_from_csv(
#         "95d06aa3-ec21-4602-86c2-c79605d81d09", "./csvtest.csv"
#     )
# )

# print(ion_client.get_project("646fa3e5-e274-4884-aef2-1d47f029c289", "27691314-3598-4abe-9293-e94b3eaa2287"))

# print(ion_client.get_raw_project("646fa3e5-e274-4884-aef2-1d47f029c289", "27691314-3598-4abe-9293-e94b3eaa2287"))

# print(ion_client.get_project_by_url("646fa3e5-e274-4884-aef2-1d47f029c289", "git@github.com:ion-channel/statler.git"))
# print(ion_client.get_project_by_url("646fa3e5-e274-4884-aef2-1d47f029c289", "https://github.com/cirruspath/angular.js"))
# print(ion_client.get_project_by_url("646fa3e5-e274-4884-aef2-1d47f029c289", "https://github.com/brendano86/handlebars.js"))

# print(ion_client.get_used_ruleset_ids("646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.get_projects_names("646fa3e5-e274-4884-aef2-1d47f029c289", ["90360692-dfec-46ac-8248-a8be96a48ee3", "27691314-3598-4abe-9293-e94b3eaa2287", "29c4fb49-c685-473e-bfb3-6ecce155c3ad"]))

# print(ion_client.get_analysis_navigation("646fa3e5-e274-4884-aef2-1d47f029c289", "ff503586-6aa6-478c-97bb-7eabf1a48dcb", "81f4b8b5-5645-452b-90ea-033926f9eeae"))

# print(
#     ion_client.get_applied_rulesets(
#         [
#             (
#                 "646fa3e5-e274-4884-aef2-1d47f029c289",
#                 "ab7d4bfc-dfb1-4240-ad9f-7a60f8441fbf",
#             )
#         ]
#     )
# )

# print(ion_client.get_applied_rulesets_brief([("646fa3e5-e274-4884-aef2-1d47f029c289", "ab7d4bfc-dfb1-4240-ad9f-7a60f8441fbf")]))

# print(ion_client.ruleset_exists("646fa3e5-e274-4884-aef2-1d47f029c289", "0ccb6e3e-a56d-45af-8704-c23d67a81f37"))

# print(ion_client.get_ruleset_names(["0ccb6e3e-a56d-45af-8704-c23d67a81f37", "46cbb767-9e74-4641-9381-457bd8a5c10c", "7253f851-a1c6-4fa6-97c8-415b4a9a634d"]))

# print(ion_client.get_analyses_statuses("646fa3e5-e274-4884-aef2-1d47f029c289", ["fad09cbe-4499-4956-8b28-152555de5bc6", "6357ce28-2cfc-45ba-ae1a-5cfa303aa61b"]))

# print(ion_client.get_latest_analysis_statuses("646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.get_project_states(["27691314-3598-4abe-9293-e94b3eaa2287", "90360692-dfec-46ac-8248-a8be96a48ee3"], "finished"))

# sample = {
#     "analysis_ids": ["5053f5c3-2314-462e-a0a2-c7314ab88458"]
# }

# print(ion_client.find_scans(sample, "646fa3e5-e274-4884-aef2-1d47f029c289"))

# print(ion_client.get_secrets(rsaKey))

# print(
#     ion_client.create_tag("95d06aa3-ec21-4602-86c2-c79605d81d09", "taga", "endpoint taga")
# )

# print(ion_client.update_tag("f8027348-5e86-451f-96c9-1a8af7fae346", "95d06aa3-ec21-4602-86c2-c79605d81d09", "updatedtags", "updated tags description"))

# print(ion_client.get_tag("f8027348-5e86-451f-96c9-1a8af7fae346", "95d06aa3-ec21-4602-86c2-c79605d81d09"))

# print(ion_client.get_raw_tag("f8027348-5e86-451f-96c9-1a8af7fae346", "95d06aa3-ec21-4602-86c2-c79605d81d09"))

# print(ion_client.get_tags("95d06aa3-ec21-4602-86c2-c79605d81d09"))

# print(ion_client.get_raw_tags("95d06aa3-ec21-4602-86c2-c79605d81d09"))

options = {
    "team_id": "21acb344-1010-4a6c-8b63-544c9cb72c71",
    "user_id": "74996a06-7df8-4867-b915-8fc262167955",
    "role": "admin",
    "status": "active",
}

# print(ion_client.create_team_user(options))

# print(ion_client.create_user("nikil.nair+endpoint@ionchannel.io", "nikil.nair+endpoint@ionchannel.io", "password"))

# print(ion_client.create_user("nikil.nair+etest@ionchannel.io", "Nikil-Testing", "nikil.nair+etest@ionchannel.io", "password"))

# print(ion_client.get_user("74996a06-7df8-4867-b915-8fc262167955"))

# print(ion_client.get_user_names(["74996a06-7df8-4867-b915-8fc262167955"], "21acb344-1010-4a6c-8b63-544c9cb72c71"))

vuln = {
    "external_id": "CUKE-TEST-4",
    "title": "some title",
    "summary": "some summary",
    "modified_at": "t",
    "recommendation": "upgrade recommendation goes here",
    "published_at": "t",
    "source": ["NVD"],
    "score_system": "CVSS",
    "score_details": {
        "cvssv3": {
            "version": "3.0",
            "vectorString": "CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H",
            "attackComplexity": "HIGH",
            "attackVector": "NETWORK",
            "availabilityImpact": "HIGH",
            "baseSeverity": "MEDIUM",
            "userInteraction": "NONE",
            "baseScore": 5.3,
            "privilegesRequired": "LOW",
            "confidentialityImpact": "NONE",
            "integrityImpact": "NONE",
            "scope": "UNCHANGED",
        }
    },
    "dependencies": [
        "cpe:/a:nyancat:rainbow:1.0.0",
        "cpe:/a:nyancat:rainbow:1.0.1",
        "cpe:/a:nyancat:rainbow:1.0.2",
    ],
}

# print(ion_client.add_vulnerability(vuln))

# print(ion_client.get_vulnerabilities_in_file("./package.json"))
