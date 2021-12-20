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


def test_get_versions_for_dependency():
    package_name = "bundler"
    ecosystem = "Ruby"
    t_status = ion_client.get_versions_for_dependency(package_name, ecosystem)
    assert ("data" in t_status) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("version" in t_status["data"][0]) == True
    assert ("latest_version" in t_status["data"][0]) == True
    assert ("org" in t_status["data"][0]) == True
    assert ("type" in t_status["data"][0]) == True
    assert ("package" in t_status["data"][0]) == True
    assert ("scope" in t_status["data"][0]) == True
    assert ("requirement" in t_status["data"][0]) == True
    assert ("dependencies" in t_status["data"][0]) == True
    assert ("confidence" in t_status["data"][0]) == True
    assert ("created_at" in t_status["data"][0]) == True
    assert ("updated_at" in t_status["data"][0]) == True
    assert ("outdated_version" in t_status["data"][0]) == True
    assert ("major_behind" in t_status["data"][0]["outdated_version"]) == True
    assert ("minor_behind" in t_status["data"][0]["outdated_version"]) == True
    assert ("patch_behind" in t_status["data"][0]["outdated_version"]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("version" in t_status["data"][1]) == True
    assert ("latest_version" in t_status["data"][1]) == True
    assert ("org" in t_status["data"][1]) == True
    assert ("type" in t_status["data"][1]) == True
    assert ("package" in t_status["data"][1]) == True
    assert ("scope" in t_status["data"][1]) == True
    assert ("requirement" in t_status["data"][1]) == True
    assert ("dependencies" in t_status["data"][1]) == True
    assert ("confidence" in t_status["data"][1]) == True
    assert ("created_at" in t_status["data"][1]) == True
    assert ("updated_at" in t_status["data"][1]) == True
    assert ("outdated_version" in t_status["data"][1]) == True
    assert ("major_behind" in t_status["data"][1]["outdated_version"]) == True
    assert ("minor_behind" in t_status["data"][1]["outdated_version"]) == True
    assert ("patch_behind" in t_status["data"][1]["outdated_version"]) == True
    assert t_status["data"][0]["name"] == package_name
    assert t_status["data"][0]["org"] == package_name
    assert t_status["data"][1]["name"] == package_name
    assert t_status["data"][1]["org"] == package_name


def test_search_dependencies():
    org = "bundler"
    t_status = ion_client.search_dependencies(org)
    assert ("data" in t_status) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("version" in t_status["data"][0]) == True
    assert ("latest_version" in t_status["data"][0]) == True
    assert ("org" in t_status["data"][0]) == True
    assert ("type" in t_status["data"][0]) == True
    assert ("package" in t_status["data"][0]) == True
    assert ("scope" in t_status["data"][0]) == True
    assert ("requirement" in t_status["data"][0]) == True
    assert ("dependencies" in t_status["data"][0]) == True
    assert ("confidence" in t_status["data"][0]) == True
    assert ("created_at" in t_status["data"][0]) == True
    assert ("updated_at" in t_status["data"][0]) == True
    assert ("outdated_version" in t_status["data"][0]) == True
    assert ("major_behind" in t_status["data"][0]["outdated_version"]) == True
    assert ("minor_behind" in t_status["data"][0]["outdated_version"]) == True
    assert ("patch_behind" in t_status["data"][0]["outdated_version"]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("version" in t_status["data"][1]) == True
    assert ("latest_version" in t_status["data"][1]) == True
    assert ("org" in t_status["data"][1]) == True
    assert ("type" in t_status["data"][1]) == True
    assert ("package" in t_status["data"][1]) == True
    assert ("scope" in t_status["data"][1]) == True
    assert ("requirement" in t_status["data"][1]) == True
    assert ("dependencies" in t_status["data"][1]) == True
    assert ("confidence" in t_status["data"][1]) == True
    assert ("created_at" in t_status["data"][1]) == True
    assert ("updated_at" in t_status["data"][1]) == True
    assert ("outdated_version" in t_status["data"][1]) == True
    assert ("major_behind" in t_status["data"][1]["outdated_version"]) == True
    assert ("minor_behind" in t_status["data"][1]["outdated_version"]) == True
    assert ("patch_behind" in t_status["data"][1]["outdated_version"]) == True
    assert t_status["data"][0]["name"] == org
    assert t_status["data"][0]["org"] == org
    assert t_status["data"][0]["type"] == "rubygem"
    assert t_status["data"][1]["name"] == org
    assert t_status["data"][1]["org"] == org
    assert t_status["data"][1]["type"] == "rubygem"


def test_get_latest_version_for_dependency():
    package_name = "bundler"
    ecosystem = "Ruby"
    t_status = ion_client.get_latest_version_for_dependency(package_name, ecosystem)
    assert ("meta" in t_status) == True
    assert ("links" in t_status) == True
    assert ("timestamps" in t_status) == True
    assert ("data" in t_status) == True
    assert ("copyright" in t_status["meta"]) == True
    assert ("authors" in t_status["meta"]) == True
    assert ("version" in t_status["meta"]) == True
    assert ("total_count" in t_status["meta"]) == True
    assert ("self" in t_status["links"]) == True
    assert ("created" in t_status["timestamps"]) == True
    assert ("updated" in t_status["timestamps"]) == True
    assert ("version" in t_status["data"]) == True


def test_get_raw_dependency_list():
    project_ids = [
        "90360692-dfec-46ac-8248-a8be96a48ee3",
        "27691314-3598-4abe-9293-e94b3eaa2287",
    ]
    t_status = json.loads(ion_client.get_raw_dependency_list(project_ids))
    assert ("data" in t_status) == True
    assert "dependency_list" in t_status["data"]
    assert "latest_version" in t_status["data"]["dependency_list"][0]
    assert "org" in t_status["data"]["dependency_list"][0]
    assert "name" in t_status["data"]["dependency_list"][0]
    assert "type" in t_status["data"]["dependency_list"][0]
    assert "package" in t_status["data"]["dependency_list"][0]
    assert "version" in t_status["data"]["dependency_list"][0]
    assert "scope" in t_status["data"]["dependency_list"][0]
    assert "requirement" in t_status["data"]["dependency_list"][0]
    assert "file" in t_status["data"]["dependency_list"][0]
    assert "projects_count" in t_status["data"]["dependency_list"][0]
    assert "latest_version" in t_status["data"]["dependency_list"][1]
    assert "org" in t_status["data"]["dependency_list"][1]
    assert "name" in t_status["data"]["dependency_list"][1]
    assert "type" in t_status["data"]["dependency_list"][1]
    assert "package" in t_status["data"]["dependency_list"][1]
    assert "version" in t_status["data"]["dependency_list"][1]
    assert "scope" in t_status["data"]["dependency_list"][1]
    assert "requirement" in t_status["data"]["dependency_list"][1]
    assert "file" in t_status["data"]["dependency_list"][1]
    assert "projects_count" in t_status["data"]["dependency_list"][1]


def test_get_dependency_statistics():
    project_ids = [
        "90360692-dfec-46ac-8248-a8be96a48ee3",
        "27691314-3598-4abe-9293-e94b3eaa2287",
    ]
    t_status = ion_client.get_dependency_statistics(project_ids)
    assert ("data" in t_status) == True
    assert ("direct_dependencies" in t_status["data"]) == True
    assert ("transitive_dependencies" in t_status["data"]) == True
    assert ("outdated_dependencies" in t_status["data"]) == True
    assert ("no_vesion_dependencies" in t_status["data"]) == True


def test_get_dependency_list():
    project_ids = [
        "90360692-dfec-46ac-8248-a8be96a48ee3",
        "27691314-3598-4abe-9293-e94b3eaa2287",
    ]
    t_status = ion_client.get_dependency_list(project_ids)
    assert ("data" in t_status) == True
    assert "dependency_list" in t_status["data"]
    assert "latest_version" in t_status["data"]["dependency_list"][0]
    assert "org" in t_status["data"]["dependency_list"][0]
    assert "name" in t_status["data"]["dependency_list"][0]
    assert "type" in t_status["data"]["dependency_list"][0]
    assert "package" in t_status["data"]["dependency_list"][0]
    assert "version" in t_status["data"]["dependency_list"][0]
    assert "scope" in t_status["data"]["dependency_list"][0]
    assert "requirement" in t_status["data"]["dependency_list"][0]
    assert "file" in t_status["data"]["dependency_list"][0]
    assert "projects_count" in t_status["data"]["dependency_list"][0]
    assert "latest_version" in t_status["data"]["dependency_list"][1]
    assert "org" in t_status["data"]["dependency_list"][1]
    assert "name" in t_status["data"]["dependency_list"][1]
    assert "type" in t_status["data"]["dependency_list"][1]
    assert "package" in t_status["data"]["dependency_list"][1]
    assert "version" in t_status["data"]["dependency_list"][1]
    assert "scope" in t_status["data"]["dependency_list"][1]
    assert "requirement" in t_status["data"]["dependency_list"][1]
    assert "file" in t_status["data"]["dependency_list"][1]
    assert "projects_count" in t_status["data"]["dependency_list"][1]
