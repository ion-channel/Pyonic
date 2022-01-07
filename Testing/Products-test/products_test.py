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


def test_get_product_versions():
    name = "jdk"
    version = "11.0"
    t_status = ion_client.get_product_versions(name, version)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("id" in t_status["data"][0]) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("org" in t_status["data"][0]) == True
    assert ("version" in t_status["data"][0]) == True
    assert ("up" in t_status["data"][0]) == True
    assert ("edition" in t_status["data"][0]) == True
    assert ("aliases" in t_status["data"][0]) == True
    assert ("created_at" in t_status["data"][0]) == True
    assert ("updated_at" in t_status["data"][0]) == True
    assert ("title" in t_status["data"][0]) == True
    assert ("references" in t_status["data"][0]) == True
    assert ("part" in t_status["data"][0]) == True
    assert ("language" in t_status["data"][0]) == True
    assert ("external_id" in t_status["data"][0]) == True
    assert ("source" in t_status["data"][0]) == True
    assert ("confidence" in t_status["data"][0]) == True
    assert ("vulnerability_count" in t_status["data"][0]) == True
    assert ("mttr_seconds" in t_status["data"][0]) == True
    assert ("vulnerabilities" in t_status["data"][0]) == True
    assert ("id" in t_status["data"][1]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("org" in t_status["data"][1]) == True
    assert ("version" in t_status["data"][1]) == True
    assert ("up" in t_status["data"][1]) == True
    assert ("edition" in t_status["data"][1]) == True
    assert ("aliases" in t_status["data"][1]) == True
    assert ("created_at" in t_status["data"][1]) == True
    assert ("updated_at" in t_status["data"][1]) == True
    assert ("title" in t_status["data"][1]) == True
    assert ("references" in t_status["data"][1]) == True
    assert ("part" in t_status["data"][1]) == True
    assert ("language" in t_status["data"][1]) == True
    assert ("external_id" in t_status["data"][1]) == True
    assert ("source" in t_status["data"][1]) == True
    assert ("confidence" in t_status["data"][1]) == True
    assert ("vulnerability_count" in t_status["data"][1]) == True
    assert ("mttr_seconds" in t_status["data"][1]) == True
    assert ("vulnerabilities" in t_status["data"][1]) == True


def test_get_product_search():
    searchInput = "(bundler)AND1.17.3"
    t_status = ion_client.get_product_search(searchInput)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("id" in t_status["data"][0]) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("org" in t_status["data"][0]) == True
    assert ("version" in t_status["data"][0]) == True
    assert ("up" in t_status["data"][0]) == True
    assert ("edition" in t_status["data"][0]) == True
    assert ("aliases" in t_status["data"][0]) == True
    assert ("created_at" in t_status["data"][0]) == True
    assert ("updated_at" in t_status["data"][0]) == True
    assert ("title" in t_status["data"][0]) == True
    assert ("references" in t_status["data"][0]) == True
    assert ("part" in t_status["data"][0]) == True
    assert ("language" in t_status["data"][0]) == True
    assert ("external_id" in t_status["data"][0]) == True
    assert ("source" in t_status["data"][0]) == True
    assert ("confidence" in t_status["data"][0]) == True
    assert ("vulnerability_count" in t_status["data"][0]) == True
    assert ("mttr_seconds" in t_status["data"][0]) == True
    assert ("vulnerabilities" in t_status["data"][0]) == True
    assert ("id" in t_status["data"][1]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("org" in t_status["data"][1]) == True
    assert ("version" in t_status["data"][1]) == True
    assert ("up" in t_status["data"][1]) == True
    assert ("edition" in t_status["data"][1]) == True
    assert ("aliases" in t_status["data"][1]) == True
    assert ("created_at" in t_status["data"][1]) == True
    assert ("updated_at" in t_status["data"][1]) == True
    assert ("title" in t_status["data"][1]) == True
    assert ("references" in t_status["data"][1]) == True
    assert ("part" in t_status["data"][1]) == True
    assert ("language" in t_status["data"][1]) == True
    assert ("external_id" in t_status["data"][1]) == True
    assert ("source" in t_status["data"][1]) == True
    assert ("confidence" in t_status["data"][1]) == True
    assert ("vulnerability_count" in t_status["data"][1]) == True
    assert ("mttr_seconds" in t_status["data"][1]) == True
    assert ("vulnerabilities" in t_status["data"][1]) == True
    assert t_status["data"][0]["name"] == "bundler"
    assert t_status["data"][0]["org"] == "bundler"
    assert t_status["data"][0]["id"] == 0
    assert t_status["data"][1]["name"] == "bundler"
    assert t_status["data"][1]["org"] == "bundler"
    assert t_status["data"][1]["id"] == 0


def test_get_raw_product():
    product_name = "go"
    t_status = json.loads(ion_client.get_raw_product(product_name))
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("id" in t_status["data"][0]) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("org" in t_status["data"][0]) == True
    assert ("version" in t_status["data"][0]) == True
    assert ("up" in t_status["data"][0]) == True
    assert ("edition" in t_status["data"][0]) == True
    assert ("aliases" in t_status["data"][0]) == True
    assert ("created_at" in t_status["data"][0]) == True
    assert ("updated_at" in t_status["data"][0]) == True
    assert ("title" in t_status["data"][0]) == True
    assert ("references" in t_status["data"][0]) == True
    assert ("part" in t_status["data"][0]) == True
    assert ("language" in t_status["data"][0]) == True
    assert ("external_id" in t_status["data"][0]) == True
    assert ("source" in t_status["data"][0]) == True
    assert ("confidence" in t_status["data"][0]) == True
    assert ("vulnerability_count" in t_status["data"][0]) == True
    assert ("mttr_seconds" in t_status["data"][0]) == True
    assert ("vulnerabilities" in t_status["data"][0]) == True
    assert ("id" in t_status["data"][1]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("org" in t_status["data"][1]) == True
    assert ("version" in t_status["data"][1]) == True
    assert ("up" in t_status["data"][1]) == True
    assert ("edition" in t_status["data"][1]) == True
    assert ("aliases" in t_status["data"][1]) == True
    assert ("created_at" in t_status["data"][1]) == True
    assert ("updated_at" in t_status["data"][1]) == True
    assert ("title" in t_status["data"][1]) == True
    assert ("references" in t_status["data"][1]) == True
    assert ("part" in t_status["data"][1]) == True
    assert ("language" in t_status["data"][1]) == True
    assert ("external_id" in t_status["data"][1]) == True
    assert ("source" in t_status["data"][1]) == True
    assert ("confidence" in t_status["data"][1]) == True
    assert ("vulnerability_count" in t_status["data"][1]) == True
    assert ("mttr_seconds" in t_status["data"][1]) == True
    assert ("vulnerabilities" in t_status["data"][1]) == True
    assert t_status["data"][0]["id"] == 0
    assert t_status["data"][0]["name"] == "go"
    assert t_status["data"][0]["org"] == "golang"
    assert t_status["data"][1]["id"] == 0
    assert t_status["data"][1]["name"] == "go"
    assert t_status["data"][1]["org"] == "golang"


def test_get_product():
    product_name = "go"
    t_status = ion_client.get_product(product_name)
    assert ("data" in t_status) == True
    assert len(t_status["data"]) > 0
    assert ("id" in t_status["data"][0]) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("org" in t_status["data"][0]) == True
    assert ("version" in t_status["data"][0]) == True
    assert ("up" in t_status["data"][0]) == True
    assert ("edition" in t_status["data"][0]) == True
    assert ("aliases" in t_status["data"][0]) == True
    assert ("created_at" in t_status["data"][0]) == True
    assert ("updated_at" in t_status["data"][0]) == True
    assert ("title" in t_status["data"][0]) == True
    assert ("references" in t_status["data"][0]) == True
    assert ("part" in t_status["data"][0]) == True
    assert ("language" in t_status["data"][0]) == True
    assert ("external_id" in t_status["data"][0]) == True
    assert ("source" in t_status["data"][0]) == True
    assert ("confidence" in t_status["data"][0]) == True
    assert ("vulnerability_count" in t_status["data"][0]) == True
    assert ("mttr_seconds" in t_status["data"][0]) == True
    assert ("vulnerabilities" in t_status["data"][0]) == True
    assert ("id" in t_status["data"][1]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("org" in t_status["data"][1]) == True
    assert ("version" in t_status["data"][1]) == True
    assert ("up" in t_status["data"][1]) == True
    assert ("edition" in t_status["data"][1]) == True
    assert ("aliases" in t_status["data"][1]) == True
    assert ("created_at" in t_status["data"][1]) == True
    assert ("updated_at" in t_status["data"][1]) == True
    assert ("title" in t_status["data"][1]) == True
    assert ("references" in t_status["data"][1]) == True
    assert ("part" in t_status["data"][1]) == True
    assert ("language" in t_status["data"][1]) == True
    assert ("external_id" in t_status["data"][1]) == True
    assert ("source" in t_status["data"][1]) == True
    assert ("confidence" in t_status["data"][1]) == True
    assert ("vulnerability_count" in t_status["data"][1]) == True
    assert ("mttr_seconds" in t_status["data"][1]) == True
    assert ("vulnerabilities" in t_status["data"][1]) == True
    assert t_status["data"][0]["id"] == 0
    assert t_status["data"][0]["name"] == "go"
    assert t_status["data"][0]["org"] == "golang"
    assert t_status["data"][1]["id"] == 0
    assert t_status["data"][1]["name"] == "go"
    assert t_status["data"][1]["org"] == "golang"
