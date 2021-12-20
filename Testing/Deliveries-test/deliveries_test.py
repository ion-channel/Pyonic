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


def test_get_delivery_destinations():
    team_id = "646fa3e5-e274-4884-aef2-1d47f029c289"
    t_status = ion_client.get_delivery_destinations(team_id)
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"][0]) == True
    assert ("team_id" in t_status["data"][0]) == True
    assert ("location" in t_status["data"][0]) == True
    assert ("region" in t_status["data"][0]) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("type" in t_status["data"][0]) == True
    assert ("id" in t_status["data"][1]) == True
    assert ("team_id" in t_status["data"][1]) == True
    assert ("location" in t_status["data"][1]) == True
    assert ("region" in t_status["data"][1]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("type" in t_status["data"][1]) == True
    assert t_status["data"][0]["team_id"] == team_id
    assert t_status["data"][1]["team_id"] == team_id


def test_delete_delivery_destination():
    team_id = "95d06aa3-ec21-4602-86c2-c79605d81d09"
    t_status = ion_client.delete_delivery_destination(team_id)
    try:
        assert ("data" in t_status) == True
        assert ("meta" in t_status) == True
        assert t_status["data"] == []
    except TypeError:
        t_status = json.loads(t_status)
        assert ("message" in t_status) == True
        assert ("code" in t_status) == True
        assert t_status["message"] == "no internal destinations found for deletion"
        assert t_status["code"] == 404


def test_create_delivery_destination():
    team_id = "95d06aa3-ec21-4602-86c2-c79605d81d09"
    location = "location1"
    region = "us-east-1"
    name = "endpoint_testing"
    desttype = "s3"
    t_status = ion_client.create_delivery_destination(
        team_id, location, region, name, desttype
    )
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"]) == True
    assert ("team_id" in t_status["data"]) == True
    assert ("location" in t_status["data"]) == True
    assert ("region" in t_status["data"]) == True
    assert ("name" in t_status["data"]) == True
    assert ("type" in t_status["data"]) == True
    assert ("access_key" in t_status["data"]) == True
    assert ("secret_key" in t_status["data"]) == True
    assert t_status["data"]["team_id"] == team_id
    assert t_status["data"]["location"] == location
    assert t_status["data"]["region"] == region
    assert t_status["data"]["name"] == name
    assert t_status["data"]["type"] == desttype
