import pyonic
import pytest

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


def test_get_tokens():
    t_status = ion_client.get_tokens()
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"][0]) == True
    assert ("created_at" in t_status["data"][0]) == True
    assert ("updated_at" in t_status["data"][0]) == True
    assert ("user_id" in t_status["data"][0]) == True
    assert ("expires_at" in t_status["data"][0]) == True
    assert ("name" in t_status["data"][0]) == True
    assert ("cli" in t_status["data"][0]) == True
    assert ("jwt" in t_status["data"][0]) == True
    assert ("data" in t_status) == True
    assert ("id" in t_status["data"][1]) == True
    assert ("created_at" in t_status["data"][1]) == True
    assert ("updated_at" in t_status["data"][1]) == True
    assert ("user_id" in t_status["data"][1]) == True
    assert ("expires_at" in t_status["data"][1]) == True
    assert ("name" in t_status["data"][1]) == True
    assert ("cli" in t_status["data"][1]) == True
    assert ("jwt" in t_status["data"][1]) == True
