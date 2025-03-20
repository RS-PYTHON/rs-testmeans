import pytest
import json
from src.common.common_routes import clean_token_dict
from datetime import datetime

@pytest.mark.unit
def test_clean_token_dict(path_to_config, empty_token_dict):
    """ Test the method to clean the dictionary containing the token information"""
    
    # ----- Test that an exception is raised if the path to the json authentification file doesn't exist
    wrong_path_to_config = "/this/path/does/not/exist"
    with pytest.raises(FileNotFoundError) as exc:
        clean_token_dict(empty_token_dict, wrong_path_to_config)
    
    # ----- Test that an exception is raised when we pass an empty dictionary to the function
    token_dict = {}
    with  pytest.raises(KeyError) as excinfo:
        clean_token_dict(token_dict, path_to_config)
      
    # ----- Test that an exception is raised when we pass a dictionary with missing keys to the function
    token_dict = {
        "client_id": "client_id",
        "client_secret": "client_secret",
        "username": "test",
        "password": "test",
        "grant_type": "password",
        "access_token_list": [],
        "access_token_creation_date": [],
        "expires_in_list": [],
        "refresh_token_list": [],
        "refresh_token_creation_date": [],
        #"refresh_expires_in_list": []
    }
    with  pytest.raises(KeyError) as exc:
        clean_token_dict(token_dict, path_to_config)
    assert "Mandatory key refresh_expires_in_list is missing from the json token dictionary" in str(exc.value)   
    
     # ----- Test that an exception is raised when we pass a dictionary with wrong type for a given key
    token_dict = {
        "client_id": [], # Here the "client" key should be a string
        "client_secret": "client_secret",
        "username": "test",
        "password": "test",
        "grant_type": "password",
        "access_token_list": [],
        "access_token_creation_date": [],
        "expires_in_list": [],
        "refresh_token_list": [],
        "refresh_token_creation_date": [],
        "refresh_expires_in_list": []
    }
    with  pytest.raises(TypeError) as exc:
        clean_token_dict(token_dict, path_to_config)
    assert "Value from key client_id doesn't have the right type:got <class 'list'>, expected <class 'str'>" in str(exc.value)
    
    
    # ----- Test that nothing special is done if we pass a token dictionary with valid tokens and
    # a valid json file where to write the token dictionary
    old_token_dict = {
        "client_id": "client_id", # Here the "client" key should be a string
        "client_secret": "client_secret",
        "username": "test",
        "password": "test",
        "grant_type": "password",
        "access_token_list": ["Token1"],
        "access_token_creation_date": [datetime.now().isoformat()],
        "expires_in_list": [70],
        "refresh_token_list": ["RefreshToken1"],
        "refresh_token_creation_date": [datetime.now().isoformat()],
        "refresh_expires_in_list": [3600]
    }
    new_token_dict = old_token_dict.copy()
    clean_token_dict(new_token_dict, path_to_config)
    assert new_token_dict["access_token_list"] == old_token_dict["access_token_list"]
    
    # ----- Test that token information are not eleted if the access token is expried
    # but its refresh token is not expired yet
    old_token_dict = {
        "client_id": "client_id", # Here the "client" key should be a string
        "client_secret": "client_secret",
        "username": "test",
        "password": "test",
        "grant_type": "password",
        "access_token_list": ["Token1"],
        "access_token_creation_date": ["2023-01-01T00:00:00.000000"],
        "expires_in_list": [70],
        "refresh_token_list": ["RefreshToken1"],
        "refresh_token_creation_date": [datetime.now().isoformat()],
        "refresh_expires_in_list": [3600]
    }
    new_token_dict = old_token_dict.copy()
    clean_token_dict(new_token_dict, path_to_config)
    assert new_token_dict["access_token_list"] == old_token_dict["access_token_list"]
    
    # ----- Test that all information related to the token are removed if we pass a dictionary 
    # with both an expired token and an expired refresh token
    old_token_dict = {
        "client_id": "client_id", # Here the "client" key should be a string
        "client_secret": "client_secret",
        "username": "test",
        "password": "test",
        "grant_type": "password",
        "access_token_list": ["Token1"],
        "access_token_creation_date": ["2023-01-01T00:00:00.000000"],
        "expires_in_list": [70],
        "refresh_token_list": ["RefreshToken1"],
        "refresh_token_creation_date": ["2023-01-01T00:00:00.000000"],
        "refresh_expires_in_list": [3600]
    }
    new_token_dict = old_token_dict.copy()
    clean_token_dict(new_token_dict, path_to_config)
    assert new_token_dict["access_token_list"] == []
    
    # Check that the json file have been correctly updated
    with open(path_to_config, "r", encoding="utf-8") as fichier:
        file_token_fict = json.load(fichier)
    assert file_token_fict == new_token_dict
    
