"""
    docs/api.swagger.json

    scopes:
        "hydra.clients": "A scope required to manage OAuth 2.0 Clients",
        "hydra.consent": "A scope required to fetch and modify consent requests",
        "hydra.keys.create": "A scope required to create JSON Web Keys",
        "hydra.keys.delete": "A scope required to delete JSON Web Keys",
        "hydra.keys.get": "A scope required to fetch JSON Web Keys",
        "hydra.keys.update": "A scope required to get JSON Web Keys",
        "hydra.policies": "A scope required to manage access control policies",
        "hydra.warden": "A scope required to make access control inquiries",
        "hydra.warden.groups": "A scope required to manage warden groups",
        "offline": "A scope required when requesting refresh tokens",
        "openid": "Request an OpenID Connect ID Token"


"""

import os
import datetime
import requests
from requests.auth import HTTPBasicAuth

VERIFY_SSL=False
HYDRA_HOST = os.environ['OIDC_HOST']
HYDRA_CLIENT_ID = os.environ['SCRIPTS_CLIENT_ID']
HYDRA_CLIENT_SECRET = os.environ['SCRIPTS_CLIENT_SECRET']

def _token_expired(tk):
    """ chequea que el token no esté expirado """
    if 'expires_aux' not in tk:
        return True
    actual = datetime.datetime.now().timestamp()
    return tk['expires_aux'] <= actual

def _token_set_expired(tk):
    """ calcula en timestamp la expiración + xx segundos de marjen """
    tk['expires_aux'] = datetime.datetime.now().timestamp() + tk['expires_in'] - 60


def obtener_token():
    client_id = HYDRA_CLIENT_ID
    client_secret = HYDRA_CLIENT_SECRET
    auth = HTTPBasicAuth(client_id, client_secret)
    data = {
        'grant_type':'client_credentials',
        'scope':'hydra.policies'
    }
    headers = {
        'Accept':'application/json'
    }
    url = HYDRA_HOST + '/oauth2/token'
    r = requests.post(url, verify=VERIFY_SSL, auth=auth, headers=headers, data=data)
    if not r.ok:
        raise Exception(r.text)
    
    token = r.json()
    _token_set_expired(token)
    return token['access_token']

def get_bearer_header(token):
    headers = {
        'Authorization': 'bearer {}'.format(token),
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    return headers


def get_policies():
    url = HYDRA_HOST + '/policies'
    h = get_bearer_header(obtener_token())
    r = requests.get(url, verify=VERIFY_SSL, headers=h, allow_redirects=False)
    if not r.ok:
        raise Exception(r.status_code)
    return r.json()