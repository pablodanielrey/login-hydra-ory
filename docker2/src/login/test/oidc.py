import os
import requests
from requests.auth import HTTPBasicAuth
import urllib
from urllib import parse

class OIDC:

    def auth_token(self, client_id, redirect_uri, scopes=[]):
        #application/x-www-form-urlencoded
        #auth = HTTPBasicAuth(client_id, client_secret)
        url = os.environ['HYDRA_HOST'] + '/oauth2/auth'
        params = {
            'client_id': client_id,
            'response_type': 'code',
            #'redirect_uri': redirect_uri,
            'scope': ' '.join(scopes),
            'state': 'algodealgo'
        }
        #r = requests.get(url, verify=False, allow_redirects=False, params=params)
        #return r
        return url + "?" + urllib.parse.urlencode(params)
