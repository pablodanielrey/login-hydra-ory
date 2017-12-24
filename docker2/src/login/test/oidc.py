import os
import logging
import requests
from requests.auth import HTTPBasicAuth
import urllib
from urllib import parse

class OIDC:

    auth_url = os.environ['HYDRA_HOST'] + '/oauth2/auth'
    token_url = os.environ['HYDRA_HOST'] + '/oauth2/token'

    def __init__(self, verify=False):
        #self.session = session
        self.verify = verify

    def auth_token(self, client_id, scopes=[]):
        #application/x-www-form-urlencoded
        #auth = HTTPBasicAuth(client_id, client_secret)
        params = {
            'client_id': client_id,
            'response_type': 'code',
            #'redirect_uri': redirect_uri,
            'scope': ' '.join(scopes),
            'state': 'algodealgo'
        }
        #r = requests.get(url, verify=False, allow_redirects=False, params=params)
        #return r
        return self.auth_url + "?" + urllib.parse.urlencode(params)

    def access_token(self, client_id, client_secret, code):
        #application/x-www-form-urlencoded
        auth = HTTPBasicAuth(client_id, client_secret)
        data = {
            'client_id': client_id,
            'grant_type': 'authorization_code',
            'code': code,
            #'redirect_uri': redirect_uri
        }
        r = requests.post(self.token_url, verify=self.verify, allow_redirects=False, auth=auth, data=data)
        return r


    def callback(self, params):
        code = params.get('code', None, str)
        state = params.get('state', None, str)

        r = self.access_token('consumer-test', 'consumer-secret', code)
        if not r.ok:
            logging.debug(r.text)
            logging.debug(r.status_code)
            logging.debug(r.headers.items())
            return None

        token = r.json()
        token['access_token']
        token['expires_in']
        token['id_token']
        token['refresh_token']
        token['scope']
        token['token_type']
        return token
