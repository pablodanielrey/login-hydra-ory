import os
import logging
import requests
from requests.auth import HTTPBasicAuth
import urllib
from urllib import parse

class OIDC:

    userinfo_url = os.environ['HYDRA_HOST'] + '/userinfo'
    auth_url = os.environ['HYDRA_HOST'] + '/oauth2/auth'
    token_url = os.environ['HYDRA_HOST'] + '/oauth2/token'

    def __init__(self, client_id, client_secret, redirect_uri, verify=False):
        #self.session = session
        self.verify = verify
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirec_uri = redirect_uri

    def auth_token(self, state, nonce, scopes=[]):
        #application/x-www-form-urlencoded
        #auth = HTTPBasicAuth(client_id, client_secret)
        params = {
            'client_id': self.client_id,
            'response_type': 'code',
            'redirect_uri': self.redirect_uri,
            'scope': ' '.join(scopes),
            'state': state,
            'nonce': nonce
        }
        #r = requests.get(url, verify=False, allow_redirects=False, params=params)
        #return r
        return self.auth_url + "?" + urllib.parse.urlencode(params)

    def access_token(self, code):
        #application/x-www-form-urlencoded
        auth = HTTPBasicAuth(self.client_id, self.client_secret)
        data = {
            'client_id': self.client_id,
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': self.redirect_uri
        }
        r = requests.post(self.token_url, verify=self.verify, allow_redirects=False, auth=auth, data=data)
        return r


    def callback(self, params):
        code = params.get('code', None, str)
        state = params.get('state', None, str)

        r = self.access_token(code)
        if not r.ok:
            logging.debug(r.text)
            logging.debug(r.status_code)
            logging.debug(r.headers.items())
            return None

        token = r.json()
        logging.debug(token)
        token['access_token']
        token['expires_in']
        token['id_token']
        token['refresh_token']
        token['scope']
        token['token_type']
        return token

    def userinfo(self, token):
        headers = {
            'Authorization': 'Bearer {}'.format(token)
        }
        r = requests.post(self.userinfo_url, verify=self.verify, allow_redirects=False, headers=headers)
        if not r.ok:
            return None
        return r.json()



from functools import wraps
import flask

class ResourceServer:

    introspect_url = os.environ['HYDRA_HOST'] + '/oauth2/introspect'

    def __init__(self, client_id, client_secret, realm='', verify=False):
        self.realm = realm
        self.verify = verify
        self.client_id = client_id
        self.client_secret = client_secret

    def require_valid_token(self, f):
        @wraps(f)
        def decorated_function(*args, **kwargs):

            ''' chequeo el token por introspeccion '''
            token = self.bearer_token(flask.request.headers)
            if not token:
                return self.invalid_token()
            tk = self.introspect_token(token)
            logging.debug(tk)
            if not tk or not tk['active']:
                return self.invalid_request()

            ''' agrego el token a los argumentos '''
            kwargs['token'] = tk

            return f(*args, **kwargs)

        return decorated_function


    def bearer_token(self, headers):
        if 'Authorization' in headers:
            auth = headers['Authorization'].split(' ')
            if auth[0].lower() == 'bearer':
                return auth[1]
        return None

    def introspect_token(self, token, scopes=[]):
        auth = HTTPBasicAuth(self.client_id, self.client_secret)
        data = {
            'token':token
        }
        if len(scopes) > 0:
            data['scope'] = ' '.join(scopes)
        headers = {
            'Accept':'application/json'
        }
        r = requests.post(self.introspect_url, verify=self.verify, allow_redirects=False, auth=auth, headers=headers, data=data)
        if not r.ok:
            return None
        return r.json()


    def invalid_request(self):
        return self.require_auth(text='Bad Request', error='invalid_request', status=400)

    def invalid_token(self):
        return self.require_auth(text='Unauthorized', error='invalid_token', status=401)

    def insufficient_scope(self):
        return self.require_auth(text='Forbidden', error='insufficient_scope', status=403)

    def require_auth(self, text='Unauthorized', error=None, status=401, error_description=''):
        headers = None
        if error:
            headers = {
                'WWW-Authenticate': 'Basic realm=\"{}\", error=\"{}\", error_description:\"{}\"'.format(self.realm, error, error_description)
            }
        else:
            headers = {
                'WWW-Authenticate': 'Basic realm=\"{}\"'.format(self.realm)
            }
        return (text, status, headers)
