import logging
import datetime

from jwkest.jwk import rsa_load, RSAKey
from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.storage import MongoWrapper
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo


IP = '192.168.0.3'
sub_hash_salt = '32423asew'

signing_key = RSAKey(key=rsa_load('/src/login/web/keys/server.key'), use='sig', alg='RS256')
configuration_information = {
    'issuer': 'https://localhost',
    'authorization_endpoint': 'http://' + IP + '/authorization',
    'token_endpoint': 'http://' + IP + '/token',
    'userinfo_endpoint': 'http://' + IP + '/userinfo',
    'registration_endpoint': 'http://' + IP + '/registration',
    'response_types_supported': ['code', 'id_token token'],
    'id_token_signing_alg_values_supported': [signing_key.alg],
    'response_modes_supported': ['fragment', 'query'],
    'subject_types_supported': ['public', 'pairwise'],
    'grant_types_supported': ['authorization_code', 'implicit'],
    'claim_types_supported': ['normal'],
    'claims_parameter_supported': True,
    'claims_supported': ['sub', 'name', 'given_name', 'family_name'],
    'request_parameter_supported': False,
    'request_uri_parameter_supported': False,
    'scopes_supported': ['openid', 'profile']
}


class DictWrapper(object):
    def __init__(self, name, d=None):
        self.name = name
        if d:
            self.data = dict(d)
        else:
            self.data = dict()

    def __setitem__(self, key, value):
        logging.debug('{} --- setitem {} --> {}'.format(self.name, key, value))
        self.data[key] = value

    def __getitem__(self, key):
        v = self.data[key]
        logging.debug('{} --- getitem {} --> {}'.format(self.name, key, v))
        return v

    def __delitem__(self, key):
        logging.debug('{} --- delitem {}'.format(self.name, key))
        del self.data[key]

    def __contains__(self, key):
        logging.debug('{} --- contains {}'.format(self.name, key))
        return key in self.data

    def items(self):
        logging.debug('{} ---  items --'.format(self.name))
        return self.data.items()

    def pop(self, key, default=None):
        v = self.data.pop(key)
        logging.debug('{} --- pop {} --> {}'.format(self.name, key, v))
        return v


authz_codes = DictWrapper('authz_codes')
access_tokens = DictWrapper('access_tokens')
refresh_tokens = DictWrapper('refresh_tokens')
subject_identifiers = DictWrapper('subject_identifiers')

subject_id_factory = HashBasedSubjectIdentifierFactory(sub_hash_salt)
authz_state = AuthorizationState(subject_id_factory,
                                 authz_codes,
                                 access_tokens,
                                 refresh_tokens,
                                 subject_identifiers)
client_db = DictWrapper('client_db',
            {'some-consumer':{
                'client_secret': 'consumer-secret',
                'redirect_uris':['http://192.168.0.3:7000/oidc_callback', 'http://127.0.0.1:7000/oidc_callback'],
                'response_types': ['code', 'id_token token'],
                'token_endpoint_auth_method':'client_secret_post'
                }
            })

#https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
user_db = DictWrapper('user_db',
        {
            '89d88b81-fbc0-48fa-badb-d32854d3d93a': {
                'sub':'89d88b81-fbc0-48fa-badb-d32854d3d93a',
                'email': 'pablo.rey@econo.unlp.edu.ar',
                'email_verified': True,
                'phone_number': '4237467',
                'phone_number_verified': False,
                'name':'Pablo Daniel',
                'given_name': 'Pablo Daniel Rey',
                'family_name':'Rey',
                'picture': 'http://192.168.0.3:9000/files/api/v1.0/archivo/6456hgv75756hg7667',
                'gender': 'Masculino',
                'birdthdate': datetime.datetime.now().date(),
                'address': {
                    "street_address": "1234 Hollywood Blvd.",
                    "locality": "Los Angeles",
                    "region": "CA",
                    "postal_code": "90210",
                    "country": "US"
                },
                'dni':'27294557',

                'legajo':None
            }
        })
provider = Provider(signing_key, configuration_information,
                    authz_state, client_db, Userinfo(user_db))


def should_fragment_encode(authn_req):
    ''' error en la función de pyop asi que la parcheo aca y la defino hasta poder resolverlo mejor '''
    if authn_req['response_type'] == 'code':
        return False
    if authn_req['response_type'] == ['code']:
        return False
    return True


'''
                    authorization_code_lifetime=300,
                    access_token_lifetime=60*60*24,
                    refresh_token_lifetime=60*60*24*365,
                    refresh_token_threshold=None)
'''
