from jwkest.jwk import rsa_load, RSAKey
from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.storage import MongoWrapper
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo


IP = '192.168.0.3'
sub_hash_salt = '32423asew'

signing_key = RSAKey(key=rsa_load('/src/login/oidc/keys/server.key'), use='sig', alg='RS256')
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


authz_codes = dict()
access_tokens = dict()
refresh_tokens = dict()
subject_identifiers = dict()

subject_id_factory = HashBasedSubjectIdentifierFactory(sub_hash_salt)
authz_state = AuthorizationState(subject_id_factory,
                                 authz_codes,
                                 access_tokens,
                                 refresh_tokens,
                                 subject_identifiers)
client_db = dict()
user_db = dict()
provider = Provider(signing_key, configuration_information,
                    authz_state, client_db, Userinfo(user_db))

'''
                    authorization_code_lifetime=300,
                    access_token_lifetime=60*60*24,
                    refresh_token_lifetime=60*60*24*365,
                    refresh_token_threshold=None)
'''
