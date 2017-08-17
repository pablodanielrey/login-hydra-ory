from jwkest.jwk import rsa_load, RSAKey
from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.storage import MongoWrapper
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo

signing_key = RSAKey(key=rsa_load('/src/login/oidc/keys/server.key'), use='sig', alg='RS256')
configuration_information = {
    'issuer': 'https://localhost',
    'authorization_endpoint': 'https://163.10.56.57/authorization',
    'token_endpoint': 'https://163.10.56.57/token',
    'userinfo_endpoint': 'https://163.10.56.57/userinfo',
    'registration_endpoint': 'https://163.10.56.57/registration',
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

subject_id_factory = HashBasedSubjectIdentifierFactory(sub_hash_salt)
authz_state = AuthorizationState(subject_id_factory,
                                 MongoWrapper(db_uri, 'provider', 'authz_codes'),
                                 MongoWrapper(db_uri, 'provider', 'access_tokens'),
                                 MongoWrapper(db_uri, 'provider', 'refresh_tokens'),
                                 MongoWrapper(db_uri, 'provider', 'subject_identifiers'))
client_db = MongoWrapper(db_uri, 'provider', 'clients')
user_db = MongoWrapper(db_uri, 'provider', 'users')
provider = Provider(signing_key, configuration_information, authz_state, client_db, Userinfo(user_db))
