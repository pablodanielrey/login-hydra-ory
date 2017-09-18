import os
import logging
import datetime

from jwkest.jwk import rsa_load, RSAKey
from pyop.authz_state import AuthorizationState
from pyop.provider import Provider
from pyop.subject_identifier import HashBasedSubjectIdentifierFactory
from pyop.userinfo import Userinfo

from login.model import LoginModel
from login.model.entities import AuthzCode, AccessToken, RefreshToken, SubjectIdentifier
from login.model.engine import Session, UsersSession


LOGIN_OIDC_URL = os.environ['LOGIN_OIDC_URL']
LOGIN_OIDC_ISSUER = os.environ['LOGIN_OIDC_ISSUER']
sub_hash_salt = os.environ['HASH_SALT']

signing_key = RSAKey(key=rsa_load('/src/login/web/keys/server.key'), use='sig', alg='RS256')
configuration_information = {
    'issuer': LOGIN_OIDC_ISSUER,
    'authorization_endpoint': LOGIN_OIDC_URL + '/authorization',
    'token_endpoint': LOGIN_OIDC_URL + '/token',
    'userinfo_endpoint': LOGIN_OIDC_URL + '/userinfo',
    'registration_endpoint': LOGIN_OIDC_URL + '/registration',
    'response_types_supported': ['code', 'id_token token'],
    'id_token_signing_alg_values_supported': [signing_key.alg],
    'response_modes_supported': ['fragment', 'query'],
    'subject_types_supported': ['public', 'pairwise'],
    'grant_types_supported': ['authorization_code', 'implicit'],
    'claim_types_supported': ['normal'],
    'claims_parameter_supported': True,
    'claims_supported': [
                "sub", 'phone', 'address', 'email',
                "name", "given_name", "family_name", "middle_name",
                "nickname", "profile", "picture", "website", "gender",
                "birthdate", "zoneinfo", "locale", "updated_at",
                "preferred_username"
            ],
    'request_parameter_supported': False,
    'request_uri_parameter_supported': False,
    'scopes_supported': ['openid','email','phone','profile','address','econo']
}


# ------------------ usuarios -------------------

class UsersWrapper(object):
    '''
        conecta el OIDC con el LoginModel para obtener los usuarios
    '''

    def __init__(self):
        self.name = 'usuarios'

    def __setitem__(self, key, value):
        logging.debug('{} --- setitem {} --> {}'.format(self.name, key, value))
        raise UsuariosError()

    def __getitem__(self, key):
        s = UsersSession()
        try:
            v = LoginModel.obtener_usuario(s, uid=key)
            logging.debug('{} --- getitem {} --> {}'.format(self.name, key, v))
            return v
        finally:
            s.close()

    def __delitem__(self, key):
        logging.debug('{} --- delitem {}'.format(self.name, key))
        raise UsuariosError()

    def __contains__(self, key):
        s = UsersSession()
        try:
            v = LoginModel.existe(s, uid=key)
            logging.debug('{} --- contains {}'.format(self.name, key))
            return v
        finally:
            s.close()

    def items(self):
        logging.debug('{} ---  items --'.format(self.name))
        raise UsersError()

    def pop(self, key, default=None):
        logging.debug('{} --- pop {}'.format(self.name, key))
        raise UsersError()


#-------------- login --------------------------------

import json

class SqlAlchemyWrapper(object):

    def __init__(self, clase):
        self.clase = clase

    def __setitem__(self, key, value):
        vvalue = json.dumps(value)
        s = Session()
        try:
            c = self.clase()
            c.code = key
            c.valor = vvalue
            s.add(c)
            s.commit()
        finally:
            s.close()


    def __getitem__(self, key):
        s = Session()
        try:
            v = s.query(self.clase).filter_by(code=key).one_or_none()
            if v:
                return json.loads(v.valor)
            return None
        finally:
            s.close()

    def __delitem__(self, key):
        s = Session()
        try:
            s.query(self.clase).filter_by(code=key).delete()
            s.commit()
        finally:
            s.close()

    def __contains__(self, key):
        s = Session()
        try:
            return s.query(self.clase).filter_by(code=key).count() > 0
        finally:
            s.close()

    def items(self):
        s = Session()
        try:
            items = []
            for i in s.query(self.clase).all():
                items.append((i.code, json.loads(i.valor)))
            return items
        finally:
            s.close()

    def pop(self, key, default=None):
        raise Exception()



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


authz_codes = SqlAlchemyWrapper(AuthzCode)
access_tokens = SqlAlchemyWrapper(AccessToken)
refresh_tokens = SqlAlchemyWrapper(RefreshToken)
subject_identifiers = SqlAlchemyWrapper(SubjectIdentifier)

subject_id_factory = HashBasedSubjectIdentifierFactory(sub_hash_salt)
authz_state = AuthorizationState(subject_id_factory,
                                 authz_codes,
                                 access_tokens,
                                 refresh_tokens,
                                 subject_identifiers)
client_db = DictWrapper('client_db',
            {
                'users':{
                    'client_secret': 'consumer-secret',
                    'redirect_uris':['http://usuarios.econo.unlp.edu.ar:5005/oidc_callback'],
                    'response_types': ['code', 'id_token token'],
                    'token_endpoint_auth_method':'client_secret_post'
                },
                'sileg': {
                    'client_secret': 'consumer-secret',
                    'redirect_uris':['http://sileg.econo.unlp.edu.ar:5020/oidc_callback'],
                    'response_types': ['code', 'id_token token'],
                    'token_endpoint_auth_method':'client_secret_post'
                },
                'issues': {
                    'client_secret': 'consumer-secret',
                    'redirect_uris':['http://issues.econo.unlp.edu.ar:5015/oidc_callback'],
                    'response_types': ['code', 'id_token token'],
                    'token_endpoint_auth_method':'client_secret_post'
                }
            })


"""
from pyop.access_token import extract_bearer_token_from_http_request
from urllib.parse import parse_qsl
from pyop.exceptions import AuthorizationError
from pyop.exceptions import InvalidAccessToken
from pyop.exceptions import InvalidTokenRequest
from pyop.exceptions import InvalidAuthorizationCode
from oic.oic import scope2claims
from oic import rndstr
from oic.exception import MessageException
from oic.oic import PREFERENCE2PROVIDER
from oic.oic import scope2claims
from oic.oic.message import AccessTokenRequest
from oic.oic.message import AccessTokenResponse
from oic.oic.message import AuthorizationRequest
from oic.oic.message import AuthorizationResponse
from oic.oic.message import EndSessionRequest
from oic.oic.message import EndSessionResponse
from oic.oic.message import IdToken
from oic.oic.message import OpenIDSchema
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import RefreshAccessTokenRequest
from oic.oic.message import RegistrationRequest
from oic.oic.message import RegistrationResponse

class MyProvider(Provider):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def handle_userinfo_request(self, request=None, http_headers=None):
        # type: (Optional[str], Optional[Mapping[str, str]]) -> oic.oic.message.OpenIDSchema
        '''
        Handles a userinfo request.
        :param request: urlencoded request (either query string or POST body)
        :param http_headers: http headers
        '''
        if http_headers is None:
            http_headers = {}
        userinfo_request = dict(parse_qsl(request))
        bearer_token = extract_bearer_token_from_http_request(userinfo_request, http_headers.get('Authorization'))

        introspection = self.authz_state.introspect_access_token(bearer_token)
        if not introspection['active']:
            raise InvalidAccessToken('The access token has expired')
        scope = introspection['scope']
        user_id = self.authz_state.get_user_id_for_subject_identifier(introspection['sub'])


        requested_claims = scope2claims(scope.split())
        authentication_request = self.authz_state.get_authorization_request_for_access_token(bearer_token)
        requested_claims.update(self._get_requested_claims_in(authentication_request, 'userinfo'))
        user_claims = self.userinfo.get_claims_for(user_id, requested_claims)


        logging.debug('----------------------------------------------------------')
        logging.debug(scope)
        logging.debug(requested_claims)



        user_claims.setdefault('sub', introspection['sub'])
        response = OpenIDSchema(**user_claims)
        #logger.debug('userinfo=%s from requested_claims=%s userinfo=%s', response, requested_claims, user_claims)
        return response

def obtener_provider(users_db):
    return MyProvider(signing_key, configuration_information, authz_state, client_db, Userinfo(users_db))
"""

def obtener_provider():
    return Provider(signing_key, configuration_information, authz_state, client_db, Userinfo(UsersWrapper()))


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
