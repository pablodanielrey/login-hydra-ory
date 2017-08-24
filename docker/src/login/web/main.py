import logging
logging.getLogger().setLevel(logging.DEBUG)
#logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
#logging.basicConfig(level=logging.DEBUG)

import flask
from flask import Flask, request, send_from_directory, jsonify, redirect, session, url_for, make_response
from flask_jsontools import jsonapi
import flask_session

from login.model import Session, LoginModel
from login.model.exceptions import *

from rest_utils import register_encoder

import urllib.parse
from pyop.exceptions import InvalidAuthenticationRequest
from pyop.exceptions import InvalidClientAuthentication
from pyop.exceptions import InvalidAccessToken
from pyop.exceptions import OAuthError
from pyop.exceptions import BearerTokenError
from pyop.access_token import AccessToken
from oic.oic.message import AuthorizationRequest
from oic.oic.message import TokenErrorResponse
from oic.oic.message import UserInfoErrorResponse


# uso should_fragment_encode pero parcheada de mi codigo
#from pyop.util import should_fragment_encode
#
from .OIDC import should_fragment_encode, obtener_provider



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
        s = Session()
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
        s = Session()
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




# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/login/web')
app.debug = True
register_encoder(app)
app.debug = True
app.config['SECRET_KEY'] = 'algo-secreto2'
app.config['SESSION_COOKIE_NAME'] = 'oidc_session'
#flask_session.Session(app)

provider = obtener_provider(UsersWrapper())


''' para OIDC OP -------------------- '''

@app.route('/.well-known/openid-configuration')
def provider_config():
    return make_response(provider.provider_configuration.to_json())

@app.route('/authorization')
def authorization_endpoints():
    try:
        args = urllib.parse.urlencode(flask.request.args)
        authn_req = provider.parse_authentication_request(args, flask.request.headers)
    except InvalidAuthenticationRequest as e:
        logging.exception(e)
        error_url = e.to_error_url()

        if error_url:
            return make_response(error_url, 303)
        else:
            return make_response("error: {}".format(str(e)), 400)

    flask.session['authn_req'] = authn_req.to_dict()
    return redirect(url_for('send'), 303)


@app.route('/login', methods=['POST'])
@jsonapi
def login():

    authn_req = flask.session.get('authn_req', None)
    if not authn_req:
        ''' aca debería redireccionar al sitio por defecto, pero por ahora tiro un error de seguridad '''
        raise SeguridadError()

    usuario = request.form.get('u', None)
    password = request.form.get('p', None)

    if not usuario or not password:
        raise ClaveError()

    s = Session()
    try:
        rusuario = LoginModel.login(session=s, usuario=usuario, clave=password)
        if rusuario:
            flask.session['usuario_id'] = rusuario.usuario_id
            #return redirect(url_for('redirection_auth_endpoint'))
            usuario = LoginModel.obtener_usuario(session=s, uid=rusuario.usuario_id)
            return {'url': url_for('redirection_auth_endpoint'), 'usuario':usuario}, 200
        else:
            raise ClaveError()
    finally:
        s.close()


@app.route('/finalize_auth')
def redirection_auth_endpoint():
    user_id = flask.session['usuario_id']
    authn_req = flask.session['authn_req']
    logging.debug(user_id)
    logging.debug(authn_req)

    authn_response = provider.authorize(AuthorizationRequest().from_dict(authn_req), user_id)
    logging.debug(authn_response)
    logging.debug(should_fragment_encode(authn_req))
    return_url = authn_response.request(authn_req['redirect_uri'], should_fragment_encode(authn_req))

    logging.debug('------------------------------')
    logging.debug(return_url)
    logging.debug('------------------------------')

    return redirect(return_url, 303)

@app.route('/token', methods=['POST', 'GET'])
def token_endpoint():
    try:
        '''
        args = urllib.parse.urlencode(flask.request.args)
        '''
        token_response = provider.handle_token_request(request.get_data().decode('utf-8'), flask.request.headers)
        return token_response.to_json()
    except InvalidClientAuthentication as e:
        logging.exception(e)
        error_resp = TokenErrorResponse(error='invalid_client', error_description=str(e))
        http_response = make_response(error_resp.to_json())
        http_response.status_code = 401
        http_response.headers['WWW-Authenticate'] = 'Basic realm=oidc'
        return http_response
    except OAuthError as e:
        error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
        return error_resp.to_json(), 400


def _userinfo_endpoint(data, headers):
    try:
        logging.debug('userinfo')
        logging.debug(data)
        response = provider.handle_userinfo_request(data, headers)
        logging.debug(response)
        return response.to_json()
    except (BearerTokenError, InvalidAccessToken) as e:
        error_resp = UserInfoErrorResponse(error='invalid_token', error_description=str(e))
        http_response = make_response(error_resp.to_json())
        http_response.status_code = 401
        http_response.headers['WWW-Authenticate'] = AccessToken.BEARER_TOKEN_TYPE + ' realm=oidc'
        logging.info(str(http_response))
        return http_response


@app.route('/userinfo', methods=['POST'])
def userinfo_endpoint():
    data = request.get_data().decode('utf-8')
    headers = request.headers
    return _userinfo_endpoint(data, headers)

@app.route('/userinfo', methods=['GET'])
def userinfo_endpoint_get():
    data = request.args
    headers = request.headers
    return _userinfo_endpoint(data, headers)



''' -------------------------------- '''

@app.errorhandler(LoginError)
def reset_retorar_error(error):
    return jsonify(error), error.status_code

@app.route('/', methods=['GET'], defaults={'path':None})
@app.route('/<path:path>', methods=['GET'])
def send(path):

    """
        para agregar el chequeo de que tienen que pedir si o si el endpoint de autorizacion primero.
        lo agreguo cuando este en producción, asi walter puede estilar las pantallas

    authn_req = flask.session.get('authn_req', None)
    if not authn_req:
        ''' aca debería redireccionar al sitio por defecto, pero por ahora tiro un error de seguridad '''
        raise SeguridadError()
    """

    if not path:
        return redirect('/index.html'), 303
    return send_from_directory(app.static_url_path, path)


''' ------------------------------------------------------------------ '''

@app.route('/authorization', methods=['OPTIONS'])
@app.route('/login', methods=['OPTIONS'])
@app.route('/finalize_auth', methods=['OPTIONS'])
@app.route('/token', methods=['OPTIONS'])
@app.route('/userinfo', methods=['OPTIONS'])
def options(*args, **kargs):
    '''
        para autorizar el CORS
        https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS
    '''
    o = request.headers.get('Origin')
    rm = request.headers.get('Access-Control-Request-Method')
    rh = request.headers.get('Access-Control-Request-Headers')

    r = make_response()
    r.headers['Access-Control-Allow-Methods'] = 'PUT,POST,GET,HEAD,DELETE'
    r.headers['Access-Control-Allow-Origin'] = '*'
    r.headers['Access-Control-Allow-Headers'] = rh
    r.headers['Access-Control-Max-Age'] = 1
    return r


@app.after_request
def add_header(r):
    """
    Add headers to both force latest IE rendering engine or Chrome Frame,
    and also to cache the rendered page for 10 minutes.
    """
    r.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    r.headers["Pragma"] = "no-cache"
    r.headers["Expires"] = "0"
    r.headers['Cache-Control'] = 'public, max-age=0'
    return r

def main():
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == "__main__":
    main()
