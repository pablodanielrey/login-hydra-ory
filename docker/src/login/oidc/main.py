import logging
logging.getLogger().setLevel(logging.DEBUG)
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
logging.basicConfig(level=logging.DEBUG)

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
from pyop.exceptions import OAuthError
from oic.oic.message import AuthorizationRequest
from oic.oic.message import TokenErrorResponse



# uso should_fragment_encode pero parcheada de mi codigo
#from pyop.util import should_fragment_encode
#
from .OIDC import should_fragment_encode
from .OIDC import provider


# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/login/oidc')
app.debug = True
register_encoder(app)
#flask_session.Session(app)
app.config['SECRET_KEY'] = 'algo'


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
            return make_response("Something went wrong: {}".format(str(e)), 400)

    flask.session['authn_req'] = authn_req.to_dict()
    return redirect(url_for('send'), 303)


@app.route('/login', methods=['POST'])
def login():
    usuario = request.form.get('u', None)
    password = request.form.get('p', None)

    if not usuario or not password:
        raise ClaveError()

    s = Session()
    try:
        rusuario = LoginModel.login(session=s, usuario=usuario, clave=password)
        if rusuario:
            flask.session['usuario_id'] = rusuario.usuario_id
            return redirect(url_for('redirection_auth_endpoint'))
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
        logging.debug(request.get_data().decode('utf-8'))
        logging.debug(request.headers)
        token_response = provider.handle_token_request(request.get_data().decode('utf-8'), flask.request.headers)
        return token_response.to_json()
    except InvalidClientAuthentication as e:
        logging.exception(e)
        error_resp = TokenErrorResponse(error='invalid_client', error_description=str(e))
        http_response = make_response(error_resp.to_json())
        http_response.status_code = 401
        http_response.headers['WWW-Authenticate'] = 'Basic realm=login'
        return http_response
    except OAuthError as e:
        error_resp = TokenErrorResponse(error=e.oauth_error, error_description=str(e))
        return error_resp.to_json(), 400






''' -------------------------------- '''

@app.errorhandler(LoginError)
def reset_retorar_error(error):
    return jsonify(error), error.status_code

@app.route('/', methods=['GET'], defaults={'path':None})
@app.route('/<path:path>', methods=['GET'])
def send(path):
    if not path:
        return redirect('/login.html'), 303
    return send_from_directory(app.static_url_path, path)


@app.route('/consent', methods=['GET'])
def hydra_consent():
    error = request.args.get('error', None)
    error_description = request.args.get('error_description', None)

    if error or error_description:
        r = jsonify({'error':error, 'error_description':error_description})
        return r, 500

    challenge = request.args.get('challenge', None, str)
    if not challenge:
        raise SeguridadError()

    app.open_session(request)
    usuario = flask.session.get('usuario',None)
    if usuario:
        redireccion = LoginModel.verificar_challenge(challenge)
        return redirect(redireccion,303)
    else:
        redireccion = '/index.html#!login/' + challenge
        return redirect(redireccion, 303)


''' ------------ métodos para implementar la pantalla de login ----- '''

@app.route('/verificar', methods=['POST'])
@jsonapi
def verificar():
    dni = request.form.get('u', None)
    if not dni:
        raise UsuarioNoEncontradoError()

    session = Session()
    try:
        return LoginModel.obtener_usuario(session=session, dni=dni)
    finally:
        session.close()



''' ------------------------------------------------------------------ '''


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
