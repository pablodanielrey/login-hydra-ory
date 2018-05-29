#
# https://www.ory.am/run-oauth2-server-open-source-api-security
# https://ory.gitbooks.io/hydra/content/images/consent-flow.svg
# https://ory.gitbooks.io/hydra/content/oauth2.html#consent-flow

import os
import logging
logging.getLogger().setLevel(logging.DEBUG)
logging.getLogger().propagate = True
#logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
#logging.basicConfig(level=logging.DEBUG)

import datetime

import flask
from flask import Flask, request, send_from_directory, jsonify, redirect, session, url_for, make_response, render_template
from flask_jsontools import jsonapi
import flask_session
import redis
import json

import oauthlib
import requests
from requests.auth import HTTPBasicAuth

from login.model import LoginModel

VERIFY_SSL=True

#import urllib.parse

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/login/web')
app.debug = False
import sys
log = logging.getLogger()
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

HYDRA_HOST = os.environ['OIDC_HOST']
HYDRA_CLIENT_ID = os.environ['OIDC_CLIENT_ID']
HYDRA_CLIENT_SECRET = os.environ['OIDC_CLIENT_SECRET']

"""
    configuro la sesion de flask
"""
import hashlib
app.config['SECRET_KEY'] = hashlib.sha1(HYDRA_CLIENT_SECRET.encode('utf-8')).hexdigest()

app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=365)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_PATH'] = '/'
#app.config['SESSION_COOKIE_DOMAIN'] = app.config.get('SERVER_NAME')
app.config['SESSION_COOKIE_NAME'] = 'consent_oidc_session'

""" extensiones de Flask_session """
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'consent_'

use_redis = os.environ.get('FLASK_SESSION_REDIS',False)
if use_redis and use_redis not in ("False","false","0"):
    logging.debug('configurando para usar redis como backend de sesiones')
    REDIS_HOST = os.environ['REDIS_HOST']
    r = redis.StrictRedis(host=REDIS_HOST, port=6379, db=0)
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = r
else:
    logging.debug('configurando el filesystem como backend de sesiones')
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = '/tmp/flask_sessions'
    app.config['SESSION_FILE_THRESHOLD'] = 500
    app.config['SESSION_FILE_MODE'] = 777


flask_session.Session(app)


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
    TOKEN_S_ID = 'consent_token'
    token = flask.session.get(TOKEN_S_ID, None)
    if token and not _token_expired(token):
        return token['access_token']
        
    client_id = HYDRA_CLIENT_ID
    client_secret = HYDRA_CLIENT_SECRET
    auth = HTTPBasicAuth(client_id, client_secret)
    data = {
        'grant_type':'client_credentials',
        'scope':'hydra.consent'
    }
    headers = {
        'Accept':'application/json'
    }
    url = HYDRA_HOST + '/oauth2/token'
    r = requests.post(url, verify=VERIFY_SSL, auth=auth, headers=headers, data=data)
    if not r.ok:
        raise Exception('no se pudo obtener un token para acceso a hydra')
    
    token = r.json()
    _token_set_expired(token)
    flask.session[TOKEN_S_ID] = token
    return token['access_token']



def obtener_consent(token, consent_id):
    url = HYDRA_HOST + '/oauth2/consent/requests/' + consent_id
    headers = {
        'Authorization': 'bearer {}'.format(token),
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    r = requests.get(url, verify=VERIFY_SSL, headers=headers, allow_redirects=False)
    if not r.ok:
        return None
    return r.json()


def aceptar_consent(token, consent, usuario):
    '''
        acepta el consent brindando la info pasada por usuario
        de acuerdo a la especificación de openid connect

        profile
            OPTIONAL. This scope value requests access to the End-User's default profile Claims, which are:
                name, family_name, given_name, middle_name, nickname, preferred_username, profile, picture, website, gender, birthdate, zoneinfo, locale, and updated_at.
        email
            OPTIONAL. This scope value requests access to the email and email_verified Claims.
        address
            OPTIONAL. This scope value requests access to the address Claim.
        phone
            OPTIONAL. This scope value requests access to the phone_number and phone_number_verified Claims.

        info de ejemplo que se puede exportar:
        data['idTokenExtra'] = {
            'preferred_username': 'usuario@algo',
            'name': usuario['name'],
            'given_name': usuario['name'],
            'family_name': usuario['name'],
            'nickname': usuario['name'],
            'picture': 'http://gravatar.com/imagen.jpg',
            'gender': 'male',
            'address': {
                'formatted': 'calle 3 número 1232 depto 5, La Plata, Buenos Aires, Argentina',
                'street_address': 'calle 3 número 1232 depto 5',
                'locality': 'La Plata',
                'region': 'Buenos Aires',
                'postal_code': '1900',
                'country': 'Argentina'
            },
            'birthdate': '1979-02-12',
            'locale': 'es-AR',
            'phone_number': '+1 (604) 555-1234;ext=5678',
            'phone_number_verified': False,
            'email':'algo@econo.unlp',
            'email_verified':True,
            'updated_at': 0
        }
    '''


    url = HYDRA_HOST + '/oauth2/consent/requests/' + consent['id'] + '/accept'
    headers = {
        'Authorization': 'bearer {}'.format(token),
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    data = {
        'subject': usuario['id'],
        'grantScopes': consent['requestedScopes'],
        #'accessTokenExtra':  {}
        'authTime': 0,
        #'providedAcr': 'algo',
        'idTokenExtra': {}
    }

    if 'profile' in consent['requestedScopes']:
        data['idTokenExtra']['name'] = usuario['nombre'] + ' ' + usuario['apellido']
        data['idTokenExtra']['family_name'] = usuario['apellido']
        data['idTokenExtra']['given_name'] = usuario['nombre']
        data['idTokenExtra']['username'] = usuario['dni']
        data['idTokenExtra']['preferred_username'] = usuario['dni']
        data['idTokenExtra']['zoneinfo'] = 'America/Argentina/Buenos_Aires'
        data['idTokenExtra']['locale'] = 'es-AR'

    if 'email' in consent['requestedScopes']:
        for m in usuario['mails']:
            data['idTokenExtra']['email'] = m['email']
            data['idTokenExtra']['email_verified'] = m['confirmado'] != ''
            if 'econo.unlp.edu.ar' in m['email']:
                break

    logging.debug('INFORMACION A RETORNAR:')
    logging.debug(data)

    r = requests.patch(url, verify=VERIFY_SSL, allow_redirects=False, headers=headers, json=data)
    return r


def denegar_consent(token, consent):
    url = HYDRA_HOST + '/oauth2/consent/requests/' + consent['id'] + '/reject'
    headers = {
        'Authorization': 'bearer {}'.format(token),
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    data = {
        'subject': 'sdfdsfsdfsdlkfs',
        'grantScopes': consent['requestedScopes'],
        #'accessTokenExtra':  {}
        'authTime': 0
        #'idTokenExtra': { 'prop1': 'algo' },
        #'providedAcr': 'algo',
    }
    r = requests.patch(url, verify=VERIFY_SSL, allow_redirects=False, headers=headers, json=data)
    return r


@app.route('/img/<path:path>', methods=['GET'])
def get_style(path):
    return send_from_directory(directory='img', filename=path)


@app.route('/', methods=['GET'])
@app.route('/login', methods=['GET'])
def login():
    """
    ''' para los casos cuando hydra reporta un error '''
    error = request.args.get('error', None, str)
    if error:
        descripcion = request.args.get('error_description', '', str)
        return render_template('error.html', error=error, descripcion=descripcion)
    """

    consent_id = request.args.get('consent', None, str)
    if not consent_id:
        return render_template('error.html', error='No permitido', descripcion='Ingrese al sistema adecuado')
    flask.session['consent_id'] = consent_id

    usuario_id = flask.session.get('usuario',None)
    if usuario_id:
        return redirect(url_for('authorize'), 303)
    return render_template('login.html')

@app.route('/', methods=['POST'])
@app.route('/login', methods=['POST'])
def do_login():
    consent_id = flask.session['consent_id']
    if not consent_id:
        return 'Bad Request', 400

    usuario = request.form.get('usuario', None)
    clave = request.form.get('clave', None)
    if not usuario or not clave:
        return 'Bad Request', 400

    usuario_data = LoginModel.login(usuario, clave)
    flask.session['usuario'] = usuario_data

    return redirect(url_for('authorize'), 303)

@app.route('/authorize', methods=['GET'])
def authorize():
    '''
        autoriza automáticamente un pedido de consent.
        arma la info retornada de usuarios en base a los scopes requeridos
        TODO: debo analizar el consent y verificarlo o rechazarlo.
        ej:
        {
            "id": "8dc077f1-4bd2-4f51-94f7-483e2a51aac8",
            "requestedScopes": ["openid", "offline", "hydra.clients"],
            "clientId": "consumer-test",
            "expiresAt": "2017-12-24T02:29:24.485681Z",
            "redirectUrl": "https://192.168.0.3:9000/oauth2/auth?client_id=consumer-test&response_type=code&redirect_uri=http%3A%2F%2F127.0.0.1%3A81%2Foauth2&scope=openid+offline+hydra.clients&state=algodealgo&consent=8dc077f1-4bd2-4f51-94f7-483e2a51aac8"
        }
    '''
    usuario = flask.session['usuario']
    if not usuario:
        return 'Bad Request', 400

    consent_id = flask.session['consent_id']
    if not consent_id:
        return 'Bad Request', 400
    
    tk = obtener_token()
    consent = obtener_consent(tk, consent_id)
    if not consent:
        return redirect(url_for('login'), 303)

    """ 
        debería chequear los scopes, etc 
        pero por ahora lo autorizo implícitamente
    """

    tk = obtener_token()
    r = aceptar_consent(tk, consent, usuario=usuario)

    if 'consent_id' in flask.session:
        del flask.session['consent_id']

    if not r or not r.ok:
        return (r.text, r.status_code, r.headers.items())
    return redirect(consent['redirectUrl'])


@app.route('/logout')
def logout():
    if 'usuario' in flask.session:
        del flask.session['usuario']

    if 'consent_id' in flask.session:
        del flask.session['consent_id']

    redirect_uri = request.args.get('post_logout_redirect_uri')
    if redirect_uri:
        return redirect(redirect_uri)
    return render_template('logout.html')


@app.route('/user', methods=['GET'])
@jsonapi
def info():
    data = {
        'usuario_id': flask.session.get('usuario_id', ''),
        'autorizado': flask.session.get('autorizado', '')
    }
    return (data, 200)


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

    '''
        para autorizar el CORS
        https://developer.mozilla.org/en-US/docs/Web/HTTP/Access_control_CORS
    '''
    o = request.headers.get('Origin', None)
    rm = request.headers.get('Access-Control-Request-Method', None)
    rh = request.headers.get('Access-Control-Request-Headers', None)

    r.headers['Access-Control-Allow-Methods'] = 'PUT,POST,GET,HEAD,DELETE'
    r.headers['Access-Control-Allow-Origin'] = '*'
    if rh:
        r.headers['Access-Control-Allow-Headers'] = rh
    r.headers['Access-Control-Max-Age'] = 1

    return r

def main():
    app.run(host='0.0.0.0', port=8003, debug=True)

if __name__ == "__main__":
    main()
