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


#import urllib.parse

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/login/web')
app.debug = True
#app.config['SECRET_KEY'] = 'algo-secreto2'
#app.config['SESSION_COOKIE_NAME'] = 'oidc_session'
import sys
log = logging.getLogger()
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)

HYDRA_HOST = os.environ['OIDC_HOST']
HYDRA_CLIENT_ID = os.environ['OIDC_CLIENT_ID']
HYDRA_CLIENT_SECRET = os.environ['OIDC_CLIENT_SECRET']

def obtener_token():
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
    r = requests.post(url, verify=False, auth=auth, headers=headers, data=data)
    return r.json()['access_token']


def verificar_consent(token, consent_id):
    url = HYDRA_HOST + '/oauth2/consent/requests/' + consent_id
    headers = {
        'Authorization': 'bearer {}'.format(token),
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    r = requests.get(url, verify=False, headers=headers, allow_redirects=False)
    return r


def aceptar_consent(token, consent, usuario={'id':'sdfdsfs', 'name':'', 'email':'','email_verified':''}):
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
        'authTime': 0
        #'providedAcr': 'algo',
    }

    ''' deberia chequear que scopes requirio y agregar los datos '''
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

    r = requests.patch(url, verify=False, allow_redirects=False, headers=headers, json=data)
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
    r = requests.patch(url, verify=False, allow_redirects=False, headers=headers, json=data)
    return r


"""
def obtener_token():
    #https://requests-oauthlib.readthedocs.io/en/latest/oauth2_workflow.html#backend-application-flow
    from oauthlib.oauth2 import BackendApplicationClient
    from requests_oauthlib import OAuth2Session
    from requests.auth import HTTPBasicAuth

    client_id = HYDRA_CLIENT_ID
    client_secret = HYDRA_CLIENT_SECRET
    scopes = ['hydra.consent']

    auth = HTTPBasicAuth(client_id, client_secret)
    client = BackendApplicationClient(client_id=client_id)
    oauth = OAuth2Session(client=client, scope=scopes)
    token = oauth.fetch_token(token_url=HYDRA_HOST + '/oauth2/token', auth=auth, verify=False)
    return oauth, token
"""

REDIS_HOST = os.environ['REDIS_HOST']
r = redis.StrictRedis(host=REDIS_HOST, port=6379, db=0)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = r
flask_session.Session(app)


def obtener_consent_id():
    consent = request.args.get('consent', None, str)
    if not consent:
        consent = flask.session.get('consent', None)
    return consent

def obtener_consent():
    id = obtener_consent_id()
    if not id:
        return None

    consent = flask.session.get('consent_{}'.format(id), None)
    if consent:
        return consent

    tk = obtener_token()
    r = verificar_consent(tk, id)
    if not r.ok:
        return None

    consent = r.json()
    flask.session['consent_{}'.format(id)] = consent
    return consent


@app.route('/staic/<path:path>', methods=['GET'])
def get_style(path):
    return send_from_directory(directory='static', filename=path)


@app.route('/login', methods=['GET'])
def login():
    ''' para los casos cuando hydra reporta un error '''
    error = request.args.get('error', None, str)
    if error:
        descripcion = request.args.get('error_description', '', str)
        return render_template('error.html', error=error, descripcion=descripcion)

    consent_id = obtener_consent_id()
    if not consent_id:
        return render_template('login.html')
    flask.session['consent'] = consent_id

    usuario_id = flask.session.get('usuario_id',None)
    if usuario_id:
        return redirect(url_for('authorize'), 303)
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def do_login():
    usuario = request.form.get('usuario', None)
    clave = request.form.get('clave', None)

    usuario_data = LoginModel.login(usuario, clave)
    #aca se debe chequear los datos de login y sino tirar error.
    #return render_template('login_ok.html', usuario=usuario)
    flask.session['usuario_id'] = usuario_data
    return redirect(url_for('authorize'), 303)


@app.route('/authorize', methods=['GET'])
def authorize():
    consent = obtener_consent()
    if not consent:
        return make_response('No autorizado', 401)

    '''
        debo analizar el conset y verificarlo o rechazarlo.
        ej:
        {
            "id": "8dc077f1-4bd2-4f51-94f7-483e2a51aac8",
            "requestedScopes": ["openid", "offline", "hydra.clients"],
            "clientId": "consumer-test",
            "expiresAt": "2017-12-24T02:29:24.485681Z",
            "redirectUrl": "https://192.168.0.3:9000/oauth2/auth?client_id=consumer-test&response_type=code&redirect_uri=http%3A%2F%2F127.0.0.1%3A81%2Foauth2&scope=openid+offline+hydra.clients&state=algodealgo&consent=8dc077f1-4bd2-4f51-94f7-483e2a51aac8"
        }
    '''
    if flask.session.get('autorizado', False):
        tk = obtener_token()
        r = aceptar_consent(tk, consent)
        return redirect(consent['redirectUrl'])
    else:
        return render_template('authorize.html', scopes=consent['requestedScopes'])


@app.route('/authorize', methods=['POST'])
def do_authorize():
    consent = obtener_consent()
    if not consent:
        return make_response('No autorizado', 401)

    tk = obtener_token()
    r = None
    autorizado = request.form.get('auth', 'false', str)
    if 'false' in autorizado:
        r = denegar_consent(tk, consent)
    else:
        r = aceptar_consent(tk, consent)
        flask.session['autorizado'] = True

    if not r or not r.ok:
        return (r.text, r.status_code, r.headers.items())
    return redirect(consent['redirectUrl'])


@app.route('/logout')
def logout():
    if 'usuario_id' in flask.session:
        del flask.session['usuario_id']
    if 'autorizado' in flask.session:
        del flask.session['autorizado']
    return make_response('Logout successful!', 200, {'content_type':'text/html'})


@app.route('/', methods=['GET'])
@jsonapi
def info():
    data = {
        'usuario_id': flask.session.get('usuario_id', ''),
        'autorizado': flask.session.get('autorizado', '')
    }
    return (data, 200)

"""
@app.route('/', methods=['GET'], defaults={'path':None})
@app.route('/<path:path>', methods=['GET'])
def send(path):
    consent = flask.session.get('consent', None)
    if not consent:
        return HTTPResponse('unauthorized', content_type='text/html', status=401)

    return redirect('/index.html'), 303

    return send_from_directory(app.static_url_path, path)
"""

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
    app.run(host='0.0.0.0', port=5000, debug=True)

if __name__ == "__main__":
    main()
