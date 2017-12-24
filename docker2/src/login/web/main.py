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

import oauthlib
import requests
from requests.auth import HTTPBasicAuth

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

HYDRA_HOST = os.environ['HYDRA_HOST']
HYDRA_CLIENT_ID = os.environ['HYDRA_CLIENT_ID']
HYDRA_CLIENT_SECRET = os.environ['HYDRA_CLIENT_SECRET']

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
    r = requests.post(url, auth=auth, verify=False, headers=headers, data=data)
    return r.json()

def verificar_consent(token, consent_id):
    url = HYDRA_HOST + '/oauth2/consent/requests/' + consent_id
    headers = {
        'Authorization': 'bearer {}'.format(token),
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    }
    r = requests.get(url, verify=False, headers=headers)
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


def obtener_consent():
    consent = flask.session.get('consent', None)
    if not consent:
        consent = request.args.get('consent', None, str)
    return consent

def hydra_obtener_consent(id):
    import json
    token = obtener_token()
    tk = token['access_token']
    r = verificar_consent(tk, id)
    if r.status_code == 200:
        return r.json()
    return None

@app.route('/login', methods=['GET'])
def login():
    ''' para los casos cuando hydra reporta un error '''
    error = request.args.get('error', None, str)
    if error:
        descripcion = request.args.get('error_description', '', str)
        return render_template('error.html', error=error, descripcion=descripcion)

    consent_id = obtener_consent()
    if not consent_id:
        return make_response('unauthorized', 401)
    flask.session['consent'] = consent_id
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def do_login():
    usuario = request.form.get('usuario', None)
    clave = request.form.get('clave', None)
    #aca se debe chequear los datos de login y sino tirar error.
    #return render_template('login_ok.html', usuario=usuario)
    return redirect(url_for('authorize'), 303)

@app.route('/authorize', methods=['GET'])
def authorize():
    consent_id = obtener_consent()
    if not consent_id:
        return make_response('unauthorized', 401)

    consent = hydra_obtener_consent(consent_id)
    if not consent:
        return make_response('No autorizado', 401)

    return make_response(consent, 200)
    #getOAuth2ConsentRequest
    #return render_template('authorize.html')

@app.route('/authorize', methods=['POST'])
def do_authorize():
    consent_id = obtener_consent()
    if not consent_id:
        return make_response('unauthorized', 401)
    return render_template('authorize.html')


@app.route('/logout')
def logout():
    if 'usuario_id' in flask.session:
        del flask.session['usuario_id']
    return make_response('Logout successful!', 200, {'content_type':'text/html'})

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
