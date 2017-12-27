import logging
logging.basicConfig(level=logging.DEBUG)

import os
import redis
import flask
from flask import Flask, request, send_from_directory, jsonify, redirect, url_for, make_response
from flask_jsontools import jsonapi
import flask_session

import uuid
import json
import requests

from oidc import OIDC, ResourceServer

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/users/web')
app.debug = True
app.config['SECRET_KEY'] = 'algo-secreto'
app.config['SESSION_COOKIE_NAME'] = 'users_session'

REDIS_HOST = os.environ['REDIS_HOST']
r = redis.StrictRedis(host=REDIS_HOST, port=6379, db=0)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = r
flask_session.Session(app)

oidc = OIDC(client_id='consumer-test', client_secret='consumer-secret', redirect_uri='http://consumer-test.localhost:81/oauth2')

@app.route('/oauth2', methods=['GET'])
def callback():
    error = request.args.get('error', None, str)
    if error:
        desc = request.args.get('error_description', '', str)
        return make_response(error + '<br>' + desc, 401)

    token = oidc.callback(request.args)
    if not token:
        return make_response('error', 401)

    flask.session['token'] = token

    return make_response(json.dumps(token), 200)

@app.route('/', methods=['GET'])
def send():
    r = oidc.auth_code(state=str(uuid.uuid4()), nonce=str(uuid.uuid4()), scopes=['openid', 'profile', 'email', 'address', 'phone', 'offline','hydra.clients'])
    return redirect(r,302)


@app.route('/r', methods=['GET'])
def get_resource():
    r = None
    token = request.args.get('token',None,str)
    if not token:
        token = flask.session.get('token',None)

    if token:
        logging.debug(token)
        headers = {
            'Authorization': 'Bearer {}'.format(token)
        }
        r = requests.get('http://127.0.0.1:5001/api/r1', headers=headers)
    else:
        r = requests.get('http://127.0.0.1:5001/api/r1')
    return (r.text, r.status_code, r.headers.items())


@app.route('/userinfo', methods=['GET'])
@jsonapi
def get_userinfo():
    r = None
    token = request.args.get('token',None,str)
    if not token:
        token = flask.session.get('token',None)

    userinfo = oidc.userinfo(token)
    if not userinfo:
        return {}
    return userinfo



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
