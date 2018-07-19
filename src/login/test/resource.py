import logging
logging.basicConfig(level=logging.DEBUG)

import os
import redis
import flask
from flask import Flask, request, send_from_directory, jsonify, redirect, url_for, make_response
from flask_jsontools import jsonapi

import requests

from oidc import OIDC, ResourceServer

VERIFY_SSL = bool(os.environ.get('VERIFY_SSL', True))

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/users/web')
app.debug = True
app.config['SECRET_KEY'] = 'algo-secreto'
app.config['SESSION_COOKIE_NAME'] = 'users_session'

rs = ResourceServer(client_id='consumer-test', client_secret='consumer-secret', realm='resource server test', verify=VERIFY_SSL)

import json

@app.route('/api/r1', methods=['GET'])
@rs.require_valid_token
@jsonapi
def r1(token=None):
    logging.debug('recibi este token')
    logging.debug(json.dumps(token))
    return {'recurso':'aca taaaaa'}


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
    app.run(host='0.0.0.0', port=5001, debug=True)

if __name__ == "__main__":
    main()
