import logging
logging.basicConfig(level=logging.DEBUG)

import os
import redis
import flask
from flask import Flask, request, send_from_directory, jsonify, redirect, url_for, make_response
from flask_jsontools import jsonapi
import flask_session

import requests

from oidc import OIDC, ResourceServer

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/users/web')
app.debug = True
app.config['SECRET_KEY'] = 'algo-secreto'
app.config['SESSION_COOKIE_NAME'] = 'users_session'

rs = ResourceServer('consumer-test','consumer-secret', 'resource server test')

@app.route('/api/r1', methods=['GET'])
@jsonapi
def r1():
    token = rs.bearer_token(request.headers)
    if not token:
        return rs.invalid_token()
    tk = rs.introspect_token(token)
    logging.debug(tk)
    if not tk or not tk['active']:
        return rs.invalid_request()
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
