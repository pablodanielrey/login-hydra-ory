import logging
logging.basicConfig(level=logging.DEBUG)

import os
import redis
import flask
from flask import Flask, request, send_from_directory, jsonify, redirect, url_for, make_response
from flask_jsontools import jsonapi

from oidc import OIDC

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/users/web')
app.debug = True
app.config['SECRET_KEY'] = 'algo-secreto'
app.config['SESSION_COOKIE_NAME'] = 'users_session'

@app.route('/oauth2', methods=['GET'])
def callback():
    error = request.args.get('error', None, str)
    if error:
        desc = request.args.get('error_description', '', str)
        return make_response(error + '<br>' + desc,500)
    return make_response('ok', 200)

@app.route('/', methods=['GET'], defaults={'path':None})
@app.route('/<path:path>', methods=['GET'])
def send(path):
    logging.debug(url_for('callback'))

    oidc = OIDC()
    r = oidc.auth_token('consumer-test', 'http://127.0.0.1:81' + url_for('callback'), ['openid','offline','hydra.clients'])
    resp = make_response(r.text, r.status_code)
    for h in r.headers:
        logging.debug(h)
        logging.debug(r.headers[h])
        resp.headers[h] = r.headers[h]
    logging.debug(resp)
    return resp

    #if not path:
    #    return redirect('/perfil/index.html'), 303
    #return send_from_directory(app.static_url_path, path)

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
