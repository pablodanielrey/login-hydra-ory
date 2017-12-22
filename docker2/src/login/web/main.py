#
#
# https://ory.gitbooks.io/hydra/content/images/consent-flow.svg
# https://ory.gitbooks.io/hydra/content/oauth2.html#consent-flow

import os
import logging
logging.getLogger().setLevel(logging.DEBUG)
#logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)
#logging.basicConfig(level=logging.DEBUG)

import flask
from flask import Flask, request, send_from_directory, jsonify, redirect, session, url_for, make_response
from flask_jsontools import jsonapi
import flask_session
import redis

#import urllib.parse

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/login/web')
app.debug = True
#app.config['SECRET_KEY'] = 'algo-secreto2'
#app.config['SESSION_COOKIE_NAME'] = 'oidc_session'

REDIS_HOST = os.environ['REDIS_HOST']
r = redis.StrictRedis(host=REDIS_HOST, port=6379, db=0)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = r
flask_session.Session(app)

@app.route('/login')
def login():
    consent = request.args.get('consent', None, str)
    

    #flask.session['consent'] =

    #if 'usuario_id' in flask.session and flask.session['usuario_id'] is not None:
    #    ''' usuario ya logueado redirecciono directamente a los permisos '''
    #    return redirect(url_for('redirection_auth_endpoint'), 303)
    #else:
    return redirect(url_for('send'), 303)

@app.route('/logout')
def end_session_endpoint():
    if 'usuario_id' in flask.session:
        del flask.session['usuario_id']
    return HTTPResponse('Logout successful!', content_type='text/html', status=200)

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
