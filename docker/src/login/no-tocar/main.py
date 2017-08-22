import logging
logging.getLogger().setLevel(logging.DEBUG)
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

import flask
from flask import Flask, request, send_from_directory, jsonify, redirect, session, url_for
from flask_jsontools import jsonapi
import flask_session

from login.model import Session, LoginModel
from login.model.exceptions import *

from rest_utils import register_encoder

# set the project root directory as the static folder, you can set others.
app = Flask(__name__, static_url_path='/src/login/web')
app.debug = True
register_encoder(app)
#flask_session.Session(app)
app.config['SECRET_KEY'] = 'algo'

@app.errorhandler(LoginError)
def reset_retorar_error(error):
    return jsonify(error), error.status_code

@app.route('/', methods=['GET'], defaults={'path':None})
@app.route('/<path:path>', methods=['GET'])
def send(path):
    if not path:
        return redirect('/index.html'), 303
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

@app.route('/login', methods=['POST'])
@jsonapi
def login():
    usuario = request.form.get('u', None)
    password = request.form.get('p', None)

    if not usuario or not password:
        raise ClaveError()

    s = Session()
    try:
        rusuario = LoginModel.login(session=s, usuario=usuario, clave=password)
        if rusuario:
            flask.session['usuario'] = rusuario.usuario_id
            return {'usuario_id': rusuario.usuario_id}
        else:
            raise ClaveError()
    finally:
        s.close()

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
