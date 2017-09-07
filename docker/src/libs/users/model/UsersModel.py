import os
import uuid
import datetime
import base64
import requests

from sqlalchemy import or_
from sqlalchemy.orm import joinedload

from . import Session, obtener_template, enviar_correo
from .exceptions import *
from .entities import *


class UsersModel:

    FILES_API_URL = os.environ['FILES_API_URL']

    @staticmethod
    def _aplicar_filtros_comunes(q, offset, limit):
        q = q.offset(offset) if offset else q
        q = q.limit(limit) if limit else q
        return q


    @classmethod
    def obtener_avatar(cls, hash):
        url = cls.FILES_API_URL + '/archivo/' + hash + '/contenido'
        resp = requests.get(url)
        if resp.status_code != 200:
            ''' pruebo obtener una imagen por defecto '''
            resp = requests.get('http://icons.iconarchive.com/icons/arrioch/whack/128/Whack-Google-Earth-icon.png')
            if resp.status_code != 200:
                raise UsersError()

        avatar = {
            'name': 'default',
            'data': base64.b64encode(resp.content).decode('utf-8'),
            'content-type': resp.headers['Content-Type']
        }
        return avatar

    @classmethod
    def actualizar_avatar(cls, hash, contenido):
        url = cls.FILES_API_URL + '/archivo/' + hash + '.json'
        resp = requests.post(url=url, json={'id':hash, 'data':contenido})
        if resp.status_code != 200:
            raise UsersError()


    @classmethod
    def claves(cls, session, uid=None, cid=None, limit=None, offset=None):
        q = session.query(UsuarioClave)
        q = q.filter(UsuarioClave.id == cid) if cid else q
        q = q.filter(UsuarioClave.usuario_id == uid) if uid else q
        cls._aplicar_filtros_comunes(q, offset, limit)
        q.order_by(UsuarioClave.actualizado.desc(), UsuarioClave.creado.desc())
        return q.all()

    @classmethod
    def cambiar_clave(cls, session, uid, clave):
        '''
            IMPORANTE!!!!:
            como ahora no todos los sistemas soportan varias claves en el registro de claves. se elimina la clave anterior.
            por lo que no queda historial ni eliminación lógica de la clave!!!!
            cuando todos los sistemas estén usando el nuevo esquema se cambia este método para registrar el historial de claves.
        '''
        assert uid is not None

        if not clave or len(clave) < 8:
            raise FormatoDeClaveIncorrectoError()

        """
        dni = session.query(Usuario.dni).filter(Usuario.id == uid).one()
        uclave = session.query(UsuarioClave).filter(UsuarioClave.usuario_id == uid, UsuarioClave.eliminada == None).one_or_none()
        if uclave:
            uclave.eliminada = datetime.datetime.now()

        uuclave = UsuarioClave(usuario_id=uid, nombre_de_usuario=dni, clave=clave)
        session.add(uuclave)
        """
        uclave = session.query(UsuarioClave).filter(UsuarioClave.usuario_id == uid).one_or_none()
        if uclave:
            uclave.clave = clave
        else:
            uuclave = UsuarioClave(usuario_id=uid, nombre_de_usuario=dni, clave=clave)
            session.add(uuclave)

    @classmethod
    def actualizar_usuario(cls, session, uid, datos):
        import re
        g = re.match('((\w)*\s*)*', datos['nombre'])
        if not g:
            raise FormatoIncorrecto()
        nombre = g.group()

        g2 = re.match('((\w)*\s*)*', datos['apellido'])
        if not g:
            raise FormatoIncorrecto()
        apellido = g2.group()

        usuario = session.query(Usuario).filter(Usuario.id == uid).one()
        usuario.nombre = nombre
        usuario.apellido = apellido


    @classmethod
    def usuarios(cls, session, usuario=None, dni=None, retornarClave=False, fecha_actualizado=None, offset=None, limit=None, fecha=None):
        q = session.query(Usuario)
        q = q.filter(Usuario.id == usuario) if usuario else q
        q = q.filter(Usuario.dni == dni) if dni else q
        q = q.filter(or_(Usuario.actualizado >= fecha, Usuario.creado >= fecha)) if fecha else q
        q = q.options(joinedload('claves')) if retornarClave else q
        q = q.options(joinedload('mails'), joinedload('telefonos'))
        q = cls._aplicar_filtros_comunes(q, offset, limit)
        return q.all()

    @classmethod
    def existe(cls, session, usuario):
        if session.query(Usuario).filter(Usuario.id == usuario).count() > 0:
            return True
        return False

    @classmethod
    def correos(cls, session, cid=None, usuario=None, historico=False, offset=None, limit=None):
        q = session.query(Mail)
        q = q.filter(Mail.id == cid) if cid else q
        q = q.filter(Mail.usuario_id == usuario) if usuario else q
        q = q.filter(Mail.eliminado == None) if not historico else q
        q = cls._aplicar_filtros_comunes(q, offset, limit)
        return q.all()

    @classmethod
    def agregar_correo(cls, session, uid, datos):
        assert 'email' in datos
        assert len(datos['email'].strip()) > 0
        if (session.query(Mail).filter(Mail.usuario_id == uid, Mail.email == datos['email'], Mail.eliminado == None).count() >= 1):
            ''' ya existe, no lo agrego pero no tiro error '''
            return
        usuario = session.query(Usuario).filter(Usuario.id == uid).one()
        mail = Mail(email=datos['email'].lower())
        usuario.mails.append(mail)

    @classmethod
    def eliminar_correo(cls, session, cid):
        correo = session.query(Mail).filter(Mail.id == cid).one()
        correo.eliminado = datetime.datetime.now()

    @classmethod
    def confirmar_correo(cls, session, cid, code):
        correo = session.query(Mail).filter(Mail.id == cid, Mail.hash == code, Mail.eliminado == None).order_by(Mail.creado.desc()).first()
        if not correo:
            raise CorreoNoEncontradoError()
        correo.confirmado = True
        correo.fecha_confirmado = datetime.datetime.now()

    @classmethod
    def enviar_confirmar_correo(cls, session, cid, datos):
        correo = session.query(Mail).filter(Mail.id == cid).one()
        if not correo.hash:
            correo.hash=str(uuid.uuid4())[:5]

        mail = correo.email.lower().strip()
        codigo = correo.hash
        nombre = correo.usuario.nombre + ' ' + correo.usuario.apellido
        cuerpo = obtener_template('confirmar_correo.html', nombre, correo.hash)
        enviar_correo('pablo.rey@econo.unlp.edu.ar', mail, 'Confirmación de cuenta alternativa de contacto', cuerpo)


    """
    @staticmethod
    def obtener_template(nombre, codigo):
        with open('users/model/templates/confirmar_correo.html','r') as f:
            template = f.read()
            texto = template.replace('$USUARIO',nombre)\
                    .replace('$CODIGO_CONFIRMACION',codigo)\
                    .replace('$URL_DE_INFORME','http://incidentes.econo.unlp.edu.ar/0293094-df2323-r4354-f34543')
            return texto

    @staticmethod
    def enviar_correo(de, para, asunto, cuerpo):
        ''' https://developers.google.com/gmail/api/guides/sending '''
        bcuerpo = base64.urlsafe_b64encode(cuerpo.encode('utf-8')).decode()
        r = requests.post('http://163.10.56.57:8001/emails/api/v1.0/enviar_correo', json={'de':de, 'para':para, 'asunto':asunto, 'cuerpo':bcuerpo})
        print(str(r))
    """
