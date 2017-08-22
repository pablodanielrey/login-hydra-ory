import uuid
import datetime
import base64
import requests
import logging
import os

import jwt

from sqlalchemy import or_
from sqlalchemy.orm import joinedload

from .exceptions import *
from .entities import *


class LoginModel:

    #HYDRA_CLAVE = os.environ['HYDRA_CLAVE']

    '''
    @classmethod
    def verificar_challenge(cls, challenge):
        token = jwt.decode(challenge, cls.HYDRA_CLAVE)
        url = token['redir']
        return url
    '''
    @staticmethod
    def _aplicar_filtros_comunes(q, offset, limit):
        q = q.offset(offset) if offset else q
        q = q.limit(limit) if limit else q
        return q


    @classmethod
    def obtener_usuario(cls, session, dni):
        try:
            q = session.query(UsuarioClave).filter(UsuarioClave.nombre_de_usuario == dni)
            usuario = q.one()
            return {
                'nombre':'algo',
                'apellido':'algo2',
                'dni': dni,
                'foto': 'http://algo.com/archivo/fdlnsdfklkf34lfm/contenido'
            }
        except Exception as e:
            logging.exception(e)
            raise UsuarioNoEncontradoError()


    @classmethod
    def login(cls, session, usuario, clave):
        try:
            ''' se deben cheqeuar intentos de login, y disparar : SeguridadError en el caso de que se haya alcanzado el máximo de intentos '''
            return session.query(UsuarioClave).filter(UsuarioClave.nombre_de_usuario == usuario, UsuarioClave.clave == clave).one()
        except Exception:
            raise ClaveError()
