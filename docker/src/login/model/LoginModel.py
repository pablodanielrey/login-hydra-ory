import uuid
import datetime
import base64
import requests
import logging
import os
import hashlib

import jwt

from sqlalchemy import or_
from sqlalchemy.orm import joinedload

from users.model.entities import *
from users.model.exceptions import *
from users.model import UsersModel

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
    def login(cls, session, usuario, clave):
        try:
            ''' se deben cheqeuar intentos de login, y disparar : SeguridadError en el caso de que se haya alcanzado el máximo de intentos '''
            return session.query(UsuarioClave).filter(UsuarioClave.nombre_de_usuario == usuario, UsuarioClave.clave == clave).one()
        except Exception:
            raise UsuarioNoEncontradoError()
            ''' chequear si hay que bloquear al usuario '''
            #raise UsuarioBloqueadoError(data={'tiempo_de_bloqueo':59})
            '''
            raise ClaveError(data={'intentos_restantes':0})
            '''

    @classmethod
    def obtener_usuario(cls, session, uid):
        '''
            https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        '''
        try:
            usuarios = UsersModel.usuarios(session, usuario=uid)
            u = usuarios[0]

            ''' lo convierto al formato esperado por OIDC '''

            r = {
                'sub': u.id,
                'name': u.nombre,
                'given_name': u.nombre + ' ' + u.apellido,
                'family_name': u.apellido,
                'gender': u.genero,
                'birdthdate': u.nacimiento
            }

            r['econo'] = {
                'id': u.id,
                'dni': u.dni,
                'legajo': ''
            }


            if u.ciudad or u.direccion or u.pais:
                r['address'] = {
                    'street_address': u.direccion,
                    'locality': u.ciudad,
                    'country': u.pais
                }

            if u.mails != None and len(u.mails) > 0:
                for ma in u.mails:
                    if ma.fecha_confirmado:
                        r['email'] = ma.email
                        r['email_verified'] = True
                        break
                else:
                    r['email'] = u.mails[0].email
                    r['email_verified'] = False

            if u.telefonos != None and len(u.telefonos) > 0:
                r['phone_number'] = u.telefonos[0].numero
                #r['phone_number_verified'] = False

            ''' hay que ver el tema del picture ahora lo hago con users pero en uns ervicio uy parecido a gravatar '''
            if 'email' in r:
                h = hashlib.md5(r['email'].strip().lower().encode('utf-8')).hexdigest()
                '''
                r['picture'] = 'https://www.gravatar.com/avatar/' + h + '?s=100&d=mm'
                '''
                r['pircture'] = os.environ['USERS_API_URL'] + '/avatar/' + h
            return r

        except Exception as e:
            logging.exception(e)
            raise UsersError()


    @classmethod
    def existe(cls, session, uid):
        return UsersModel.existe(session, uid)
