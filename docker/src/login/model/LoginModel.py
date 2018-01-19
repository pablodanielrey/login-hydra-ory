import uuid
import datetime
import base64
import requests
import logging
import os
import hashlib

from .exceptions import *

class LoginModel:

    verify = True
    USERS_API_URL = os.environ['USERS_API_URL']

    '''
    @classmethod
    def verificar_challenge(cls, challenge):
        token = jwt.decode(challenge, cls.HYDRA_CLAVE)
        url = token['redir']
        return url
    '''

    @classmethod
    def login(cls, usuario, clave):
        ''' se deben cheqeuar intentos de login, y disparar : SeguridadError en el caso de que se haya alcanzado el máximo de intentos '''
        r = requests.post(cls.USERS_API_URL + '/auth', verify=cls.verify, json={'usuario':usuario, 'clave':clave})
        if r.status_code == 200:
            return r.json()

        if r.status_code == 403:
            raise ClaveError()

        if r.status_code == 404:
            raise UsuarioNoEncontradoError()

        raise LoginError()

    @classmethod
    def obtener_usuario(cls, uid):
        '''
            https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        '''
        try:
            r = requests.get(cls.USERS_API_URL + '/usuarios/' + uid)
            if r.status_code != 200:
                raise UsuarioNoEncontradoError()

            u = r.json()

            ''' lo convierto al formato esperado por OIDC '''

            r = {
                'sub': u['id'],
                'name': u['nombre'],
                'given_name': u['nombre'] + ' ' + u['apellido'],
                'family_name': u['apellido'],
                'gender': u['genero'],
                'birdthdate': u['nacimiento']
            }

            r['econo'] = {
                'id': u['id'],
                'dni': u['dni'],
                'legajo': ''
            }


            if u['ciudad'] or u['direccion'] or u['pais']:
                r['address'] = {
                    'street_address': u['direccion'],
                    'locality': u['ciudad'],
                    'country': u['pais']
                }

            if 'mails' in u and len(u['mails']) > 0:
                for ma in u['mails']:
                    if ma['fecha_confirmado']:
                        r['email'] = ma['email']
                        r['email_verified'] = True
                        break
                else:
                    r['email'] = u['mails'][0]['email']
                    r['email_verified'] = False

            if 'telefonos' in u and len(u['telefonos']) > 0:
                r['phone_number'] = u['telefonos'][0]['numero']
                #r['phone_number_verified'] = False

            ''' hay que ver el tema del picture ahora lo hago con users pero en uns ervicio uy parecido a gravatar '''
            if 'email' in r:
                h = hashlib.md5(r['email'].strip().lower().encode('utf-8')).hexdigest()
                '''
                r['picture'] = 'https://www.gravatar.com/avatar/' + h + '?s=100&d=mm'
                '''
                r['pircture'] = cls.USERS_API_URL + '/avatar/' + h
            return r

        except Exception as e:
            logging.exception(e)
            raise e
