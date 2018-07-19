import uuid
import datetime
import base64
import requests

import logging
import os
import hashlib

import oidc
from oidc.oidc import ClientCredentialsGrant


from .exceptions import *

class LoginModel:

    verify = bool(int(os.environ.get('VERIFY_SSL', 1)))
    USERS_API_URL = os.environ['USERS_API_URL']
    client_id = os.environ['OIDC_CLIENT_ID']
    client_secret = os.environ['OIDC_CLIENT_SECRET']

    '''
    @classmethod
    def verificar_challenge(cls, challenge):
        token = jwt.decode(challenge, cls.HYDRA_CLAVE)
        url = token['redir']
        return url
    '''

    @classmethod
    def login(cls, usuario, clave):

        ''' obtengo un token mediante el flujo client_credentials para poder llamar a la api de usuarios '''
        grant = ClientCredentialsGrant(cls.client_id, cls.client_secret, verify=cls.verify)
        token = grant.get_token(grant.access_token())
        if not token:
            raise LoginError()


        ''' se deben cheqeuar intentos de login, y disparar : SeguridadError en el caso de que se haya alcanzado el máximo de intentos '''
        headers = {
            'Authorization': 'Bearer {}'.format(token)
        }
        r = requests.post(cls.USERS_API_URL + '/auth', verify=cls.verify, headers=headers, json={'usuario':usuario, 'clave':clave})
        if r.status_code == 200:
            clave_data = r.json()
            usuario_id = clave_data['usuario_id']
            r = requests.get(cls.USERS_API_URL + '/usuarios/{}'.format(usuario_id), headers=headers, verify=cls.verify)
            if r.status_code == 200:
                return r.json()
        logging.debug(r)
        
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
