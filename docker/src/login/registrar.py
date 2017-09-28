

if __name__ == '__main__':
    import os
    import sys

    nombre = 'login'
    dominio = os.environ['LOGIN_OIDC_URL'].replace('http://','').replace('https://','')
    path = sys.argv[1]
    server = sys.argv[2]

    import auth_utils
    r = auth_utils.RegistrarServicio()
    r.register(name=nombre, domain=dominio, path=path, server=server)
