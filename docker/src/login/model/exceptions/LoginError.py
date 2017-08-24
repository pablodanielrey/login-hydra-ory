
class LoginError(Exception):

    def __init__(self, status_code=None, data=None):
        self.status_code = 500
        if status_code:
            self.status_code=status_code
        self.error = self.__class__.__name__
        self.data = data

    def __json__(self):
        return self.__dict__

class SeguridadError(LoginError):
    def __init__(self):
        super().__init__(status_code=403)

class UsuarioNoEncontradoError(LoginError):
    def __init__(self, data=None):
        super().__init__(status_code=404, data=data)

class ClaveError(LoginError):
    def __init__(self, data=None):
        super().__init__(status_code=500, data=data)


class UsuarioBloqueadoError(LoginError):
    def __init__(self, data=None):
        super().__init__(status_code=500, data=data)
