
'''
    para hacer funcionar este encoder. las clases de sqlalchemy deben tener definida la superclase: flask_jsontools.JsonSerializableBase
    Base = declarative_base(cls=(JsonSerializableBase,MyBaseClass))

    y ser registrado en la app flask usando.
    app.json_encoder = ApiJSONEncoder

    y el metodo rest debe ser anotado usando @jsonapi
    from flask_jsontools import jsonapi

'''
from flask_jsontools import DynamicJSONEncoder
import datetime

class ApiJSONEncoder(DynamicJSONEncoder):
    def default(self, o):
        # Custom formats
        if isinstance(o, datetime.datetime):
            return o.isoformat(' ')
        if isinstance(o, datetime.date):
            return o.isoformat()
        if isinstance(o, set):
            return list(o)

        return super(ApiJSONEncoder, self).default(o)



def register_encoder(app):
    app.json_encoder = ApiJSONEncoder
