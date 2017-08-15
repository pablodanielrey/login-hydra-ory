'''
    problema de codificación a json en flask.
    respuesta :
    https://stackoverflow.com/questions/5022066/how-to-serialize-sqlalchemy-result-to-json
'''
from sqlalchemy.ext.declarative import DeclarativeMeta
from flask import json
import json as jsonn
import datetime

class BasicEncoder(jsonn.JSONEncoder):

    @staticmethod
    def encode_c(o):
        if isinstance(o, datetime.datetime):
            return o.isoformat(' ')
        if isinstance(o, datetime.date):
            return o.isoformat()
        if isinstance(o, set):
            return list(o)
        if isinstance(o, str):
            return o
        return jsonn.dumps(o)

    def default(self, o):
        return self.encode_c(o)


class AlchemyEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o.__class__, DeclarativeMeta):
            data = {}
            fields = o.__serialize__ if hasattr(o, '__serialize__') else dir(o)
            for field in [f for f in fields if not f.startswith('_') and f not in ['metadata', 'query', 'query_class']]:
                value = o.__getattribute__(field)
                try:
                    value = BasicEncoder.encode_c(value)
                    data[field] = value
                except TypeError:
                    data[field] = None
            return data
        return super(AlchemyEncoder,self).default(o)


def register_encoder(app):
    app.json_encoder = AlchemyEncoder
