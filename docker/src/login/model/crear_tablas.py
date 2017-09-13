
if __name__ == '__main__':

    from sqlalchemy.schema import CreateSchema
    from model_utils import Base

    from login.model.engine import engine
    from login.model.entities import *

    #engine.execute(CreateSchema('login'))
    LoginLog.table.create(engine)
