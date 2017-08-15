from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship

from model_utils import Base


class LoginLog(Base):

    __tablename__ = 'log'
    __table_args__ = ({'schema': 'login'})

    usuario = Column(String)
    correcto = Column(DateTime)
    incorrecto = Column(DateTime)
