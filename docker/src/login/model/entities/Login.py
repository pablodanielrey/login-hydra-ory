from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, DateTime
from sqlalchemy.orm import relationship

from model_utils import Base


class LoginLog(Base):

    __tablename__ = 'log'
    __table_args__ = ({'schema': 'login'})

    usuario = Column(String)
    correcto = Column(DateTime)
    incorrecto = Column(DateTime)


class AuthzCode(Base):

    __tablename__ = 'authz_code'
    __table_args__ = ({'schema': 'login'})

    code = Column(String)
    valor = Column(String)


class AccessToken(Base):

    __tablename__ = 'access_token'
    __table_args__ = ({'schema': 'login'})

    code = Column(String)
    valor = Column(String)


class RefreshToken(Base):

    __tablename__ = 'refresh_token'
    __table_args__ = ({'schema': 'login'})

    code = Column(String)
    valor = Column(String)


class SubjectIdentifier(Base):

    __tablename__ = 'subject_identifier'
    __table_args__ = ({'schema': 'login'})

    code = Column(String)
    valor = Column(String)
