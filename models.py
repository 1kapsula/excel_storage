import sqlalchemy as sa
import datetime
from passlib.hash import bcrypt
from itsdangerous import URLSafeTimedSerializer as Serializer, BadSignature, SignatureExpired
from sqlalchemy import orm
from db_session import Database, Base
from flask import current_app

class Files(Base):
    __tablename__ = "excel_files"
    file_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    file_name = sa.Column(sa.String())
    file_path = sa.Column(sa.String())
    create_date = sa.Column(sa.DateTime)
    user_id = sa.Column(sa.Integer, sa.ForeignKey("users.user_id"))
    user = orm.relationship("Users", back_populates="files")
    is_private = sa.Column(sa.Boolean, default=True)

    def __repr__(self) -> str:
        return f'File {self.file_id}:{self.file_name}'

class InvalidToken(Exception):
    pass

class Users(Base):
    __tablename__ = "users"
    user_id = sa.Column(sa.Integer, primary_key=True, autoincrement=True)
    username = sa.Column(sa.String, nullable=True, unique=True)
    password_hash = sa.Column(sa.String)
    files = orm.relationship("Files", back_populates="user")

    def encode_access_token(self):
        s = Serializer(current_app.config['SECRET_KEY'])
        return s.dumps({'user_id': self.user_id})

    @staticmethod
    def decode_access_token(access_token, session):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(access_token)
        except SignatureExpired:
            return None
        except BadSignature:
            return None
        user = session.query(Users).get(data['user_id'])
        return user

    @property
    def password(self):
        raise AttributeError("password: write-only field")

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.using(rounds=current_app.config["ROUNDS"]).hash(password)

    def check_password(self, password):
        return bcrypt.verify(password, self.password_hash)

    def __repr__(self) -> str:
        return f'User {self.user_id}:{self.username}'
