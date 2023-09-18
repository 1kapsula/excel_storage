from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

class Database:
    def __init__(self, db_file: str):
        if not db_file.strip():
            raise Exception("The database file must be specified")
        self.__create_engine_and_factory(db_file)
        Base.metadata.create_all(self.engine)

    def __create_engine_and_factory(self, db_file: str):
        conn_str = f'sqlite:///{db_file.strip()}?check_same_thread=False'
        self.engine = create_engine(conn_str, echo=False)
        self.__factory = scoped_session(sessionmaker(bind=self.engine))

    def create_session(self) -> scoped_session:
        return self.__factory()

    def __enter__(self):
        self.session = self.create_session()
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()
