from sqlalchemy import Column, Integer, String, Float
from database import Base

class MovieModel(Base):
    __tablename__ = "movies"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    genre = Column(String, index=True, nullable=False)
    price = Column(Float, nullable=False)
