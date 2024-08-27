from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship, validates
from sqlalchemy_serializer import SerializerMixin
from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    username = Column(String(80), unique=True, nullable=False)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(128), nullable=False)
    image_url = Column(String(255))  # Optional
    bio = Column(String(500))  # Optional

    serialize_only = ('id', 'username', 'email', 'image_url', 'bio')

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def verify_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'

    id = Column(Integer, primary_key=True)
    title = Column(String(100), nullable=False)
    description = Column(String(255))  # Optional
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)

    user = relationship('User', backref='recipes')

    serialize_only = ('id', 'title', 'description', 'user_id')

    @validates('title')
    def validate_title(self, key, title):
        if not title:
            raise ValueError('Title cannot be empty')
        return title

    @validates('description')
    def validate_description(self, key, description):
        if description and len(description) < 50:
            raise ValueError('Description must be at least 50 characters long')
        return description
