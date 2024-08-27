from flask import request, session, jsonify
from flask_restful import Api, Resource
from sqlalchemy.exc import IntegrityError
from models import User, Recipe
from config import app, db, bcrypt

api = Api(app)

class Signup(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        email = data.get('email')

        if not username or not password or not email:
            return {'message': 'Missing required fields'}, 422

        if User.query.filter_by(username=username).first():
            return {'message': 'Username already exists'}, 422

        try:
            user = User(username=username, password=password, email=email)
            db.session.add(user)
            db.session.commit()
            return {'message': 'User created successfully'}, 201
        except IntegrityError:
            db.session.rollback()
            return {'message': 'Error creating user'}, 500

class CheckSession(Resource):
    def get(self):
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user:
                return {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }, 200
        return {'message': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return {'message': 'Missing required fields'}, 422

        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            session['user_id'] = user.id
            return {'message': 'Logged in successfully'}, 200
        return {'message': 'Invalid credentials'}, 401

class Logout(Resource):
    def post(self):
        if 'user_id' not in session:
            return {'message': 'No active session'}, 401

        session.pop('user_id', None)
        return {'message': 'Logged out successfully'}, 200

class RecipeIndex(Resource):
    def get(self):
        if 'user_id' not in session:
            return {'message': 'Unauthorized'}, 401

        user = User.query.get(session['user_id'])
        if user:
            recipes = Recipe.query.filter_by(user_id=user.id).all()
            return [{'id': r.id, 'title': r.title, 'description': r.description} for r in recipes], 200
        return {'message': 'No recipes found'}, 404

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')

if __name__ == '__main__':
    app.run(port=5555, debug=True)
