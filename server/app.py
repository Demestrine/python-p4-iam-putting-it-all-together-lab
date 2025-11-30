#!/usr/bin/env python3
from flask import Flask, jsonify, request, session
from flask_restful import Resource, Api
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError

# Import db and bcrypt from models
from models import db, bcrypt, User, Recipe

# -------------------------
# App setup
# -------------------------
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = b'Y\xf1Xz\x00\xad|eQ\x80t \xca\x1a\x10K'

# Initialize extensions
db.init_app(app)
bcrypt.init_app(app)
migrate = Migrate(app, db)
api = Api(app)

# -------------------------
# Resources
# -------------------------
class Signup(Resource):
    def post(self):
        data = request.get_json()
        try:
            # Check if username is provided
            if 'username' not in data or not data['username']:
                return {"errors": "Username is required"}, 422
                
            user = User(
                username=data['username'],
                bio=data.get('bio'),
                image_url=data.get('image_url')
            )
            user.password_hash = data['password']
            db.session.add(user)
            db.session.commit()
            session['user_id'] = user.id
            return {"id": user.id, "username": user.username, "bio": user.bio, "image_url": user.image_url}, 201
        except IntegrityError:
            db.session.rollback()
            return {"errors": "Username must be unique"}, 422
        except Exception as e:
            db.session.rollback()
            return {"errors": str(e)}, 422


class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401
        user = User.query.get(user_id)
        return {"id": user.id, "username": user.username, "bio": user.bio, "image_url": user.image_url}, 200


class Login(Resource):
    def post(self):
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        if user and user.authenticate(data['password']):
            session['user_id'] = user.id
            return {"id": user.id, "username": user.username, "bio": user.bio, "image_url": user.image_url}, 200
        return {"error": "Invalid credentials"}, 401


class Logout(Resource):
    def delete(self):
        if session.get('user_id'):  # This properly checks for a valid user_id
            session.pop('user_id')
            return '', 204
        return {"error": "Unauthorized"}, 401


class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401
        recipes = Recipe.query.filter_by(user_id=user_id).all()
        return [{"id": r.id, "title": r.title, "instructions": r.instructions,
                 "minutes_to_complete": r.minutes_to_complete,
                 "user": {"id": r.user.id, "username": r.user.username,
                          "bio": r.user.bio, "image_url": r.user.image_url}} for r in recipes], 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {"error": "Unauthorized"}, 401
        data = request.get_json()
        try:
            recipe = Recipe(
                title=data['title'],
                instructions=data['instructions'],
                minutes_to_complete=data['minutes_to_complete'],
                user_id=user_id
            )
            db.session.add(recipe)
            db.session.commit()
            return {"id": recipe.id, "title": recipe.title, "instructions": recipe.instructions,
                    "minutes_to_complete": recipe.minutes_to_complete,
                    "user": {"id": recipe.user.id, "username": recipe.user.username,
                             "bio": recipe.user.bio, "image_url": recipe.user.image_url}}, 201
        except Exception as e:
            db.session.rollback()
            return {"errors": str(e)}, 422

# -------------------------
# Routes
# -------------------------
api.add_resource(Signup, '/signup')
api.add_resource(CheckSession, '/check_session')
api.add_resource(Login, '/login')
api.add_resource(Logout, '/logout')
api.add_resource(RecipeIndex, '/recipes')

# -------------------------
# Run
# -------------------------
if __name__ == '__main__':
    app.run(port=5555, debug=True)
