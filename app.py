import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restx import Api, Resource, fields
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URI')
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
db = SQLAlchemy(app)
jwt = JWTManager(app)

# Initialize Flask-RESTX
api = Api(app, version='1.0', title='Sample Python API',
    description='A simple API with Swagger documentation')

# Define namespaces
ns_auth = api.namespace('auth', description='Authentication operations')
ns_items = api.namespace('items', description='Item operations')

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)

# Item model
class Item(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))

# Define API models
user_model = api.model('User', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password')
})

item_model = api.model('Item', {
    'name': fields.String(required=True, description='Item name'),
    'description': fields.String(required=True, description='Item description')
})


# Authentication routes
@ns_auth.route('/register')
class Register(Resource):
    @api.expect(user_model)
    @api.doc(responses={201: 'Success', 400: 'Validation Error'})
    def post(self):
        data = api.payload
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        
        # Check if this is the first user
        is_first_user = User.query.count() == 0
        
        new_user = User(username=data['username'], password=hashed_password, is_admin=is_first_user)
        db.session.add(new_user)
        
        try:
            db.session.commit()
            return {"message": "User created successfully", "is_admin": is_first_user}, 201
        except IntegrityError:
            db.session.rollback()
            return {"message": "Username already exists"}, 400


# Admin creation
@ns_auth.route('/create_admin')
class CreateAdmin(Resource):
    @jwt_required()
    @api.expect(user_model)
    @api.doc(security='Bearer Auth')
    def post(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        if not current_user.is_admin:
            return {"message": "Admin access required"}, 403
        
        data = api.payload
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        new_admin = User(username=data['username'], password=hashed_password, is_admin=True)
        
        try:
            db.session.add(new_admin)
            db.session.commit()
            return {"message": "Admin user created successfully"}, 201
        except IntegrityError:
            db.session.rollback()
            return {"message": "Username already exists"}, 400


@ns_auth.route('/login')
class Login(Resource):
    @api.expect(user_model)
    @api.doc(responses={200: 'Success', 401: 'Unauthorized'})
    def post(self):
        data = api.payload
        user = User.query.filter_by(username=data['username']).first()
        if user and check_password_hash(user.password, data['password']):
            access_token = create_access_token(identity=user.id)
            return {"access_token": access_token}, 200
        return {"message": "Invalid credentials"}, 401

# Item routes
@ns_items.route('/')
class ItemList(Resource):
    @jwt_required()
    @api.doc(security='Bearer Auth')
    def get(self):
        items = Item.query.all()
        return [{"id": item.id, "name": item.name, "description": item.description} for item in items], 200
    
    @jwt_required()
    @api.expect(item_model)
    @api.doc(security='Bearer Auth')
    def post(self):
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        if not user.is_admin:
            return {"message": "Admin access required"}, 403
        
        data = api.payload
        new_item = Item(name=data['name'], description=data['description'])
        db.session.add(new_item)
        db.session.commit()
        return {"message": "Item created successfully"}, 201

# Add JWT authorization to Swagger UI
authorizations = {
    'Bearer Auth': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'Authorization',
        'description': "Type in the *'Value'* input box below: **'Bearer &lt;JWT&gt;'**, where JWT is the token you received from the /auth/login endpoint."
    }
}
api.authorizations = authorizations

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)