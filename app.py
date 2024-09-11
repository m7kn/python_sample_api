import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from flask_restx import Api, Resource, fields, abort
from dotenv import load_dotenv
from sqlalchemy.exc import IntegrityError
from enum import Enum

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
ns_admin = api.namespace('admin', description='Admin operations')
ns_auth = api.namespace('auth', description='Authentication operations')
ns_info = api.namespace('info', description='Information operations')
ns_data = api.namespace('data', description='Data operations')

# Define Role enum
class Role(Enum):
    ADMIN = 'admin'
    EDITOR = 'editor'
    USER = 'user'

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    role = db.Column(db.Enum(Role), default=Role.USER)

# Data model
class Data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

# Define API models
user_model = api.model('User', {
    'username': fields.String(required=True, description='Username'),
    'password': fields.String(required=True, description='Password'),
    'role': fields.String(required=False, description='User role (admin/editor/user)', enum=['admin', 'editor', 'user'], default='user', example='user')    
})

data_model = api.model('Data', {
    'name': fields.String(required=True, description='Item name'),
    'content': fields.String(required=True, description='Data content')
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
        role = Role.ADMIN if is_first_user else Role.USER
        
        new_user = User(username=data['username'], password=hashed_password, role=role)
        db.session.add(new_user)
        
        try:
            db.session.commit()
            return {"message": "User created successfully", "role": role.value}, 201
        except IntegrityError:
            db.session.rollback()
            return {"message": "Username already exists"}, 400


# Admin routes
@ns_admin.route('/create_user')
class CreateUser(Resource):
    @jwt_required()
    @api.expect(user_model)
    @api.doc(security='Bearer Auth')
    def post(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        if current_user.role != Role.ADMIN:
            return {"message": "Admin access required"}, 403
        
        data = api.payload
        hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
        new_user = User(username=data['username'], password=hashed_password, role=Role(data.get('role', 'user')))
        
        try:
            db.session.add(new_user)
            db.session.commit()
            return {"message": f"{new_user.role.value.capitalize()} user created successfully"}, 201
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
@ns_data.route('/')
class DataList(Resource):
    @jwt_required()
    @api.doc(security='Bearer Auth')
    def get(self):
        data = Data.query.all()
        return [{"id": item.id, "name": item.name, "content": item.content} for item in data], 200
    
    @jwt_required()
    @api.expect(data_model)
    @api.doc(security='Bearer Auth')
    def post(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        if current_user.role == Role.USER:
            return {"message": "Editor or Admin access required"}, 403
        
        data = api.payload
        new_data = Data(name=data['name'], content=data['content'])
        db.session.add(new_data)
        db.session.commit()
        return {"message": "Data created successfully"}, 201


# Info route
@ns_info.route('/user')
class UserInfo(Resource):
    @jwt_required()
    @api.doc(security='Bearer Auth')
    def get(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        return {"username": current_user.username, "role": current_user.role.value}, 200


# Add this new model for role change
role_change_model = api.model('RoleChange', {
    'username': fields.String(required=True, description='Username of the user to change role'),
    'new_role': fields.String(required=True, description='New role for the user', enum=['admin', 'editor', 'user'])
})

# change_role in the admin namespace
@ns_admin.route('/change_role')
class ChangeUserRole(Resource):
    @jwt_required()
    @api.expect(role_change_model)
    @api.doc(security='Bearer Auth')
    def post(self):
        current_user_id = get_jwt_identity()
        current_user = User.query.get(current_user_id)
        
        if current_user.role != Role.ADMIN:
            return {"message": "Admin access required"}, 403
        
        data = api.payload
        user_to_change = User.query.filter_by(username=data['username']).first()
        
        if not user_to_change:
            abort(404, f"User {data['username']} not found")
        
        try:
            new_role = Role(data['new_role'])
        except ValueError:
            abort(400, f"Invalid role: {data['new_role']}")
        
        user_to_change.role = new_role
        db.session.commit()
        
        return {"message": f"User {data['username']} role changed to {new_role.value}"}, 200
    

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