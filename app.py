from flask import Flask, request, jsonify, g, Response
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, get_jwt, unset_jwt_cookies, create_access_token, set_access_cookies
)
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import decode_token
from flask import make_response
import re
import logging
import uuid
import json
import redis
from datetime import datetime
from pathlib import Path
from argon2 import PasswordHasher
from flask_swagger_ui import get_swaggerui_blueprint
from sqlalchemy.dialects.postgresql import JSON
from collections import defaultdict, OrderedDict
from functools import wraps  # Required for decorators
from flask import has_app_context, has_request_context
from werkzeug.serving import WSGIRequestHandler
from threading import local
from datetime import timedelta
from email_validator import validate_email, EmailNotValidError


LOG_DIRECTORY = './logs/'
SCRIPT_NAME = 'cbnotices'
request_data = local()
ph = PasswordHasher()

# Logging Filter to Add Transaction ID
class TransactionIDFilter(logging.Filter):
    def filter(self, record):
        transaction_id = getattr(request_data, 'transaction_id', 'N/A')
        record.transaction_id = transaction_id
        return True

class CustomFormatter(logging.Formatter):
    def format(self, record):
        if not hasattr(record, 'transaction_id'):
            record.transaction_id = 'N/A'
        return super().format(record)

class CustomWSGIRequestHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        transaction_id = getattr(request_data, 'transaction_id', 'N/A')
        self.log(
            "info",
            f'[Transaction-ID: {transaction_id}] "{self.requestline}" {code} {size}',
        )

    def log_message(self, format, *args):
        transaction_id = getattr(request_data, 'transaction_id', 'N/A')
        message = f'[Transaction-ID: {transaction_id}] ' + (format % args)
        logging.info(message)

def setup_logging(level='INFO'):
    # Create log directory if it doesn't exist
    today = datetime.now().strftime("%Y-%m-%d")
    log_directory = Path(LOG_DIRECTORY).resolve()

    if not log_directory.exists():
        log_directory.mkdir(parents=True, exist_ok=True)

    # Determine the log file name with iteration
    iteration = 1
    while True:
        log_filename = f"{today}-{SCRIPT_NAME}_{iteration}.log"
        full_log_path = log_directory / log_filename
        if not full_log_path.exists():
            break
        iteration += 1

    # Define a custom formatter to include transaction_id
    formatter = CustomFormatter('%(asctime)s [%(transaction_id)s] - %(levelname)s - %(message)s')

    # Create a file handler and attach the formatter
    file_handler = logging.FileHandler(filename=str(full_log_path), mode='w')
    file_handler.setFormatter(formatter)

    # Configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    root_logger.addHandler(file_handler)

    # Attach TransactionIDFilter to all handlers
    for handler in root_logger.handlers:
        handler.addFilter(TransactionIDFilter())

    # Patch Werkzeug logger
    werkzeug_logger = logging.getLogger('werkzeug')
    werkzeug_logger.setLevel(logging.ERROR)

    # Define a specific formatter for Werkzeug logs
    class WerkzeugFormatter(CustomFormatter):
        def format(self, record):
            from flask import has_request_context, g
            if has_request_context():
                record.transaction_id = getattr(g, 'transaction_id', 'N/A')
            else:
                record.transaction_id = 'N/A'
            return super().format(record)

    # Apply the Werkzeug formatter and filter
    for handler in werkzeug_logger.handlers:
        handler.setFormatter(WerkzeugFormatter())
        handler.addFilter(TransactionIDFilter())

    # Log startup details
    logging.info('#' * 50)
    logging.info(f"Script Name: {SCRIPT_NAME}")
    logging.info(f"Log File: {full_log_path}")
    logging.info(f"Script Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logging.info('#' * 50)

    return full_log_path  # Optionally return the log file path

setup_logging()
logging.getLogger().addFilter(TransactionIDFilter())

# Initialize Flask App
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://<db_username>:<db_password>@<db_host>/<db_name>'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = '<jwt_secret_key>'
app.config['LOGGING_LEVEL'] = 'INFO'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=30)
app.config['JSON_SORT_KEYS'] = False
redis_client = redis.StrictRedis(host='localhost', port=6379, db=0)

db = SQLAlchemy(app)
jwt = JWTManager(app)
ph = PasswordHasher()

# Swagger Configuration
SWAGGER_URL = '/api/docs'
API_URL = '/static/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,  # Swagger UI endpoint
    API_URL,      # Swagger specification file
    config={
        'app_name': "RBAC Boilerplate App"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

# Before Request to Set Transaction ID
@app.before_request
def log_request_start():
    """Generate a Transaction-ID and log the request start."""
    g.transaction_id = str(uuid.uuid4())  # Generate a unique Transaction ID
    request_data.transaction_id = g.transaction_id  # Store it in request_data for global access
    logging.info(f"Transaction ID set: {g.transaction_id} for {request.method} {request.path}")

# After Request to Add Transaction ID to Headers
@app.after_request
def log_request(response):
    """Log the request and add the Transaction-ID to response headers."""
    transaction_id = getattr(g, 'transaction_id', None)  # Retrieve the Transaction ID
    if transaction_id:
        response.headers['Transaction-ID'] = transaction_id  # Add the Transaction ID to response headers
    # Log the request details including Transaction ID
    logging.info(
        f"{transaction_id} - {request.remote_addr} - {request.method} {request.path} - {response.status_code}"
    )
    return response

@app.teardown_request
def log_teardown_request(error=None):
    if error:
        logging.error(f"Request teardown due to error: {error}")
    else:
        logging.info(f"Request teardown completed")

# Mask sensitive data for logs
def mask_sensitive_data(data):
    return data[:2] + "****" if len(data) > 2 else "****"

def safe_json_loads(json_string):
    try:
        return json.loads(json_string) if json_string else {}
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON in allowed_routes: {json_string}")
        return {}

# Data Models
class Role(db.Model):
    __tablename__ = 'role'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)

    # Relationship to RolePermission
    allowed_routes = db.relationship(
        'RolePermission',
        back_populates='role',
        cascade="all, delete-orphan"
    )

    # Relationship to UserRole for many-to-many with User
    users = db.relationship(
        'UserRole',
        back_populates='role',
        cascade="all, delete-orphan"
    )

class User(db.Model):
    __tablename__ = 'user'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    first_name = db.Column(db.String(80), nullable=False)
    last_name = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    # Relationship to UserRole
    roles = db.relationship(
        'UserRole',
        back_populates='user',
        cascade="all, delete-orphan"
    )

class RolePermission(db.Model):
    __tablename__ = 'role_permissions'

    id = db.Column(db.Integer, primary_key=True)
    route = db.Column(db.String(255), nullable=False)
    method = db.Column(db.String(10), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)

    # Relationship back to Role
    role = db.relationship('Role', back_populates='allowed_routes')

class UserRole(db.Model):
    __tablename__ = 'user_roles'

    # Composite primary key
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), primary_key=True)

    # Relationships to User and Role
    user = db.relationship('User', back_populates='roles')
    role = db.relationship('Role', back_populates='users')

# Utility Functions
# Function to extend session key
def extend_session():
    """Extend the session key for the authenticated user."""
    identity = get_jwt_identity()
    if identity:
        # Create a new access token with a 30-minute expiration
        access_token = create_access_token(identity=identity, expires_delta=timedelta(minutes=30))
        
        # Create a response object
        response = make_response(jsonify({"msg": "Session extended"}))
        
        # Set the access cookies on the response
        set_access_cookies(response, access_token)
        
        return response

    return jsonify({"msg": "No active session"}), 401

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    # Check Redis to see if the token is in the blocklist
    token_revoked = redis_client.get(f"revoked_token:{jti}")
    return token_revoked is not None

def get_all_methods():
    methods = defaultdict(list)
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            methods[rule.rule].extend(list(rule.methods - {'HEAD', 'OPTIONS'}))
    return {route: methods for route, methods in methods.items() if methods}

def role_required():
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            try:
                # Get the user ID (sub claim) from the JWT and convert it to an integer
                user_id = int(get_jwt_identity())
                logging.info(f"Extracted user_id from JWT: {user_id}")

                # Retrieve the user from the database
                user = db.session.query(User).filter_by(id=user_id).first()
                if not user:
                    logging.error(f"User with ID {user_id} not found")
                    return jsonify({"msg": "User not found"}), 404

                logging.info(f"User found: {user.username}")

                # Get the requested route and method
                requested_route = request.path
                requested_method = request.method
                logging.info(f"Checking permissions for route {requested_route}, method {requested_method}")

                # Check if the user has permission for the route and method
                # Fetch all permissions for the user
                permissions = (
                    db.session.query(RolePermission)
                    .join(Role, Role.id == RolePermission.role_id)
                    .join(UserRole, UserRole.role_id == Role.id)
                    .filter(UserRole.user_id == user.id)
                    .all()
                )

                # Match route and method
                has_permission = False
                for perm in permissions:
                    # Handle wildcards
                    if (perm.route == "*" or perm.method == "*") or (
                        perm.method == requested_method and match_route(perm.route, requested_route)
                    ):
                        has_permission = True
                        break

                logging.info(f"Permission check result: {has_permission}")

                if not has_permission:
                    logging.warning(f"User {user.username} does not have access to {requested_route}")
                    return jsonify({"msg": "Access denied"}), 403

            except Exception as e:
                logging.error(f"Error in @role_required: {e}")
                return jsonify({"msg": "Unexpected server error"}), 500

            return f(*args, **kwargs)
        return wrapper
    return decorator

def is_valid_email(email):
    """
    Validates an email address using a regex pattern.
    
    This regex ensures that the email has a basic structure of:
    some_characters@some_domain.extension
    
    Returns:
        True if the email matches the pattern, False otherwise.
    """
    # This is a basic regex pattern for email validation.
    # For production use, consider a more robust solution such as the `email-validator` package.
    try:
        # Validate and normalize the email address
        validate_email(email)
        return True
    except EmailNotValidError:
        return False

#  Match a database route (with placeholders) to an actual route.
def match_route(db_route, actual_route):
    # Convert Flask-style route placeholders to regex
    regex_route = re.sub(r"<.*?>", r"[^/]+", db_route)  # Replace <...> with regex for non-slashes
    regex_route = f"^{regex_route}$"  # Ensure full match
    return re.match(regex_route, actual_route) is not None

# Helper function to enforce password complexity
def is_password_complex(password):
    if (len(password) >= 8 and
        any(c.isdigit() for c in password) and
        any(c.islower() for c in password) and
        any(c.isupper() for c in password) and
        any(c in '!@#$%^&*()-_=+[]{}|;:,.<>?/' for c in password)):
        return True
    return False

## debug route
@app.route('/api/debug_token', methods=['GET'])
@jwt_required()
def debug_token():
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"msg": "Authorization header is missing or improperly formatted"}), 400

        # Extract the token
        token = auth_header.split()[1]

        # Decode the token
        decoded = decode_token(token)
        return jsonify({"decoded_token": decoded}), 200
    except Exception as e:
        return jsonify({"msg": f"Error decoding token: {e}"}), 400
    
@app.route('/api/ping', methods=['GET'])
def ping():
    return jsonify({'message': 'pong'}), 200

## User Routes ##
# User Login
@app.route('/api/login', methods=['POST'])
def login():
    username = request.json.get("username")
    password = request.json.get("password")

    # Validate inputs
    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    # Convert the username to lowercase for case-insensitive login
    username = username.lower()

    # Query the database for the user
    user = db.session.query(User).filter_by(username=username).first()
    if not user:
        return jsonify({"msg": "Invalid credentials"}), 401

    # Validate the password
    try:
        ph.verify(user.password, password)
    except Exception as e:
        logging.error(f"Password verification failed: {e}")
        return jsonify({"msg": "Invalid credentials"}), 401

    # Create a JWT token with the user's ID as a string
    access_token = create_access_token(identity=str(user.id))
    return jsonify({"access_token": access_token}), 200

@app.route('/api/session/logout', methods=['POST'])
@jwt_required()
def logout():
    """Kill the current session key (self)."""
    jti = get_jwt()["jti"]
    exp = get_jwt()["exp"]  # Get the expiration timestamp of the token
    now = datetime.utcnow().timestamp()

    # Calculate the time remaining until the token naturally expires
    ttl = int(exp - now)

    # Store the revoked token in Redis with a TTL
    redis_client.setex(f"revoked_token:{jti}", ttl, "true")

    response = jsonify({"msg": "Session ended"})
    unset_jwt_cookies(response)
    return response

@app.route('/api/session/extend', methods=['POST'])
@jwt_required()
def extend_session():
    """Extend the session key."""
    identity = get_jwt()["sub"]
    access_token = create_access_token(identity=identity, expires_delta=timedelta(minutes=30))
    response = jsonify({"msg": "Session extended"})
    set_access_cookies(response, access_token)
    return response

#User Routes
@app.route('/api/users', methods=['GET'])
@jwt_required()
@role_required()
def list_users():
    # Ensure users are sorted by id in ascending order.
    users = User.query.order_by(User.id.asc()).all()
    
    result = []
    for user in users:
        # Create an OrderedDict for the user with the desired key order.
        user_data = OrderedDict([
            ("id", user.id),
            ("first_name", user.first_name),
            ("last_name", user.last_name),
            ("email", user.email),
            ("username", user.username)
        ])
        
        # Build an ordered list for the user's roles.
        roles = []
        for user_role in user.roles:
            role_data = OrderedDict([
                ("id", user_role.role.id),
                ("name", user_role.role.name)
            ])
            roles.append(role_data)
        
        # Add the roles to the user data.
        user_data["roles"] = roles
        result.append(user_data)
    
    # Serialize to JSON without sorting keys and return a custom response.
    json_output = json.dumps(result, sort_keys=False)
    return Response(json_output, mimetype='application/json')


@app.route('/api/users', methods=['POST'])
@jwt_required()
@role_required()
def register():
    username = request.json.get("username")
    password = request.json.get("password")
    confirm_password = request.json.get("confirm_password")
    first_name = request.json.get("first_name")
    last_name = request.json.get("last_name")
    email = request.json.get("email")

    # Validate inputs
    if not all([username, password, confirm_password, first_name, last_name, email]):
        return jsonify({"msg": "All fields (username, password, confirm_password, first_name, last_name, email) are required"}), 400

    # Validate email format
    if not is_valid_email(email):
        return jsonify({"msg": "Invalid email format"}), 400

    if password != confirm_password:
        return jsonify({"msg": "Passwords do not match"}), 400

    if not is_password_complex(password):
        return jsonify({"msg": "Password does not meet complexity requirements"}), 400

    # Check if the username is already taken
    if db.session.query(User).filter_by(username=username).first():
        return jsonify({"msg": "Username is not available."}), 409

    # Check if the email is already taken
    if db.session.query(User).filter_by(email=email).first():
        return jsonify({"msg": "Email is not available."}), 409

    # Hash the password
    hashed_password = ph.hash(password)

    # Create a new user
    new_user = User(
        username=username,
        password=hashed_password,
        first_name=first_name,
        last_name=last_name,
        email=email  # Include email
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"msg": "User registered successfully"}), 201

@app.route('/api/users/<int:user_id>', methods=['GET'])
@jwt_required()
@role_required()
def get_user(user_id):
    user = User.query.get(user_id)
    if not user:
        # You can also use an OrderedDict here if you want consistent ordering for error responses.
        error_response = OrderedDict([("message", "User not found")])
        return Response(json.dumps(error_response, sort_keys=False), status=404, mimetype='application/json')
    
    # Build the user data as an OrderedDict
    user_data = OrderedDict([
        ("id", user.id),
        ("first_name", user.first_name),
        ("last_name", user.last_name),
        ("email", user.email),
        ("username", user.username)
    ])
    
    # Build the ordered list for the user's roles
    roles = []
    for user_role in user.roles:
        role_data = OrderedDict([
            ("id", user_role.role.id),
            ("name", user_role.role.name)
        ])
        roles.append(role_data)
    
    # Add the roles to the user data
    user_data["roles"] = roles

    # Serialize the OrderedDict to JSON with sort_keys disabled
    json_output = json.dumps(user_data, sort_keys=False)
    return Response(json_output, status=200, mimetype='application/json')

@app.route('/api/users/<int:user_id>', methods=['PUT'])
@jwt_required()
@role_required()
def edit_user(user_id):
    """Edit user details. Password update requires both new_password and confirm_password."""
    data = request.get_json()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.email = data.get('email', user.email)
    user.username = data.get('username', user.username)

    # Handle password update only if both passwords are provided
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    if new_password or confirm_password:
        if new_password != confirm_password:
            return jsonify({"message": "Passwords do not match"}), 400
        if not is_password_complex(new_password):
            return jsonify({"message": "Password does not meet complexity requirements"}), 400
        user.password = ph.hash(new_password)

    db.session.commit()
    return jsonify({"message": "User updated successfully"}), 200

@app.route('/api/users/self', methods=['PUT'])
@jwt_required()
def update_self():
    """Update the logged-in user's details. Password update requires both new_password and confirm_password."""
    user_id = get_jwt_identity()  # Get the user ID from the JWT token
    data = request.get_json()

    # Retrieve the user from the database
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404

    # Update only the allowed fields
    user.first_name = data.get('first_name', user.first_name)
    user.last_name = data.get('last_name', user.last_name)
    user.email = data.get('email', user.email)
    user.username = data.get('username', user.username)

    # Handle password update only if both passwords are provided
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    if new_password or confirm_password:
        if new_password != confirm_password:
            return jsonify({"message": "Passwords do not match"}), 400
        if not is_password_complex(new_password):
            return jsonify({"message": "Password does not meet complexity requirements"}), 400
        user.password = ph.hash(new_password)

    db.session.commit()
    return jsonify({"message": "Your profile has been updated successfully"}), 200

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@jwt_required()
def delete_user(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({"message": "User deleted successfully"}), 200

#Users role management
@app.route('/api/users/<int:user_id>/add-role', methods=['POST'])
@jwt_required()
@role_required()
def add_role_to_user(user_id):
    data = request.get_json()
    role_id = data.get('role_id')
    if not role_id:
        return jsonify({"message": "Role ID is required"}), 400

    user = User.query.get(user_id)
    role = Role.query.get(role_id)

    if not user or not role:
        return jsonify({"message": "User or Role not found"}), 404

    if not UserRole.query.filter_by(user_id=user_id, role_id=role_id).first():
        new_user_role = UserRole(user_id=user_id, role_id=role_id)
        db.session.add(new_user_role)
        db.session.commit()
        return jsonify({"message": "Role added to user successfully"}), 200

    return jsonify({"message": "Role already assigned to user"}), 400

@app.route('/api/users/<int:user_id>/remove-role', methods=['POST'])
@jwt_required()
@role_required()
def remove_role_from_user(user_id):
    data = request.get_json()
    role_id = data.get('role_id')
    if not role_id:
        return jsonify({"message": "Role ID is required"}), 400

    user_role = UserRole.query.filter_by(user_id=user_id, role_id=role_id).first()
    if not user_role:
        return jsonify({"message": "Role not assigned to user"}), 400

    db.session.delete(user_role)
    db.session.commit()
    return jsonify({"message": "Role removed from user successfully"}), 200

# Routes for roles
# Routes
@app.route('/api/roles/methods', methods=['GET'])
@jwt_required()
@role_required()
def get_methods():
    methods = get_all_methods()
    return jsonify({"methods": methods}), 200

@app.route('/api/roles', methods=['GET'])
@jwt_required()
@role_required()
def list_roles():
    roles = Role.query.all()
    roles_data = []
    
    for role in roles:
        # Build the allowed_routes value.
        if not role.allowed_routes:
            allowed_routes = "*"
        else:
            # Create an OrderedDict for allowed_routes. This will iterate in the
            # natural order provided by the relationship.
            allowed_routes = OrderedDict()
            for permission in role.allowed_routes:
                allowed_routes[permission.route] = permission.method
        
        # Build an OrderedDict for the role with keys in the desired order.
        role_data = OrderedDict([
            ("id", role.id),
            ("name", role.name),
            ("allowed_routes", allowed_routes),
            ("users", [ur.user.username for ur in UserRole.query.filter_by(role_id=role.id).all()])
        ])
        roles_data.append(role_data)
    
    # Serialize to JSON without sorting keys
    json_output = json.dumps(roles_data, sort_keys=False)
    return Response(json_output, status=200, mimetype='application/json')

@app.route('/api/roles', methods=['POST'])
@jwt_required()
@role_required()
def create_role():
    data = request.get_json()
    role_name = data.get('name')
    if not role_name:
        return jsonify({"msg": "Role name is required"}), 400

    if Role.query.filter_by(name=role_name).first():
        return jsonify({"msg": "Role with this name already exists"}), 400

    new_role = Role(name=role_name)
    db.session.add(new_role)
    db.session.commit()

    return jsonify({"msg": "Role created successfully", "role": {"id": new_role.id, "name": new_role.name}}), 201

@app.route('/api/roles/<int:role_id>', methods=['GET'])
@jwt_required()
@role_required()
def get_role(role_id):
    role = Role.query.get(role_id)
    if not role:
        error_response = OrderedDict([("message", "Role not found")])
        return Response(json.dumps(error_response, sort_keys=False),
                        status=404,
                        mimetype='application/json')

    # Build allowed_routes with ordered keys if permissions exist.
    if not role.allowed_routes:
        allowed_routes = "*"
    else:
        allowed_routes = OrderedDict()
        for permission in role.allowed_routes:
            allowed_routes[permission.route] = permission.method

    # Build the role data as an OrderedDict.
    role_data = OrderedDict([
        ("id", role.id),
        ("name", role.name),
        ("allowed_routes", allowed_routes),
        ("users", [ur.user.username for ur in UserRole.query.filter_by(role_id=role.id).all()])
    ])
    
    # Serialize the OrderedDict to JSON without sorting keys.
    json_output = json.dumps(role_data, sort_keys=False)
    return Response(json_output, status=200, mimetype='application/json')

@app.route('/api/roles/<int:role_id>', methods=['PUT'])
@jwt_required()
@role_required()
def edit_role(role_id):
    role = Role.query.get(role_id)
    if not role:
        return jsonify({"message": "Role not found"}), 404

    data = request.get_json()
    role_name = data.get('name')
    if role_name:
        role.name = role_name

    db.session.commit()
    return jsonify({"message": "Role updated successfully"}), 200

@app.route('/api/roles/<int:role_id>', methods=['DELETE'])
@jwt_required()
@role_required()
def delete_role(role_id):
    role = Role.query.get(role_id)
    if not role:
        return jsonify({"message": "Role not found"}), 404

    db.session.delete(role)
    db.session.commit()
    return jsonify({"message": "Role deleted successfully"}), 200

@app.route('/api/roles/<int:role_id>/add-permission', methods=['POST'])
@jwt_required()
@role_required()
def add_permission_to_role(role_id):
    data = request.get_json()
    role = Role.query.get(role_id)
    if not role:
        return jsonify({"message": "Role not found"}), 404

    permissions = data
    for permission in permissions:
        route = permission.get('route')
        method = permission.get('method')
        if not route or not method:
            return jsonify({"message": "Both route and method are required"}), 400

        existing_permission = RolePermission.query.filter_by(route=route, method=method, role_id=role_id).first()
        if not existing_permission:
            new_permission = RolePermission(route=route, method=method, role=role)
            db.session.add(new_permission)

    db.session.commit()
    return jsonify({"message": "Permissions added successfully"}), 200

@app.route('/api/roles/<int:role_id>/remove-permission', methods=['POST'])
@jwt_required()
@role_required()
def remove_permission_from_role(role_id):
    data = request.get_json()
    role = Role.query.get(role_id)
    if not role:
        return jsonify({"message": "Role not found"}), 404

    permissions = data
    for permission in permissions:
        route = permission.get('route')
        method = permission.get('method')
        if not route or not method:
            return jsonify({"message": "Both route and method are required"}), 400

        existing_permission = RolePermission.query.filter_by(route=route, method=method, role_id=role_id).first()
        if existing_permission:
            db.session.delete(existing_permission)

    db.session.commit()
    return jsonify({"message": "Permissions removed successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True, request_handler=CustomWSGIRequestHandler)
