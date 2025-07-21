from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import jwt
import datetime
from functools import wraps

# Flask App Setup
app = Flask(__name__)
app.config['SECRET_KEY'] = 'supersecretkey123'  # Change this in production
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@localhost/user_auth_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# User Model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.LargeBinary(128), nullable=False)

# Token Auth Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('x-access-token')
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = User.query.filter_by(username=data['username']).first()
        except:
            return jsonify({'message': 'Invalid Token!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated

# Register
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_pw = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt())
    if User.query.filter_by(username=data['username']).first():
        return jsonify({'message': 'User already exists!'}), 409
    new_user = User(username=data['username'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully!'}), 201

# Login
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(username=data['username']).first()
    if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), user.password):
        return jsonify({'message': 'Invalid credentials!'}), 401
    token = jwt.encode({
        'username': user.username,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'token': token})

# Protected Route
@app.route('/dashboard', methods=['GET'])
@token_required
def dashboard(current_user):
    return jsonify({'message': f'Welcome {current_user.username}! This is a protected route.'})

if __name__ == '__main__':
    app.run(debug=True)
