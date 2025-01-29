from flask import request, jsonify
from datetime import datetime, timedelta
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
import jwt
from functools import wraps
from flask_cors import CORS  # Import CORS

app = Flask(__name__)

# Enable CORS for all routes
CORS(app)

# Configuración de la base de datos y JWT
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app2.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'bXyZ@56!_randomSecretKey'

# Inicializar SQLAlchemy
db = SQLAlchemy(app)

# Modelo para almacenar usuarios


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Define the Category model


class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)
    tasks = db.relationship('Task', backref='category', lazy=True)

# Define the Task model


class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255))
    # Make sure default is correct
    creation_date = db.Column(db.DateTime, default=datetime.utcnow)
    finishing_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), nullable=False, default='pending')
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey(
        'category.id'), nullable=False)


# Crear las tablas en la base de datos


# Crear las tablas en la base de datos al inicio de la aplicación
with app.app_context():
    db.create_all()

# Decorador para proteger rutas que requieren un token JWT válido


def token_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(
                " ")[1]  # Obtener el token del header
        if not token:
            return jsonify({'message': 'Token is missing!'}), 403
        try:
            # Verificar y decodificar el token
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token has expired!'}), 403
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 403
        if 'still_valid' not in jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"]):
            return jsonify({'message': 'Invalid token!'}), 403
        if not jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])['still_valid']:
            return jsonify({'message': 'Invalid token!'}), 403
        return f(*args, **kwargs)
    return decorated_function

# Ruta para crear un nuevo usuario


@app.route('/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password!'}), 400

    # Verificar si el usuario ya existe
    user = User.query.filter_by(username=data['username']).first()
    if user:
        return jsonify({'message': 'User already exists!'}), 400

    # Crear un nuevo usuario
    new_user = User(username=data['username'], password=data['password'])
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message': 'User created successfully!'})

# Ruta para obtener el token JWT


@app.route('/login', methods=['POST'])
def login():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'message': 'Missing username or password!'}), 400

    user = User.query.filter_by(
        username=data['username'], password=data['password']).first()
    if not user:
        return jsonify({'message': 'Invalid credentials!'}), 401

    # Crear el token JWT con expiración de 30 minutos
    token = jwt.encode({'user': user.username, 'exp': datetime.utcnow() + timedelta(minutes=30), 'still_valid': True},
                       app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'token': token})


@app.route('/logout', methods=['POST'])
@token_required
def logout():
    user_from_token = jwt.decode(request.headers['Authorization'].split(
        " ")[1], app.config['SECRET_KEY'], algorithms=["HS256"])['user']
    print(user_from_token)
    user = User.query.filter_by(username=user_from_token).first()

    token = jwt.encode({'user': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30), 'still_valid': False},
                       app.config['SECRET_KEY'], algorithm="HS256")
    return jsonify({'token': token})


@app.route('/protected', methods=['GET'])
@token_required
def protected():
    return jsonify({'message': 'Este es un endpoint protegido!'})


@app.route('/categories', methods=['GET'])
@token_required
def get_categories():
    categories = Category.query.all()
    return jsonify([{'id': category.id, 'name': category.name, 'description': category.description} for category in categories])


@app.route('/categories', methods=['POST'])
@token_required
def create_category():
    data = request.json
    new_category = Category(name=data['name'], description=data['description'])
    db.session.add(new_category)
    db.session.commit()
    return jsonify({'message': 'Category created successfully!'})


@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks():
    user_from_token = jwt.decode(request.headers['Authorization'].split(
        " ")[1], app.config['SECRET_KEY'], algorithms=["HS256"])['user']
    user = User.query.filter_by(username=user_from_token).first()
    tasks = Task.query.filter_by(user_id=user.id).all()
    return jsonify([{
        'id': task.id,
        'name': task.name,
        'description': task.description,
        'status': task.status,
        'creation_date': task.creation_date,
        'finishing_date': task.finishing_date,
    } for task in tasks])


@app.route('/tasks', methods=['POST'])
@token_required
def create_task():
    try:
        # Get data from the request
        data = request.get_json()
        user_from_token = jwt.decode(request.headers['Authorization'].split(
            " ")[1], app.config['SECRET_KEY'], algorithms=["HS256"])['user']
        user = User.query.filter_by(username=user_from_token).first()

        # Convert finishing_date from string to datetime if it's present
        if 'finishing_date' in data:
            finishing_date_str = data['finishing_date']
            # Ensure the finishing_date is a valid datetime string and convert
            finishing_date = datetime.fromisoformat(
                finishing_date_str)  # Converts string to datetime
        else:
            finishing_date = None  # If there's no finishing date, it stays as None

        # Create the new task
        new_task = Task(
            name=data['name'],
            description=data['description'],
            creation_date=datetime.utcnow(),  # Using the current UTC time
            finishing_date=finishing_date,
            status=data['status'],
            user_id=user.id,
            category_id=data['category_id']
        )

        # Add the task to the session and commit
        db.session.add(new_task)
        db.session.commit()

        # Respond with a success message or task details
        return jsonify({'message': 'Task created successfully', 'task': new_task.id}), 201

    except Exception as e:
        # Handle any errors
        return jsonify({'error': str(e)}), 400


@app.route('/tasks/<int:task_id>', methods=['GET'])
@token_required
def get_task(task_id):
    user_from_token = jwt.decode(request.headers['Authorization'].split(
        " ")[1], app.config['SECRET_KEY'], algorithms=["HS256"])['user']
    user = User.query.filter_by(username=user_from_token).first()
    task = Task.query.get(task_id)
    if task.user_id != user.id:
        return jsonify({'message': 'Unauthorized!'}), 403
    return jsonify({
        'id': task.id,
        'name': task.name,
        'description': task.description,
        'status': task.status,
        'creation_date': task.creation_date,
        'finishing_date': task.finishing_date,
    })


@app.route('/tasks/<int:task_id>', methods=['PUT'])
@token_required
def update_task(task_id):
    data = request.json
    user_from_token = jwt.decode(request.headers['Authorization'].split(
        " ")[1], app.config['SECRET_KEY'], algorithms=["HS256"])['user']
    user = User.query.filter_by(username=user_from_token).first()
    task = Task.query.get(task_id)
    if task.user_id != user.id:
        return jsonify({'message': 'Unauthorized!'}), 403
    task.name = data.get('name', task.name)
    task.description = data.get('description', task.description)
    task.status = data.get('status', task.status)
    task.finishing_date = data.get('finishing_date', task.finishing_date)
    task.category_id = data.get('category_id', task.category_id)
    db.session.commit()
    return jsonify({'message': 'Task updated successfully!'}), 200


@app.route('/tasks/<int:task_id>', methods=['DELETE'])
@token_required
def delete_task(task_id):
    user_from_token = jwt.decode(request.headers['Authorization'].split(
        " ")[1], app.config['SECRET_KEY'], algorithms=["HS256"])['user']
    user = User.query.filter_by(username=user_from_token).first()
    task = Task.query.get(task_id)
    if task.user_id != user.id:
        return jsonify({'message': 'Unauthorized!'}), 403
    db.session.delete(task)
    db.session.commit()
    return jsonify({'message': 'Task deleted successfully!'}), 200


if __name__ == '__main__':
    app.run(debug=True)
