from datetime import datetime
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
import jwt
import datetime
from functools import wraps

# Inicialización de la aplicación y la base de datos
app = Flask(__name__)

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
    description = db.Column(db.String(200), nullable=False)
    creation_date = db.Column(db.DateTime, default=datetime)
    finishing_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey(
        'category.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('tasks', lazy=True))


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
    token = jwt.encode({'user': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30), 'still_valid': True},
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
    data = request.json
    user_from_token = jwt.decode(request.headers['Authorization'].split(
        " ")[1], app.config['SECRET_KEY'], algorithms=["HS256"])['user']
    user = User.query.filter_by(username=user_from_token).first()
    if 'finishing_date' in data and datetime.fromisoformat(data['finishing_date']) < datetime.now():
        return jsonify({'message': 'Finishing date cannot be in the past!'}), 400
    new_task = Task(
        name=data['name'],
        description=data['description'],
        status=data['status'],
        user_id=user.id,
        category_id=data['category_id'],
        finishing_date=data.get('finishing_date')
    )
    db.session.add(new_task)
    db.session.commit()
    return jsonify({'message': 'Task created successfully!'}), 201


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
