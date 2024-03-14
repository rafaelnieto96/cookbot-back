from bson import ObjectId
from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended import JWTManager
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = '6efc1e00a12d49ee85512add1da18def'  # Cambia esto a una clave secreta segura
jwt = JWTManager(app)


client = MongoClient('mongodb://localhost:27017/')
db = client['cookbot']
recetas_collection = db['recipes']
usuarios_collection = db['users']

CORS(app, origins='*')

@app.route('/recipes/save', methods=['POST'])
def guardar_receta():
    datos_receta = request.json
    
    if 'user_id' not in datos_receta or 'title' not in datos_receta or 'description' not in datos_receta:
        return jsonify({'mensaje': 'Faltan campos obligatorios'}), 400
    
    receta_nueva = {
        'user_id': datos_receta['user_id'],
        'title': datos_receta['title'],
        'description': datos_receta['description']
    }
    recetas_collection.insert_one(receta_nueva)
    
    return jsonify({'mensaje': 'Receta guardada correctamente'}), 201

@app.route('/recipes', methods=['GET'])
def obtener_recetas():
    recetas = list(recetas_collection.find({}))
    
    for receta in recetas:
        receta['_id'] = str(receta['_id'])

    return jsonify(recetas), 200

@app.route('/recipes/<string:recipe_id>', methods=['GET'])
def obtener_receta_por_id(recipe_id):
    receta = recetas_collection.find_one({'_id': ObjectId(recipe_id)})
    
    if receta:
        receta['_id'] = str(receta['_id'])
        return jsonify(receta), 200
    else:
        return jsonify({'mensaje': 'Receta no encontrada'}), 404
    
@app.route('/register', methods=['POST'])
def registrar_usuario():
    datos_usuario = request.json
    
    if usuarios_collection.find_one({'username': datos_usuario['username']}):
        return jsonify({'mensaje': 'El usuario ya existe'}), 400
    
    datos_usuario['password'] = generate_password_hash(datos_usuario['password'])
    
    usuarios_collection.insert_one(datos_usuario)
    access_token = create_access_token(identity=datos_usuario, expires_delta=timedelta(days=1))
    return jsonify({'mensaje': 'Usuario registrado correctamente', 'access_token': access_token}), 201

@app.route('/login', methods=['POST'])
def iniciar_sesion():
    datos_login = request.json
    
    usuario = usuarios_collection.find_one({'username': datos_login['username']})
    
    if usuario and check_password_hash(usuario['password'], datos_login['password']):
        usuario['_id'] = str(usuario['_id'])
        access_token = create_access_token(identity=usuario, expires_delta=timedelta(days=1))
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'mensaje': 'Credenciales incorrectas'}), 401
    
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

if __name__ == '__main__':
    app.run(debug=True)
