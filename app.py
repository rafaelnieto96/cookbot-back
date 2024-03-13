from flask import Flask, request, jsonify
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS

app = Flask(__name__)

client = MongoClient('mongodb://localhost:27017/')
db = client['cookbot']
recetas_collection = db['recipes']
usuarios_collection = db['users']

CORS(app)

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
    recetas = list(recetas_collection.find({}, {'_id': 0}))
    
    return jsonify(recetas), 200

@app.route('/registro', methods=['POST'])
def registrar_usuario():
    datos_usuario = request.json
    
    if usuarios_collection.find_one({'email': datos_usuario['email']}):
        return jsonify({'mensaje': 'El usuario ya existe'}), 400
    
    datos_usuario['password'] = generate_password_hash(datos_usuario['password'])
    
    usuarios_collection.insert_one(datos_usuario)
    
    return jsonify({'mensaje': 'Usuario registrado correctamente'}), 201

@app.route('/login', methods=['POST'])
def iniciar_sesion():
    datos_login = request.json
    
    usuario = usuarios_collection.find_one({'email': datos_login['email']})
    
    if usuario and check_password_hash(usuario['password'], datos_login['password']):
        usuario['_id'] = str(usuario['_id'])
        return jsonify({'mensaje': 'Inicio de sesión exitoso', 'usuario': usuario}), 200
    else:
        return jsonify({'mensaje': 'Credenciales incorrectas'}), 401

if __name__ == '__main__':
    app.run(debug=True)
