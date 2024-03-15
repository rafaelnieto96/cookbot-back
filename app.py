import requests
import os
import random
import uuid

from bson import ObjectId
from flask import Flask, request, jsonify, session
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from flask_jwt_extended import JWTManager
from datetime import datetime, timedelta
from pymongo.errors import DuplicateKeyError
from dotenv import load_dotenv

load_dotenv()

GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
API_KEY = os.getenv("API_KEY")

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = '6efc1e00a12d49ee85512add1da18def'  # Cambia esto a una clave secreta segura
jwt = JWTManager(app)
app.secret_key = '123123'  # Reemplaza 'clave_secreta_para_la_session' con tu propia clave secreta


client = MongoClient('mongodb://localhost:27017/')
db = client['cookbot']
recetas_collection = db['recipes']
usuarios_collection = db['users']

CORS(app, origins='*')

@app.route('/recipes/save', methods=['POST'])
@jwt_required()
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
@jwt_required()
def obtener_recetas():
    user_id = get_jwt_identity().get('_id')
    
    user_object_id = ObjectId(user_id)

    recetas = list(recetas_collection.find({"user_id": str(user_object_id)}))

    for receta in recetas:
        receta['_id'] = str(receta['_id'])

    return jsonify(recetas), 200

@app.route('/recipes/<string:recipe_id>', methods=['GET'])
@jwt_required()
def obtener_receta_por_id(recipe_id):
    receta = recetas_collection.find_one({'_id': ObjectId(recipe_id)})
    
    if receta:
        receta['_id'] = str(receta['_id'])
        return jsonify(receta), 200
    else:
        return jsonify({'mensaje': 'Receta no encontrada'}), 404
    
@app.route('/user_recipes/<string:user_id>', methods=['GET'])
def obtener_recetas_por_usuario(user_id):
    recetas = list(recetas_collection.find({'user_id': user_id}))
    
    for receta in recetas:
        receta['_id'] = str(receta['_id'])

    return jsonify(recetas), 200

@app.route('/register', methods=['POST'])
def registrar_usuario():
    datos_usuario = request.json
    
    if usuarios_collection.find_one({'username': datos_usuario['username']}):
        return jsonify({'mensaje': 'El usuario ya existe'}), 400
    
    datos_usuario['password'] = generate_password_hash(datos_usuario['password'])
    
    result = usuarios_collection.insert_one(datos_usuario)
    datos_usuario['_id'] = str(result.inserted_id)
    # Convertir ObjectId a cadena
    datos_usuario['_id'] = str(result.inserted_id)
    try:
        access_token = create_access_token(identity=datos_usuario, expires_delta=timedelta(days=1))
        return jsonify({'access_token': access_token}), 201
    except DuplicateKeyError:
        return jsonify({'mensaje': 'Error al registrar el usuario: el nombre de usuario ya está en uso'}), 400
    
@app.route('/login', methods=['POST'])
def iniciar_sesion():
    datos_login = request.json
    
    usuario = usuarios_collection.find_one({'username': datos_login['username']})
    
    if usuario and check_password_hash(usuario['password'], datos_login['password']):
        session['username'] = usuario['username']
        usuario['_id'] = str(usuario['_id'])
        access_token = create_access_token(identity=usuario, expires_delta=timedelta(days=1))
        return jsonify({'access_token': access_token, 'username': usuario['username']}), 200
    else:
        return jsonify({'mensaje': 'Credenciales incorrectas'}), 401
    
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200

@app.route('/logout', methods=['GET'])
def cerrar_sesion():
    session.pop('username', None)
    return jsonify({'mensaje': 'Cierre de sesión exitoso'}), 200


@app.route('/save_recipe', methods=['GET'])
def save_recipe():
    user_id = get_jwt_identity().get('username')
    usuario = usuarios_collection.find_one({"username": user_id })
    receta_texto=request.json  #hay que recoger el dato de la respuesta del json de la receta, no se como lo envia la api
    if usuario:
        id_usuario = str(usuario["_id"])
        receta = {"id_usuario": id_usuario, "receta_texto": receta_texto} #esto aun no funciona
        recetas_collection.insert_one(receta)
        print("Receta insertada exitosamente.")
    else:
        print("Usuario no encontrado.")


@app.route('/generate_recipe', methods=['POST'])
@jwt_required()
def generate_recipe():
    ingredients = request.json.get('ingredients', [])
    
    if not ingredients:
        return jsonify({'mensaje': 'No se proporcionaron ingredientes'}), 400

    prompt = "Eres un experto cocinero. Generame una receta en la que se utilicen todos o algunos de estos ingredientes y ninguno más:\n" + "\n".join(ingredients)
    
    url = "https://ia-kong-dev.codingbuddy-4282826dce7d155229a320302e775459-0000.eu-de.containers.appdomain.cloud/aigen/llm/openai/rag/clients"
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': API_KEY
        }
    data = {
        "model": "gpt-35-turbo-0301",
        "uuid": generate_uuid(),
        "message": {
            "role": "user",
            "content": prompt
        },
        "index": str(generate_random_number()),
        "vectorization_model": "text-embedding-ada-002-1",
        "temperature": 0,
        "origin": "escueladata",
        "user": GMAIL_ADDRESS
    }

    try:
        response = requests.post(url, json=data, headers=headers)
        if response.status_code == 200:
            recipe = response.json()
            return jsonify(recipe), 200
        else:
            return jsonify({'mensaje': 'Error al generar la receta'}), 500
    except Exception as e:
        return jsonify({'mensaje': 'Error al conectarse con la IA generativa'}), 500

@app.route('/send_pdf', methods=['POST'])
def send_pdf_to_api():

    url = "https://ia-kong-dev.codingbuddy-4282826dce7d155229a320302e775459-0000.eu-de.containers.appdomain.cloud/api/plugin/any-client"
    headers = {
        'Content-Type': 'application/pdf',  # Specify content type as PDF
        'X-API-KEY': API_KEY
    }

    pdf_path = os.path.join(os.path.dirname(__file__), "Fragmentos_de_obras.pdf")
    print("existe o no", pdf_path)
    if not os.path.exists(pdf_path):
        print("El archivo PDF no existe.")
        return
    
    data = {
        "file": pdf_path,
        "index": str(generate_random_number()),
        "name": "",
        "description": "",
        "owner": "",
        "type": "pdf",
        "visibility": "private",
        "modelVectorization": "text-embedding-ada-002-1",
        "renderizarImagenes": "false",
        "vectorizarFile": "false",
    }

    try:
        response = requests.post(url, data=data, headers=headers)
        if response.status_code == 200:
            result = response.json()
            return result
        else:
            return {'mensaje': 'Error al enviar el PDF a la IA'}
    except Exception as e:
        print("Error:", e)
        return {'mensaje': 'Error al conectarse con la IA generativa'}




    
def generate_random_number():
    return random.randint(1, 3)

def generate_uuid():
    return str(uuid.uuid4().hex)[:10]

if __name__ == '__main__':
    app.run(debug=True)
