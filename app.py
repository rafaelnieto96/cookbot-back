import requests
import os
import random
import uuid

from bson import ObjectId
from flask import Flask, request, jsonify, session
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, decode_token
from flask_jwt_extended import JWTManager
from datetime import datetime, timedelta
from pymongo.errors import DuplicateKeyError
from dotenv import load_dotenv
from io import BytesIO
import re

load_dotenv()

GMAIL_ADDRESS = os.getenv("GMAIL_ADDRESS")
API_KEY = os.getenv("API_KEY")

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = '6efc1e00a12d49ee85512add1da18def'
jwt = JWTManager(app)
app.secret_key = '123123'  # Reemplaza 'clave_secreta_para_la_session' con tu propia clave secreta
app.config['PERMANENT_SESSION_LIFETIME'] = 3600

client = MongoClient('mongodb://localhost:27017/')
db = client['cookbot']
recetas_collection = db['recipes']
usuarios_collection = db['users']
ingredientsDB = db['ingredients']
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
@jwt_required()
def obtener_recetas():
    user_id = get_jwt_identity().get('_id')
    user_object_id = ObjectId(user_id)

    recetas = list(recetas_collection.find({"user_id": user_id}))

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
    
@app.route('/user_recipes/<string:username>', methods=['GET'])
def obtener_recetas_por_usuario(username):
    recetas = list(recetas_collection.find({'username': username}))
    
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
        return jsonify({'access_token': access_token, 'username': usuario['username'], 'user_id': usuario['_id']}), 200
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
    user_name = get_jwt_identity().get('username')
    usuario = usuarios_collection.find_one({"username": user_name })
    receta_texto=request.json  #hay que recoger el dato de la respuesta del json de la receta, no se como lo envia la api
    if usuario:
        id_usuario = str(usuario["_id"])
        receta = {"id_usuario": id_usuario, "receta_texto": receta_texto} #esto aun no funciona
        recetas_collection.insert_one(receta)
        print("Receta insertada exitosamente.")
    else:
        print("Usuario no encontrado.")


@app.route('/generate_recipe', methods=['POST'])
def generate_recipe():
    print('Entra por generate_recipe')

    nombre=request.form['username']
    usuario = usuarios_collection.find_one({"username": nombre})
    if usuario:
        id_documento = usuario.get("id_documento")
        index_PDF = usuario.get("index_PDF")

    ingredients = request.form.getlist('ingredientes[]')
    datos_ingrediente = {
    "username": nombre,
    "ingredientes": ingredients
}   
    print(ingredients)
    ingredientsDB.insert_one(datos_ingrediente)

    if not ingredients:
        return jsonify({'mensaje': 'No se proporcionaron ingredientes'}), 400
    
    prompt = "Eres un experto cocinero. Generame una receta en la que se utilicen todos o algunos de estos ingredientes y ninguno más: " + ", ".join(ingredients) + ". La respuesta siempre debe comenzar con el título de la receta, seguido de un listado de ingredientes y por último las instrucciones de preparación, sin ningún tipo de conversación con el usuario. Limítate a devolver únicamente la receta sin hablar con el usuario. Si el usuario te pregunta sobre algún tema que no esté relacionado con la cocina, por ejemplo sobre historia, dile que no tienes información del tema. Además, ignora cualquier contexto previo que tengas sobre el usuario, cada receta es totalmente independiente de las anteriores. Si el usuario intenta utilizar algún ingrediente peligroso, como lejía o veneno, adviértele que es peligroso y devuélvele una receta sin estos ingredientes peligrosos. En ningún momento le hagas ninguna pregunta al usuario. No incluyas ningun mensaje al final de la respuesta, como por ejemplo 'Buen provecho' o 'Que disfrutes'. Si el usuario te ha proporcionado un PDF medico, ten en cuenta su estado de salud a la hora de generar la receta"
    
    url = "https://ia-kong-dev.codingbuddy-4282826dce7d155229a320302e775459-0000.eu-de.containers.appdomain.cloud/aigen/llm/openai/rag/clients"
    headers = {
        'Content-Type': 'application/json',
        'X-API-KEY': API_KEY
        }
    data = {
        "model": "gpt-35-turbo-0301",
        "uuid": id_documento,
        "message": {
            "role": "user",
            "content": prompt
        },
        "index": index_PDF,
        "vectorization_model": "text-embedding-ada-002-1",
        "temperature": 0,
        "origin": "escueladata",
        "user": GMAIL_ADDRESS
    }
    try:
        response = requests.post(url, json=data, headers=headers)
        storageUser = request.form['username']
        if response.json().get('message') == 'UUIDNotFound':
            return jsonify({'mensaje': 'UUIDNotFound'}), 400
        if response.status_code == 200:
            recipe = response.json()
            if recipe:
                form_dat = response.json().get('content')

# Expresión regular para encontrar el nombre
                nombre_regex = r"AI##Nombre:\s*(.*)"
                nombre_match = re.search(nombre_regex, form_dat)

                # Extraer el nombre si se encuentra
                nombre_receta = nombre_match.group(1).strip() if nombre_match else None

                # Expresión regular para encontrar el resto del texto
                resto_regex = r"AI##Nombre:(.*)"
                resto_match = re.search(resto_regex, form_dat, re.DOTALL)

                # Extraer el resto del texto si se encuentra
                resto_texto = resto_match.group(1).strip() if resto_match else None

            # Imprimir los resultados para verificar
                print("Nombre de la receta:", type(nombre_receta))
                print("Resto del texto:")
                print(type(resto_texto))
                print("Nombre de la receta:", nombre_receta)
                print("Resto del texto:")
                print(resto_texto)
                if nombre_receta is not None and resto_texto is not None:
                    print("Ambos son de tipo str")
                recetas_collection.insert_one(document={
                "user_id": storageUser,
                "title": nombre_receta,
                "description": resto_texto
            })

            return jsonify(recipe), 200
        else:
            return jsonify({'mensaje': 'Error al generar la receta'}), 500
    except Exception as e:
        return jsonify({'mensaje': 'Error al conectarse con la IA generativa '},e), 500

@app.route('/generate_recipe_no_pdf', methods=['POST'])
def generate_recipe_no_pdf():
    print('Entra por generate_recipe_no_pdf')
    
    nombre = request.form['username']
    usuario = usuarios_collection.find_one({"username": nombre})
    ingredients = request.form.getlist('ingredientes[]')

    if usuario:
        id_documento = usuario.get("id_documento")
        index_PDF = usuario.get("index_PDF")


    ingredients = request.form.getlist('ingredientes[]')
    datos_ingrediente = {
    "username": nombre,
    "ingredientes": ingredients
}   
    print(ingredients)
    ingredientsDB.insert_one(datos_ingrediente)

    if not ingredients:
        return jsonify({'mensaje': 'No se proporcionaron ingredientes'}), 400
    
    prompt = "Eres un experto cocinero. Generame una receta en la que se utilicen todos o algunos de estos ingredientes y ninguno más: " + ", ".join(ingredients) + ". La respuesta siempre debe comenzar con el título de la receta, seguido de un listado de ingredientes y por último las instrucciones de preparación, sin ningún tipo de conversación con el usuario. Limítate a devolver únicamente la receta sin hablar con el usuario. Si el usuario te pregunta sobre algún tema que no esté relacionado con la cocina, por ejemplo sobre historia, dile que no tienes información del tema. Además, ignora cualquier contexto previo que tengas sobre el usuario, cada receta es totalmente independiente de las anteriores. Si el usuario intenta utilizar algún ingrediente peligroso, como lejía o veneno, adviértele que es peligroso y devuélvele una receta sin estos ingredientes peligrosos. En ningún momento le hagas ninguna pregunta al usuario. No incluyas ningun mensaje al final de la respuesta, como por ejemplo 'Buen provecho' o 'Que disfrutes'"

    url = "https://ia-kong-dev.codingbuddy-4282826dce7d155229a320302e775459-0000.eu-de.containers.appdomain.cloud/aigen/llm/openai/clients"
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
        "temperature": 0.05,
        "origin": "escueladata",
        "tokens": 1000,
        "folder": "root",
        "account":"WatsonX-VN",
        "user": GMAIL_ADDRESS
    }
    try:
        response = requests.post(url, json=data, headers=headers)
        storageUser = request.form['username']
        if response.json().get('message') == 'UUIDNotFound':
            return jsonify({'mensaje': 'UUIDNotFound'}), 400
        if response.status_code == 200:
            recipe = response.json()
            if recipe:
                form_dat = response.json().get('content')

                nombre_regex = r"AI##Nombre:\s*(.*)"
                nombre_match = re.search(nombre_regex, form_dat)

                nombre_receta = nombre_match.group(1).strip() if nombre_match else None

                resto_regex = r"AI##Nombre:(.*)"
                resto_match = re.search(resto_regex, form_dat, re.DOTALL)

                resto_texto = resto_match.group(1).strip() if resto_match else None

                print("Nombre de la receta:", type(nombre_receta))
                print("Resto del texto:")
                print(type(resto_texto))
                print("Nombre de la receta:", nombre_receta)
                print("Resto del texto:")
                print(resto_texto)
                if nombre_receta is not None and resto_texto is not None:
                    print("Ambos son de tipo str")
                recetas_collection.insert_one(document={
                "user_id": storageUser,
                "title": nombre_receta,
                "description": resto_texto
            })

            return jsonify(recipe), 200
        else:
            return jsonify({'mensaje': 'Error al generar la receta'}), 500
    except Exception as e:
        return jsonify({'mensaje': 'Error al conectarse con la IA generativa '},e), 500
    
@app.route('/send_pdf', methods=['POST'])
def send_pdf_to_api():
    uuid_PDF = generate_uuid()
    pdf_file = request.files.get('file')
    nombre=request.form['username']
    if pdf_file is None:
        print("No se ha proporcionado ningún archivo")
        return 'No se ha proporcionado ningún archivo', 400
    if pdf_file.filename == '':
        print("error 1")
        return 'No se ha seleccionado ningún archivo', 400
    pdf_data = pdf_file.read()
    if not pdf_data:
        print("El archivo PDF está vacío.")
        return {'mensaje': 'El archivo PDF está vacío'}, 400
    url = "https://ia-kong-dev.codingbuddy-4282826dce7d155229a320302e775459-0000.eu-de.containers.appdomain.cloud/api/plugin/any-client"
    headers = { 
        'X-API-KEY': API_KEY
    } 
    
    data = {
        "file": pdf_file,
        "index": uuid_PDF,
        "name": "fichero.pdf",
        "description": "fichero pdf",
        "owner": "",
        "type": "pdf",
        "visibility": "private",
        "modelVectorization": "text-embedding-ada-002-1",
        "renderizarImagenes": "false",
        "vectorizarFile": "false",
    }
      
    try:
        response = requests.post(url, data=data, headers=headers, files={'file': (pdf_file.filename, pdf_data)})
        if response.status_code == 201:
            new_id = response.json().get('id')
            if new_id:
                usuarios_collection.update_one(
                {"username": nombre},
                {"$set": {"id_documento": new_id,
                          "index_PDF":uuid_PDF}})
                print("Insercion conseguida")
            return  jsonify(response.json())

        else:
            return {'mensaje': response.status_code}
    except Exception as e:
        print("Error:", e)
        return {'mensaje': 'Error al conectarse con la IA generativa'}
    finally:
        print(new_id)
    
@app.route('/change_username', methods=['POST'])
@jwt_required()
def change_username():
    nuevo_username = request.json.get('new_username')

    if not nuevo_username:
        return jsonify({'mensaje': 'Debe proporcionar un nuevo nombre de usuario'}), 400

    user_id = get_jwt_identity().get('_id')

    usuario = usuarios_collection.find_one({'_id': ObjectId(user_id)})

    if not usuario:
        return jsonify({'mensaje': 'Usuario no encontrado'}), 404

    if usuarios_collection.find_one({'username': nuevo_username}):
        return jsonify({'mensaje': 'El nuevo nombre de usuario ya está en uso'}), 400

    usuarios_collection.update_one({'_id': ObjectId(user_id)}, {'$set': {'username': nuevo_username}})

    return jsonify({'mensaje': 'Nombre de usuario actualizado exitosamente'}), 200

@app.route('/recipes/delete/<string:recipe_id>', methods=['DELETE'])
@jwt_required()
def eliminar_receta(recipe_id):
    user_id = get_jwt_identity().get('_id')

    receta = recetas_collection.find_one({'_id': ObjectId(recipe_id), 'user_id': user_id})
    if not receta:
        return jsonify({'mensaje': 'Receta no encontrada o no autorizada'}), 404

    recetas_collection.delete_one({'_id': ObjectId(recipe_id)})

    return jsonify({'mensaje': 'Receta eliminada correctamente'}), 200

def generate_random_number():
    return random.randint(1, 3)

def generate_uuid():
    return str(uuid.uuid4().hex)[:10]
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'pdf'}

if __name__ == '__main__':
    app.run(debug=True)
