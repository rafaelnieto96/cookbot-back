import pymongo
import bcrypt


# Conexión a la base de datos MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["cookbot"]  

# Colección de usuarios, recetas y counters (ids autoincremental)
user_collection = db["users"]
recipes_collection = db["recipes"]

# Crear un índice único en el campo 'nombre' (ahora llamado 'username')
user_collection.create_index([("username", pymongo.ASCENDING)], unique=True)

# Función para insertar un usuario
def insertar_usuario(username, password):
    try:
        password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        user = {"username": username, "password": password_hash}
        user_collection.insert_one(user)
        print("Usuario insertado exitosamente.")
    except pymongo.errors.DuplicateKeyError:
        print("Ya existe un usuario con ese nombre de usuario.")
        
def verificar_contraseña(username, password):
    user = user_collection.find_one({"username": username})
    if user:
        # Verificar la contraseña hasheada
        if bcrypt.checkpw(password.encode('utf-8'), user["password"]):
            print("Contraseña correcta")
        else:
            print("Contraseña incorrecta")
    else:
        print("Usuario no encontrado")

        
# Función para insertar una receta
def insertar_receta(nombre_usuario, receta_texto):
    # Buscar el ID del usuario por su nombre
    usuario = user_collection.find_one({"username": nombre_usuario})
    
    if usuario:
        id_usuario = str(usuario["_id"])
        receta = {"id_usuario": id_usuario, "receta_texto": receta_texto}
        recipes_collection.insert_one(receta)
        print("Receta insertada exitosamente.")
    else:
        print("Usuario no encontrado.")


# Ejemplo de uso
#insertar_usuario("usuario1", "contraseña123")
#insertar_receta("usuario1", "Texto de la receta")
#verificar_contraseña("usuario1", "contraseña123")