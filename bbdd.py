import pymongo
import bcrypt


# Conexión a la base de datos MongoDB
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["cookbot"]  # Reemplaza "nombre_de_tu_base_de_datos" con el nombre real de tu base de datos

# Colección de usuarios, recetas y counters (ids autoincremental)
usuarios_collection = db["usuarios"]
recetas_collection = db["recetas"]

# Crear un índice único en el campo 'nombre' (ahora llamado 'username')
usuarios_collection.create_index([("username", pymongo.ASCENDING)], unique=True)

# Función para insertar un usuario
def insertar_usuario(username, contraseña):
    try:
        hash_contraseña = bcrypt.hashpw(contraseña.encode('utf-8'), bcrypt.gensalt())

        usuario = {"username": username, "contraseña": hash_contraseña}
        usuarios_collection.insert_one(usuario)
        print("Usuario insertado exitosamente.")
    except pymongo.errors.DuplicateKeyError:
        print("Ya existe un usuario con ese nombre de usuario.")
        
def verificar_contraseña(nombre_usuario, contraseña):
    usuario = usuarios_collection.find_one({"username": nombre_usuario})
    if usuario:
        # Verificar la contraseña hasheada
        if bcrypt.checkpw(contraseña.encode('utf-8'), usuario["contraseña"]):
            print("Contraseña correcta")
        else:
            print("Contraseña incorrecta")
    else:
        print("Usuario no encontrado")

        
# Función para insertar una receta
def insertar_receta(nombre_usuario, receta_texto):
    # Buscar el ID del usuario por su nombre
    usuario = usuarios_collection.find_one({"username": nombre_usuario})
    
    if usuario:
        id_usuario = str(usuario["_id"])
        receta = {"id_usuario": id_usuario, "receta_texto": receta_texto}
        recetas_collection.insert_one(receta)
        print("Receta insertada exitosamente.")
    else:
        print("Usuario no encontrado.")


# Ejemplo de uso
#insertar_usuario("usuario1", "contraseña12233")
#insertar_receta("usuario1", "Texto de la receta")
#verificar_contraseña("usuario1", "contraseña123")