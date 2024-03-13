from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

@app.route('/')
def index():
    return 'Hola desde Flask!'

@app.route('/test')
def test_connection():
    return jsonify({'message': '¡La conexión entre Angular y Flask funciona correctamente!'})

if __name__ == '__main__':
    app.run(debug=True)
