from flask import Blueprint, request, jsonify
from model.modelUserMaster import crear_tabla
from config.config import conexion
from flask_cors import CORS

# Create a Blueprint instance
app3_bp = Blueprint('app3', __name__)
# Create a cursor to interact with the database
cursor = conexion.cursor()
# Create the table if it does not exist
crear_tabla()
# Allow Cross-Origin Resource Sharing (CORS)
CORS(app3_bp)
# SQL query to get all data from the usersMaster table
get_all = ("SELECT * FROM usersMaster")

@app3_bp.route('/userMaster', methods=['POST'])
def crear_usuario():
    # Get the JSON data sent in the request
    datos_json = request.get_json()
    email = datos_json['email']
    password = datos_json['password']
    full_name = datos_json['full_name']
    phone = datos_json['phone']
    
    # Check if the email is already registered in the usersMaster table
    cursor.execute('SELECT * FROM users WHERE email=%s', (email,))
    registro_master = cursor.fetchone()
    if registro_master:
        # The email is already registered in the users table, respond with an error message
        response_data = {'mensaje': 'El email ya está registrado'}
        return jsonify(response_data), 409
    
    # Check if the email is already registered in the usersMaster table
    cursor.execute('SELECT * FROM usersMaster WHERE email=%s', (email,))
    registro = cursor.fetchone()
    if registro:
        # The email is already registered in the usersMaster table, respond with an error message
        response_data = {'mensaje': 'El email ya está registrado como usersMaster'}
        return jsonify(response_data), 409
    # Insert the data into the table
    cursor.execute('INSERT INTO usersMaster (email, password, full_name, phone) VALUES (%s, %s, %s, %s)', (email, password, full_name, phone))
    conexion.commit()
    
    # Respond with a success message
    response_data = {'mensaje': 'UserMaster creado con éxito'}
    return jsonify(response_data)
# Get all users from the usersMaster table
@app3_bp.route('/userMaster', methods=['GET'])
def get_users():
    # Execute the SQL query to get all data from the table
    cursor.execute(get_all)
    data = cursor.fetchall()

    # convert data to JSON format
    json_data = []
    for row in data:
        json_data.append({
        'id': row[0],
        'email': row[1],
        'password': row[2],
        'full_name': row[3],
        'phone': row[4]

        })
    return jsonify(json_data)

# Login a user in the usersMaster table
@app3_bp.route('/loginMaster', methods=['POST'])
def login():
    # Get the JSON data sent in the request
    datos_json = request.get_json()
    email = datos_json['email']
    password = datos_json['password']

    # Find the user in the usersMaster table
    cursor.execute('SELECT * FROM usersMaster WHERE email=%s', (email,))
    registro = cursor.fetchone()
    if not registro:
        # The email is not registered, respond with an error message
        return 'Correo electrónico o la contraseña son incorrectos', 401
    
    # Verify the password
    if registro[2] != password:
        # The password is incorrect, respond with an error message
        return 'Correo electrónico o la contraseña son incorrectos', 401
    
    # Crear un objeto con los datos del usuario
    user = {
        'id': registro[0],
        'email': registro[1],
        'full_name': registro[3],
        'phone': registro[4]
    }
    
    # Responder con el objeto del usuario
    return jsonify(user)


@app3_bp.route('/userMaster/<string:email>', methods=['PUT'])
def update_password_master(email):
    # Get the JSON data sent
    datos_json = request.get_json()
    new_password = datos_json['new_password']

# Search for the Master user in the table
    cursor.execute('SELECT * FROM usersMaster WHERE email=%s', (email,))
    registro = cursor.fetchone()
    if not registro:
    # The Master user is not registered, respond with an error message
        response_data = {'mensaje': 'El usuario maestro no existe'}
        return jsonify(response_data), 404
    
# Update the Master user's password
    cursor.execute('UPDATE usersMaster SET password=%s WHERE email=%s', (new_password, email))
    conexion.commit()

# Respond with a success message
    response_data = {'mensaje': 'Contraseña actualizada exitosamente'}
    return jsonify(response_data)
