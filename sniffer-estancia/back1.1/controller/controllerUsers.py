from flask import Blueprint, request, jsonify
from model.modelUser import crear_tabla
from config.config import conexion
from flask_cors import CORS


app1_bp = Blueprint('app1', __name__)
# Establish connection to the database
cursor = conexion.cursor()
# Create the 'users' table if it doesn't exist
crear_tabla()
# Enable Cross-Origin Resource Sharing (CORS) for the blueprint
CORS(app1_bp)
# Query to retrieve all users from the 'users' table
get_all = ("SELECT * FROM users")
@app1_bp.route('/users', methods=['POST'])
def create_users():
    # Get the JSON data sent in the request
    datos_json = request.get_json()
    email = datos_json['email']
    password = datos_json['password']
    full_name = datos_json['full_name']
    phone = datos_json['phone']
    
    # Check if the email is already registered in the 'usersMaster' table
    cursor.execute('SELECT * FROM usersMaster WHERE email=%s', (email,))
    registro_master = cursor.fetchone()
    if registro_master:
        # The email is already registered in the 'usersMaster' table, respond with an error message
        response_data = {'mensaje': 'El email ya está registrado como usersMaster'}
        return jsonify(response_data), 409
    
    # Check if the email is already registered in the 'users' table
    cursor.execute('SELECT * FROM users WHERE email=%s', (email,))
    registro = cursor.fetchone()
    if registro:
        # The email is already registered in the 'users' table, respond with an error message
        response_data = {'mensaje': 'El email ya está registrado '}
        return jsonify(response_data), 409
    
    # Insert the data into the 'users' table
    cursor.execute('INSERT INTO users (email, password, full_name, phone) VALUES (%s, %s, %s, %s)', (email, password, full_name, phone))
    conexion.commit()
    
      # Respond with a success message
    response_data = {'mensaje': 'users creado correctamente'}
    return jsonify(response_data)

@app1_bp.route('/users', methods=['GET'])
def get_users():
    # get all data from the usuarios table
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


@app1_bp.route('/login', methods=['POST'])
def login():
    # Get the JSON data sent in the request
    datos_json = request.get_json()
    email = datos_json['email']
    password = datos_json['password']

    # Search for the user in the 'users' table
    cursor.execute('SELECT * FROM users WHERE email=%s', (email,))
    registro = cursor.fetchone()
    if not registro:
        # The email is not registered, respond with an error message
        return 'email o password incorrectos', 401
    
    # Verify the password
    if registro[2] != password:
        # The password is incorrect, respond with an error message
        return 'email o password incorrectos', 401
    
    # Create an object with the user's data
    users = {
        'id': registro[0],
        'email': registro[1],
        'full_name': registro[3],
        'phone': registro[4]
    }
    
    # Responder con el objeto del usuario
    return jsonify(users)

@app1_bp.route('/users/<int:id>', methods=['DELETE'])
def delete_users(id):
    # Find the user in the table
    cursor.execute('SELECT * FROM users WHERE id=%s', (id,))
    registro = cursor.fetchone()
    if not registro:
        # User is not registered, respond with an error message
        response_data = {'mensaje': 'El users no existe'}
        return jsonify(response_data), 404
    
    # Delete the user from the table
    cursor.execute('DELETE FROM users WHERE id=%s', (id,))
    conexion.commit()

    # Respond with a success message
    response_data = {'mensaje': 'users eliminado correctamente'}
    return jsonify(response_data)

@app1_bp.route('/users/<string:email>', methods=['PUT'])
def actualizar_password(email):
    # Get the JSON data sent
    datos_json = request.get_json()
    new_password = datos_json['new_password']

# Find the user in the table
    cursor.execute('SELECT * FROM users WHERE email=%s', (email,))
    registro = cursor.fetchone()
    if not registro:
    # User is not registered, respond with an error message
        response_data = {'mensaje': 'El users no existe'}
        return jsonify(response_data), 404
    
# Update the user's password
    cursor.execute('UPDATE users SET password=%s WHERE email=%s', (new_password, email))
    conexion.commit()

# Respond with a success message
    response_data = {'mensaje': 'password actualizada correctamente'}
    return jsonify(response_data)
