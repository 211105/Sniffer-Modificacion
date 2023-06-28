# sniffer-estancia



from flask import Blueprint, request, jsonify
from config.config import conexion
from flask_cors import CORS
from scapy.all import *
import datetime
import threading
import time

sniffer_thread = None

app2_bp = Blueprint('app2', __name__)
CORS(app2_bp)

cursor = conexion.cursor()

# SQL command to create table if it doesn't exist
crear_tabla_query = '''
    CREATE TABLE IF NOT EXISTS sniff (
        id INT AUTO_INCREMENT PRIMARY KEY,
        mac_src VARCHAR(20),
        ip_src VARCHAR(20),
        tam_src INT,
        fecha DATE,
        hora TIME
    )
'''

# Create the 'sniff' table if it doesn't exist
cursor.execute(crear_tabla_query)

# SQL commands for inserting and retrieving data
add_all = "INSERT INTO sniff(mac_src, ip_src, tam_src, fecha, hora) VALUES (%s, %s, %s, %s, %s)"
get_all = "SELECT * FROM sniff"

# Callback function - called for every packet
def traffic_monitor_callback(pkt):
    if "IP" in pkt:
        # Sniff variables
        ip_src = pkt["IP"].src
        tam_ip_src = pkt["IP"].len
        mac_src = pkt.src

        # Get current date and time
        fecha = datetime.datetime.now().date()
        hora = datetime.datetime.now().time()

        # Print the sniffed data
        print(ip_src)
        print(tam_ip_src)
        print(mac_src)

        # Commit the data to the database
        cursor.execute(add_all, (mac_src, ip_src, tam_ip_src, fecha, hora))
        conexion.commit()

# Start the sniffer thread
def start_sniffer_thread():
    global sniffer_thread
    if sniffer_thread is None:
        sniffer_thread = threading.Thread(target=sniffer_function)
        sniffer_thread.start()

# Stop the sniffer thread
def stop_sniffer_thread():
    global sniffer_thread
    if sniffer_thread is not None:
        sniffer_thread.stop()
        sniffer_thread = None

# Sniffer function
def sniffer_function():
    try:
        sniff(prn=traffic_monitor_callback, store=0)
    except Exception as e:
        print("Error occurred while sniffing:", e)
        # If an error occurs, sleep for 10 seconds and then restart the sniffer
        time.sleep(10)
        sniffer_function()

# Create POST endpoint to start the sniffer
start_sniffer_thread()

# Create POST endpoint to stop the sniffer
@app2_bp.route('/stop_sniffer', methods=['POST'])
def stop_sniffer():
    stop_sniffer_thread()
    return 'Sniffer stopped'

# Create GET endpoint to retrieve all sniff data
@app2_bp.route('/sniff', methods=['GET'])
def get_sniff():
    try:
        # Get all data from the sniff table
        cursor.execute(get_all)
        data = cursor.fetchall()

        # Convert data to JSON format
        json_data = []
        for row in data:
            json_data.append({
                'id': row[0],
                'mac_src': row[1],
                'ip_src': row[2],
                'tam_src': row[3],
                'fecha': str(row[4]),
                'hora': str(row[5])
            })
        return jsonify(json_data)
    except Exception as e:
        print(f"Error occurred: {str(e)}")
        return 'Se produjo un error en el servidor', 500

# Create GET endpoint to retrieve sniff data by date
@app2_bp.route('/sniff/<fecha>', methods=['GET'])
def get_sniff_by_date(fecha):
    try:
        # Get data from the sniff table for a specific date
        cursor.execute("SELECT * FROM sniff WHERE fecha = %s", (fecha,))
        data = cursor.fetchall()

        # Convert data to JSON format
        json_data = []
        for row in data:
            json_data.append({
                'id': row[0],
                'mac_src': row[1],
                'ip_src': row[2],
                'tam_src': row[3],
                'fecha': str(row[4]),
                'hora': str(row[5])
            })
        return jsonify(json_data)
    except Exception as e:
        print(f"Error occurred: {str(e)}")

# Create GET endpoint to retrieve sniff data by MAC address
@app2_bp.route('/sniff/mac/<mac_src>', methods=['GET'])
def get_sniff_by_mac(mac_src):
    cursor.execute("SELECT * FROM sniff WHERE mac_src = %s", (mac_src,))
    data = cursor.fetchall()
    json_data = []
    for row in data:
        json_data.append({
            'id': row[0],
            'mac_src': row[1],
            'ip_src': row[2],
            'tam_src': row[3],
            'fecha': str(row[4]),
            'hora': str(row[5])
        })
    return jsonify(json_data)
