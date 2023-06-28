#from flask import Flask, jsonify
from flask import Blueprint, request,jsonify
from config.config import conexion
from flask_cors import CORS
from scapy.all import *
import datetime
from model.modelUser import crear_tabla
import threading
import time


sniffer_thread = None

app2_bp = Blueprint('app2', __name__)
CORS(app2_bp)


cursor = conexion.cursor()
crear_tabla()


# sql command to create table if it doesn't exist

add_all = ("INSERT INTO sniff(mac_src,ip_src, tam_src, fecha, hora) VALUES (%s, %s, %s, %s, %s)")

get_all = ("SELECT * FROM sniff")


# callback function - called for every packet
def traffic_monitor_callback(pkt):
    if "IP" in pkt:
        # sniff variables
        ip_src = pkt["IP"].src
        tam_ip_src = pkt["IP"].len     
        mac_src = pkt.src

        # get current date
        fecha = datetime.datetime.now().date()
        hora = datetime.datetime.now().time()

        # print on console the data got from the sniffers
        print(ip_src)
        print(tam_ip_src)
        print(mac_src)

        # commit the data to db
        cursor.execute(add_all, (mac_src, ip_src, tam_ip_src,  fecha, hora,))
        conexion.commit()


# create POST endpoint
def start_sniffer_thread():
    global sniffer_thread
    if sniffer_thread is None:
        sniffer_thread = threading.Thread(target=sniffer_function)
        sniffer_thread.start()

def stop_sniffer_thread():
    global sniffer_thread
    if sniffer_thread is not None:
        sniffer_thread.stop()
        sniffer_thread = None

def sniffer_function():
    try:
        sniff(prn=traffic_monitor_callback, store=0)
    except Exception as e:
        print("Error occurred while sniffing:", e)
        # If an error occurs, sleep for 10 seconds and then restart the sniffer
        time.sleep(10)
        sniffer_function()

# create POST endpoint
start_sniffer_thread()

# create POST endpoint
@app2_bp.route('/stop_sniffer', methods=['POST'])
def stop_sniffer():
    stop_sniffer_thread()
    return 'Sniffer stopped'

@app2_bp.route('/sniff', methods=['GET'])
def get_sniff():
    # get all data from the sniff table
    cursor.execute(get_all)
    data = cursor.fetchall()

    # convert data to JSON format
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


@app2_bp.route('/sniff/<fecha>', methods=['GET'])
def get_sniff_by_date(fecha):
    # get data from the sniff table for a specific date
    cursor.execute("SELECT * FROM sniff WHERE fecha = %s", (fecha,))
    data = cursor.fetchall()

    # convert data to JSON format
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

@app2_bp.route('/sniff/mac/<mac_src>', methods=['GET'])
def get_sniff_by_mac(mac_src):
    # get data from the sniff table for a specific mac_src
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