from flask import Blueprint, request, jsonify
from config.config import conexion
from flask_cors import CORS
from scapy.all import *
import datetime
from model.modelUser import crear_tabla
import threading
import time
import pandas as pd
import json
from telegram import Bot
from telegram.error import NetworkError, TelegramError
import logging
from flask import Flask
import requests

# Configura el token de autenticación del bot y el chat ID
TELEGRAM_TOKEN = '6232545267:AAEhKL6GQVHvlulgppjs5yH_H_iNZgCvX0w'
TELEGRAM_CHAT_ID = '1362637804'

sniffer_thread = None

app2_bp = Blueprint('app2', __name__)
CORS(app2_bp)


cursor = conexion.cursor()
crear_tabla()


# sql command to create table if it doesn't exist

add_all = ("INSERT INTO sniff(mac_src,ip_src, tam_src, fecha, hora) VALUES (%s, %s, %s, %s, %s)")

get_all = ("SELECT * FROM sniff")

def convert_json_to_csv(json_data, csv_filename):
    df = pd.DataFrame(json_data)
    df.to_csv(csv_filename, index=False)
    return csv_filename

def send_file_to_telegram(file_path):
    bot_token = '6232545267:AAEhKL6GQVHvlulgppjs5yH_H_iNZgCvX0w'
    chat_id = '1362637804'
    #const telegramUrl = `https://telegram.me/Snifferup_bot?text=${encodeURIComponent(data)}`;
    url = f'https://telegram.me/Snifferup_bot{bot_token}/sendDocument'
    params = {'chat_id': chat_id}

    with open(file_path, 'rb') as file:
        files = {'document': file}
        response = requests.post(url, params=params, files=files)

    if response.status_code == 200:
        print('Archivo enviado correctamente a Telegram')
    else:
        print('Error al enviar el archivo a Telegram')

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

"""@app2_bp.route('/sniff/csv/', methods=['GET'])
def get_sniff_by_mac_csv():
    cursor.execute("SELECT * FROM sniff")
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
    csv_filename = "C:\\Users\\pssbo\\OneDrive\\Documentos\\newneurona\\sniffer-estancia\\back1.1\\datos.csv"
    convert_json_to_csv(json_data, csv_filename)
    send_file_to_telegram(csv_filename)
    return f"Data saved in file {csv_filename} and sent to Telegram"""""


# ----------------------------------------------------------------------------
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders


def send_file_by_email(file_path, email_to, email_from, email_subject):
    # Configura los detalles del correo electrónico
    email_server = 'smtp.gmail.com'
    email_port = 587
    email_username = '211105@ids.upchiapas.edu.mx'
    email_password = '8t4jh1xZ6h139'


    # Crea el objeto MIMEMultipart
    message = MIMEMultipart()
    message['From'] = email_from
    message['To'] = email_to
    message['Subject'] = email_subject

    # Adjunta el archivo CSV al mensaje
    with open(file_path, 'rb') as file:
        attachment = MIMEBase('application', 'octet-stream')
        attachment.set_payload(file.read())
        encoders.encode_base64(attachment)
        attachment.add_header('Content-Disposition', f'attachment; filename={file_path}')
        message.attach(attachment)

    # Establece la conexión con el servidor SMTP y envía el correo electrónico
    try:
        server = smtplib.SMTP(email_server, email_port)
        server.starttls()
        server.login(email_username, email_password)
        server.sendmail(email_from, email_to, message.as_string())
        server.quit()
        print('Correo electrónico enviado correctamente')
    except smtplib.SMTPException as e:
        print('Error al enviar el correo electrónico:', str(e))

# Luego, en tu función existente, puedes llamar a la función send_file_by_email pasando la ruta del archivo CSV y los detalles del correo electrónico
@app2_bp.route('/sniff/csv/', methods=['GET'])
def get_sniff_by_mac_csv():
    cursor.execute("SELECT * FROM sniff")
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
    csv_filename = "C:\\Users\\pssbo\\OneDrive\\Documentos\\newneurona\\sniffer-estancia\\back1.1\\datos.csv"
    convert_json_to_csv(json_data, csv_filename)
    send_file_by_email(csv_filename, 'destinatario@example.com', 'remite@example.com', 'Archivo CSV')
    return f"Data saved in file {csv_filename} and sent by email"
