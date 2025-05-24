import pyshark
import os
import json
from api import get_json_report

'''
* FUNCIÓN: get_sample_ip_info
* DESCRIPCIÓN: Obtiene las IP a las que se ha conectado la muestra, incluyendo sus países
* ARGS_IN:
    - report_data: contenido del informe .json de la sandbox
* ARGS_OUT:
    - ip_host: conjunto de IP destino
    - countries_host: conjunto de países
''' 
def get_sample_ip_info(report_data):

    ip_host = set()
    countries_host = set()

    for value in report_data['network']['hosts']:
        ip_host.add(value['ip'])
        countries_host.add(value['country_name'])

    return ip_host,countries_host

'''
* FUNCIÓN: get_malscore
* DESCRIPCIÓN: Obtiene la puntuación malscore de la muestra
* ARGS_IN:
    - report_data: contenido del informe .json de la sandbox
* ARGS_OUT:
    - malscore: puntuación asignada
''' 
def get_malscore(report_data):
    return report_data['malscore']

'''
* FUNCIÓN: get_malstatus
* DESCRIPCIÓN: Obtiene el tipo de muestra tras del análisis, según la naturaleza asignada por la sandbox
* ARGS_IN:
    - report_data: contenido del informe .json de la sandbox
* ARGS_OUT:
    - malstatus: texto sobre la naturaleza de la muestra
''' 
def get_malstatus(report_data):
    return report_data['malstatus']

'''
* FUNCIÓN: get_detection
* DESCRIPCIÓN: Obtiene el tipo de malware de la muestra si así es determinado por la sandbox
* ARGS_IN:
    - report_data: contenido del informe .json de la sandbox
* ARGS_OUT:
    - Si es capaz de determinar el tipo de malware, devuelve su familia. En caso contrario,
      devuelve una cadena vacía
''' 
def get_detection(report_data):
    if 'detections' in report_data.keys():
        if 'family' in report_data['detections'][0].keys():
            return report_data['detections'][0]['family']
    return ""

'''
* FUNCIÓN: get_behavior_summary
* DESCRIPCIÓN: Obtiene la información del comportamiento de la muestra
* ARGS_IN:
    - report_data: contenido del informe .json de la sandbox
* ARGS_OUT:
    - behavior_summary: diccionario con la información del comportamiento de la muestra
''' 
def get_behavior_summary(report_data):
    behavior_summary = {}

    switch={"files": "Involved files", "read_files": "Read files", 
            "write_files": "Written files", "delete_files": "Deleted files",
            "keys": "Involved registers", "read_keys": "Read registers",
            "write_keys": "Written registers", "delete_keys": "Deleted registers",
            "executed_commands": "Executed commands", "resolved_apis": "Used APIs",
            "mutexes": "Mutexes", "created_services": "Created services", 
            "started_services":"Executed services"}

    for key in report_data['behavior']['summary'].keys():
    
        if key in switch.keys():
            behavior_summary[switch[key]] = len(report_data['behavior']['summary'][key])
        else:
            behavior_summary[key] = len(report_data['behavior']['summary'][key])
    
    return behavior_summary

'''
* FUNCIÓN: get_signatures_description
* DESCRIPCIÓN: Obtiene la información de los principales hitos del análisis
* ARGS_IN:
    - report_data: contenido del informe .json de la sandbox
* ARGS_OUT:
    - signatures_description: lista de los principales hitos del análisis
'''
def get_signatures_description(report_data):
    signatures_description = []
    
    for i in range(len(report_data['signatures'])):
        signatures_description.append(report_data['signatures'][i]['description'])

    return signatures_description


'''
* FUNCIÓN: get_dst_ips
* DESCRIPCIÓN: Devuelve un conjunto con las IP destino de una captura .pcap
* ARGS_IN:
    - pcap_file: fichero .cap
* ARGS_OUT:
    - ip_dst: conjunto de IP destino
'''
def get_dst_ips(pcap_file):
    pcap = pyshark.FileCapture(pcap_file)

    ip_dst = set()
    try:
        for packet in pcap:
            ip_dst.add(packet.ip.dst)
        pcap.close()
    except AttributeError:
        pass

    return ip_dst

'''
* FUNCIÓN: html
* DESCRIPCIÓN: Procesa el contenido del informe HTML con la información del análisis
* ARGS_IN:
    - malscore: puntuación malscore
    - malstatus: malstatus
    - detection: tipo de muestra
    - num_ips_involved: número de IPs conectadas
    - num_countries_involved: número de países involucrados
    - signatures: principales hitos del análisis
    - isolation: información sobre el aislamiento de las conexiones
    - behavior_summary: información sobre el comportamiento de la muestra
* ARGS_OUT:
    - html_output: salida HTML del informe del análisis
'''

def html(malscore, malstatus, detection, num_ips_involved, num_countries_involved, signatures, isolation, behavior_summary):
    # Plantilla HTML con marcadores para los datos del análisis
    html_template = """
<!DOCTYPE html>
<html>

<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
        }}

        .section {{
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
            background-color: #F7F7F7
        }}

        .malicious {{
            background-color: #FFCDD2;
        }}

        .suspicious {{
            background-color: #FFE0B2;
        }}

        .clean {{
            background-color: #C8E6C9;
        }}

        .else {{
            background-color: #E0E0E0;
        }}

        .behavior-container {{
            column-count: 3;
            column-gap: 15px;
        }}

        .behavior-item {{
            break-inside: avoid-column;
        }}

        .flex-container {{
            display: flex;
        }}

        .flex-item {{
            flex: 1;
        }}

        .center {{
            text-align: center;
        }}
    </style>
</head>

<body>
    <div class="container">
        <div class="section {malstatus_class} center">
            <h1>Result: <span class="{malstatus_class}">{malstatus}</span></h1>
            <h2>Grade: {malscore}</h2>
            <h2>{detection}</h2>
        </div>
        <div class="section flex-container">
            <div class="flex-item">
                <h2>Summary: </h2>
                <p>{signatures}</p>
            </div>
            <div class="flex-item">
                <h2>Connections info:</h2>
                <p>Number of connected IP addresses: {num_ips_involved}</p>
                <p>Number of countries involved: {num_countries_involved}</p>
                <p><strong>{isolation}</strong></p>
            </div>
        </div>
        <div class="section">
            <h2>Behavior: </h2>
            <div class="behavior-container">
                <div class="behavior-summary">{behavior_summary}</div>
            </div>
        </div>
    </div>
</body>

</html>
"""

    # Se determina la clase en función del resultado
    if malstatus == None:
        malstatus_class = "clean"
    elif malstatus.lower() == "malicious":
        malstatus_class = "malicious"
    elif malstatus.lower() == "suspicious":
        malstatus_class = "suspicious"
    elif malstatus.lower() == "clean":
        malstatus_class = "clean"
    else:
        malstatus_class = "else"
    
    # Formateo de la información del comportamiento
    behavior_summary_html=""
    for key, value in behavior_summary.items():
        behavior_summary_html += f"<p>{key}: {value}</p>"

    # Reemplazo de los marcadores con los datos
    html_output = html_template.format(malscore=malscore, malstatus=malstatus, detection=detection,malstatus_class=malstatus_class, num_ips_involved=num_ips_involved, num_countries_involved=num_countries_involved, signatures='<br>'.join(signatures), isolation=isolation, behavior_summary=behavior_summary_html)
    
    return html_output


'''
* FUNCIÓN: process_report
* DESCRIPCIÓN: Procesa el informe implementado para el análisis
* ARGS_IN:
    - analysis_id: ID del análisis
* ARGS_OUT:
    - filename: nombre del fichero HTML del análisis
'''
def process_report(analysis_id):
    report_file = get_json_report(analysis_id=analysis_id)
    pcap = str(analysis_id)+".pcap"

    with open(report_file, 'r') as file:
            # Lectura del json proporcionado por CAPE
            report_data = json.load(file)
    file.close()
    
    # Host contactados por el malware y sus paises
    malware_ip_hosts, countries = get_sample_ip_info(report_data)

    # IP destino de la captura de tráfico del host
    ip_dst = get_dst_ips(pcap)
    
    # Intersección entre las IP destino del malware y las del host
    intersection = malware_ip_hosts.intersection(ip_dst)

    if len(intersection) == 0:
        isolation = "None malware traffic was carried out within the host"

    else:
        isolation="The following malware traffic has been carried out within the host: "
        for ip in intersection:
            isolation += ip +"<br>"

    #Procesamiento del informe HTML
    html_output = html(get_malscore(report_data), get_malstatus(report_data),get_detection(report_data) ,len(malware_ip_hosts),len(countries), 
        get_signatures_description(report_data), isolation, get_behavior_summary(report_data))
    
    filename = "info_"+str(analysis_id)+".html"
    
    # Guardar el contenido HTML en un archivo
    with open(os.path.join(os.getcwd(), filename), "w") as file:
        file.write(html_output)
    
    return filename