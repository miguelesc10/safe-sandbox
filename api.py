import requests
import json

'''
* FUNCIÓN: submit_file
* DESCRIPCIÓN: Envía a la sandbox un fichero para analizar mediante la API
* ARGS_IN:
    - file_path: Ruta del fichero a analizar
* ARGS_OUT:
    - analysis_id: ID del análisis
'''
def submit_file(file_path):
    
    file = open(file_path, 'rb')
    if file is None:
        return None
    
    url = "http://localhost:8000/apiv2/tasks/create/file/"
    
    files = {'file': file}
    
    # Petición a la API de CAPE Sandbox
    response = requests.post(url, files=files)
    file.close()

    # Procesa la respuesta del servicio
    response_json = response.json()

    if response_json['error']:
        return None

    # Obtiene el ID del análisis            
    analysis_id = response_json['data']['task_ids'][0]
    
    return analysis_id

'''
* FUNCIÓN: check_status
* DESCRIPCIÓN: Comprueba el estado de un análisis en la sandbox mediante la API
* ARGS_IN:
    - analysis_id: ID del análisis
* ARGS_OUT:
    - status: estado del análisis
''' 
def check_status(analysis_id):
    
    url = "http://localhost:8000/apiv2/tasks/status/"+str(analysis_id)
    
    # Petición a la API de CAPE Sandbox
    response = json.loads(requests.get(url).content)
    
    return response['data']

'''
* FUNCIÓN: get_json_report
* DESCRIPCIÓN: Obtiene los resultados del análisis y los guarda en formato .json
* ARGS_IN:
    - analysis_id: ID del análisis
* ARGS_OUT:
    - report_name: nombre del fichero guardado
''' 
def get_json_report(analysis_id):
    
    url = "http://localhost:8000/apiv2/tasks/get/report/"+str(analysis_id)
    
    # Petición a la API de CAPE Sandbox
    response = requests.get(url).json()

    report_name = str(analysis_id)+'.json'
    with open(report_name, 'w') as file:
        json.dump(response, file, indent=4)
    file.close()
    
    return report_name