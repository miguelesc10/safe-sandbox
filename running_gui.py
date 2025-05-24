import customtkinter as tk
from CTkMessagebox import CTkMessagebox
from api import check_status
from report import process_report 
import subprocess
import signal
from threading import Event, Thread
import time

class RunningAnalysis(tk.CTkFrame):
    def __init__(self, parent, controller, analysis_id=None):
        super().__init__(parent)
        self.controller = controller
        self.analysis_id = analysis_id

        # Evento para controlar la detención del hilo
        self.stop_event = Event()

        # Título de la pantalla
        self.title_label = tk.CTkLabel(self, text="Running analysis", font=("Arial", 25, "bold"))
        self.title_label.place(relx=0.5, rely=0.4, anchor=tk.CENTER)

        # Etiqueta para mostrar el ID del análisis
        self.text_label = tk.CTkLabel(self, text= "The sample is being analyzed. Please wait for the results.", font=("Arial", 14))
        self.text_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        self.analysis_id_label = tk.CTkLabel(self, text="", font=("Arial", 16))
        self.analysis_id_label.place(relx=0.5, rely=0.6, anchor=tk.CENTER)

        # Barra de progreso
        self.progressbar = tk.CTkProgressBar(self, mode="indeterminate")
        self.progressbar.place(relx=0.5, rely=0.7, anchor=tk.CENTER)
        self.progressbar.start()  

    '''
    * FUNCIÓN: set_analysis_id
    * DESCRIPCIÓN: Inicializa la ventana con el ID de análisis y comienza la captura de tráfico en el host
    * ARGS_IN:
        - analysis_id: ID del análisis
    '''
    def set_analysis_id(self, analysis_id):
        # Se actualizan los valores de ID análisis
        self.analysis_id = analysis_id
        self.analysis_id_label.configure(text="ID: "+str(analysis_id))
        
        # Comenienza la captura de tráfico en el host y la comprobación periódica del estado del análisis con la API de CAPE
        self.start_capture()
        self.check_status_periodic()
        

    '''
    * FUNCIÓN: check_status_periodic
    * DESCRIPCIÓN: Función para comprobar de forma periódica el estado de un análisis de la sandbox CAPE
    '''
    def check_status_periodic(self):
        
        status = check_status(self.analysis_id)  

        if status == "reported":
            # Si el estado es 200, detenemos la barra de progreso y mostramos que el análisis terminó
            self.stop_capture()

            self.progressbar.pack_forget()
            print("Se finaliza la captura")
            messagebox = CTkMessagebox(title="Process completed",message="Sample "+str(self.analysis_id)+" has been analyzed by the sandbox", 
                  icon="check", option_1="OK")
            print("Messagebox")
            subprocess.Popen(["firefox", process_report(analysis_id=self.analysis_id)])
            
            self.controller.show_frame("Home")


        else:
            # Si el estado no es 200, esperamos 10 segundos y verificamos nuevamente
            self.after(10000, self.check_status_periodic)  # Repetir la comprobación cada 10 segundos
    
    
    '''
    * FUNCIÓN: capture_packets
    * DESCRIPCIÓN: Función para capturar paquetes con tshark en un hilo
    '''
    def capture_packets(self):

        capture_name = str(self.analysis_id) +".pcap"
        
        # Captura en todas las interfaces
        command = ["tshark", "-i", "any", "-w", capture_name]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        try:
            while not self.stop_event.is_set():
                # Se mantiene el hilo activo mientras el evento no esté configurado el evento de parada
                time.sleep(3)
        except Exception as e:
            CTkMessagebox(title="Error", message="Error while monitoring the host. Capture has failed.", icon="cancel", option_1="OK")
        finally:
            # Envío de señal para detener tshark
            process.send_signal(signal.SIGINT)
            process.wait()

    '''
    * FUNCIÓN: start_capture
    * DESCRIPCIÓN: Función para iniciar el hilo de captura de paquetes
    '''
    def start_capture(self):
        self.stop_event.clear()
        thread = Thread(target=self.capture_packets, daemon=True)
        thread.start()

    '''
    * FUNCIÓN: stop_capture
    * DESCRIPCIÓN: Función para detener la captura de paquetes
    '''
    def stop_capture(self):
        self.stop_event.set()
