import customtkinter as tk
from customtkinter import filedialog
from CTkMessagebox import CTkMessagebox
from api import submit_file

class Home(tk.CTkFrame):
    def __init__(self, parent, controller):
        super().__init__(parent, width=1280, height=720)
        self.controller = controller

        # Título de la pantalla
        label = tk.CTkLabel(self, text="Safe Sandbox", font=("Arial", 25, "bold"))
        label.place(relx=0.5, rely=0.4, anchor=tk.CENTER)
        
        # Texto explicativo
        text_label = tk.CTkLabel(self, text="Please select a file to submit for analysis", font=("Arial", 14))
        text_label.place(relx=0.5, rely=0.5, anchor=tk.CENTER)
        
        # Botón para examinar archivos
        boton_examinar = tk.CTkButton(self, text="Explore", command=self.select_file)
        boton_examinar.place(relx=0.5, rely=0.6, anchor=tk.CENTER)
    
    '''
    * FUNCIÓN: select_file
    * DESCRIPCIÓN: Muestra la ventana para seleccionar la muestra a analizar
    '''
    def select_file(self):
        
        # Ventana de selección de archivo
        file_path = filedialog.askopenfilename(title="Please select a file to submit for analysis")
        if file_path:
            # Envía el archivo para análisis
            analysis_id = submit_file(file_path)
            if analysis_id:
                # Cambia a la pantalla de análisis, indicando el ID obtenido
                self.controller.show_frame("RunningAnalysis", analysis_id=analysis_id)
            else:
                CTkMessagebox(title="Error", message="Please try again", icon="cancel", option_1="OK")
