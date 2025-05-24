import customtkinter as tk
from home_gui import Home
from running_gui import RunningAnalysis

tk.set_appearance_mode("Dark")
tk.set_default_color_theme("green")

class App(tk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Safe Sandbox")
    
        # Contenedor para las pantallas
        self.container = tk.CTkFrame(self)
        self.container.pack(fill="both", expand=True)

        # Diccionario de pantallas
        self.frames = {}

        # Se inicializan las pantallas
        self.init_frames()

    
    '''
    * FUNCIÓN: init_frames
    * DESCRIPCIÓN: Inicializa las pantallas de la aplicación
    '''
    def init_frames(self):
        
        # Creación de las pantallas iniciales
        for F in (Home, RunningAnalysis):
            frame_name = F.__name__
            frame = F(parent=self.container, controller=self)
            self.frames[frame_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        # Mostrar la pantalla inicial
        self.show_frame("Home")

    '''
    * FUNCIÓN: show_frame
    * DESCRIPCIÓN: Muestra la ventana de la aplicación indicada
    * ARGS_IN:
        - frame: nombre de la ventana a mostrar al usuario
        - kwargs: argumentos adicionales (opcionales)
    '''
    def show_frame(self, frame_name, **kwargs):
        
        # Se muestra la ventana y se actualiza si hay parámetros
        frame = self.frames[frame_name]
        if frame_name == "RunningAnalysis" and "analysis_id" in kwargs:
            frame.set_analysis_id(kwargs["analysis_id"])

        
        frame.tkraise()


if __name__ == "__main__":
    app = App()
    app.mainloop()
