# Sistema de Analisis Constitucional de Normatividad en Inteligencia Artificial (I.J.U.R.I.S.)

Plataforma de analisis jurídico y de auditoría algorítmica para evaluar sistemas de Inteligencia Artificial frente a la Constitución Política de los Estados Unidos Mexicanos (CPEUM), leyes de privacidad y normativas internacionales de derechos humanos (EU AI Act, Recomendaciones UNESCO).

## Características Principales

- **Diagnóstico y Control de Convencionalidad**: Identificación automática de preceptos constitucionales vulnerados (Arts. 1, 6, 14, 16 CPEUM) y determinación de niveles de riesgo ético y algorítmico (Inadmisible, Alto, Medio, Bajo/Positivo).
- **Doble Motor de Inferencia**:
  - **Modo Nube (Groq API)**: Análisis mediante modelos LLM con latencia mínima.
  - **Modo Local (solo en el equipo que actua como servidor / Heurístico**: Compatibilidad con modelos locales (Ollama) o motor de inferencia jurídica determinista integrado.
- **Asistente Interactivo y Robot Guiado**: Interfaz moderna con visualización interactiva y menú de preguntas frecuentes sobre derechos humanos y normatividad.
- **Base de Datos y Seguridad**: Control de sesiones, auditoría (`normatividad_ia.db` autogenerada), hashing seguro con `bcrypt` y protección de rutas administrativas.


## Requisitos e Instalación Local

1. **Clonar o descargar el repositorio**:
   ```bash
   git clone <URL_DEL_REPOSITORIO>
   cd Asistente
   ```

2. **Crear y activar un entorno virtual (recomendado)**:
   ```bash
   python -m venv venv
   # En Windows:
   .\venv\Scripts\activate
   # En Linux/macOS:
   source venv/bin/activate
   ```

3. **Instalar dependencias**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configurar llave de Groq (Opcional para modo Nube)**:
   - Crear un archivo `.env` o definir la variable de entorno:
     ```env
     GROQ_API_KEY=tu_llave_de_groq_aqui (ejemplo)
     ```
   - O colocar la llave dentro de un archivo de texto llamado `api`.

5. **Ejecutar el servidor local**:
   ```bash
   python main.py
   ```
   O bien:
   ```bash
   uvicorn main:app --host 127.0.0.1 --port 8000 --reload
   ```
   Abre tu navegador en `http://localhost:8000`.


## Estructura del Proyecto

```text
├── Lawfice/              # Recursos estáticos (CSS, JS, imágenes, fuentes, librerías) uso e integracion de caracteristicas
├── ai_engine.py          # Motor de análisis constitucional, casos precargados y Groq
├── database.py           # Gestor de base de datos SQLite y auditoría forense
├── index.html            # Interfaz de usuario interactiva
├── main.py               # Servidor FastAPI y endpoints de la API REST
├── Procfile              # Comando de arranque para plataformas cloud (Render/Heroku)
├── render.yaml           # Plantilla de infraestructura como código (Blueprint) para Render
├── requirements.txt      # Dependencias de Python requeridas
├── .env.example          # Plantilla de variables de entorno
└── .gitignore            # Exclusión de archivos sensibles, bases de datos y cachés
```
