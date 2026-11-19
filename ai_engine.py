import os
import re
import json
import time
import httpx
from typing import Dict, Any, List, Optional

# ==============================================================================
# CONFIGURACIÓN DE LLAVE GROQ Y CONSTANTES
# ==============================================================================
def get_groq_api_key() -> str:
    key = os.getenv("GROQ_API_KEY", "").strip()
    if not key and os.path.exists("api"):
        try:
            with open("api", "r", encoding="utf-8") as f:
                key = f.read().strip()
        except Exception:
            pass
    if not key and os.path.exists(".env"):
        try:
            from dotenv import load_dotenv
            load_dotenv()
            key = os.getenv("GROQ_API_KEY", "").strip()
        except Exception:
            pass
    return key

# Catálogo completo de casos precargados (Vulneraciones, Riesgos y Casos Éticos)
CASOS_EJEMPLO = [
    {
        "id": "caso_1",
        "tipo": "vulnera",
        "categoria": "Vigilancia Biométrica Masiva",
        "titulo": "1. Reconocimiento Facial en Tiempo Real en Transporte Público",
        "descripcion": "Un gobierno municipal instala cámaras con IA de reconocimiento facial en tiempo real en todas las estaciones del metro y paradas de autobuses para identificar ciudadanos con multas administrativas o de tránsito pendientes, cruzando imágenes biométricas con redes sociales y registros civiles sin orden judicial ni aviso de privacidad previo."
    },
    {
        "id": "caso_2",
        "tipo": "vulnera",
        "categoria": "Discriminación Algorítmica",
        "titulo": "2. Filtro de Reclutamiento con Sesgo por Género, Edad y Código Postal",
        "descripcion": "Una corporación financiera utiliza un modelo de IA para preseleccionar candidatos a puestos directivos. El algoritmo descarta automáticamente a mujeres en edad reproductiva, postulantes mayores de 40 años y residentes de códigos postales de bajo nivel socioeconómico, sin que exista supervisión o posibilidad de apelación humana."
    },
    {
        "id": "caso_3",
        "tipo": "vulnera",
        "categoria": "Justicia Penal y Debido Proceso",
        "titulo": "3. Algoritmo Predictivo de Reincidencia Penal para Prisión Preventiva",
        "descripcion": "Un tribunal implementa un software de IA privativo que calcula una puntuación de riesgo de reincidencia delictiva para determinar la imposición de prisión preventiva justificada. La defensa técnica no tiene acceso al código fuente ni a las variables analizadas, y el juez adopta el dictamen algorítmico sin motivación fáctica independiente."
    },
    {
        "id": "caso_4",
        "tipo": "vulnera",
        "categoria": "Democracia y Desinformación",
        "titulo": "4. Campaña Electoral con Deepfakes Hiperrealistas y Clonación de Voz",
        "descripcion": "Un partido político difunde en redes sociales videos sintéticos (deepfakes) con clonación de voz de candidatos opositores declarando falsamente la renuncia a su postulación dos días antes de las elecciones generales, sin etiquetado de contenido generado por IA ni marcas de agua perceptibles."
    },
    {
        "id": "caso_5",
        "tipo": "positivo",
        "categoria": "Salud y Beneficio Social",
        "titulo": "5. Diagnóstico de Retinopatía Diabética Asistido por IA con Supervisión Médica",
        "descripcion": "Un hospital público utiliza un modelo de IA auditado contra sesgos étnicos para analizar imágenes de fondo de ojo en zonas rurales. Los pacientes firman un consentimiento informado detallado, los datos son anonimizados en servidores locales seguros y el diagnóstico final siempre es validado y firmado por un oftalmólogo certificado."
    },
    {
        "id": "caso_6",
        "tipo": "positivo",
        "categoria": "Educación e Inclusión Cultural",
        "titulo": "6. Asistente Educativo Multilingüe en Lenguas Indígenas con Código Abierto",
        "descripcion": "Una universidad pública desarrolla un asistente de IA local de código abierto para traducir contenidos pedagógicos y científicos a náhuatl, maya y otomí. El sistema opera localmente sin recopilar datos personales de menores, cita las fuentes bibliográficas y respeta la propiedad intelectual y cultural de las comunidades."
    },
    {
        "id": "caso_7",
        "tipo": "riesgo",
        "categoria": "Servicios Financieros Esenciales",
        "titulo": "7. Scoring Crediticio Automatizado con Análisis de Comportamiento Digital",
        "descripcion": "Una entidad bancaria implementa un modelo de scoring crediticio que evalúa hábitos de navegación web y marcas de teléfonos móviles para aprobar o rechazar créditos hipotecarios. Aunque no discrimina explícitamente por raza, rechaza sistemáticamente perfiles atípicos sin brindar una justificación clara al usuario."
    },
    {
        "id": "caso_8",
        "tipo": "vulnera",
        "categoria": "Protección de la Niñez y Educación",
        "titulo": "8. Monitoreo Biométrico Emocional de Alumnos en Clases Virtuales",
        "descripcion": "Una plataforma de educación privada incorpora un sistema de visión artificial que monitorea los microgestos faciales y la dilatación pupilar de niños y adolescentes durante exámenes virtuales para calcular niveles de estrés y atención, almacenando los perfiles biométricos en la nube sin autorización parental expresa."
    }
]

# ==============================================================================
# DETECCIÓN DE TIPO DE CONSULTA: CONCEPTUAL VS CASO PRÁCTICO
# ==============================================================================
def es_pregunta_conceptual(texto: str) -> bool:
    """
    Detecta si el usuario está realizando una consulta conceptual, pedagógica o ciudadana
    sobre derechos humanos, artículos constitucionales o garantías legales,
    en lugar de presentar un caso fáctico de auditoría de un algoritmo.
    """
    t = texto.lower().strip()
    patrones = [
        "¿que son", "¿qué son", "que son los derechos", "qué son los derechos",
        "que son derechos", "qué son derechos", "definicion", "definición",
        "concepto de", "¿que es", "¿qué es", "que es la", "qué es la",
        "que es el", "qué es el", "explica", "explicame", "explícame",
        "dime que", "dime qué", "como funcionan", "cómo funcionan",
        "articulo 16", "artículo 16", "art. 16", "art 16",
        "articulo 1", "artículo 1", "art. 1", "art 1",
        "articulo 14", "artículo 14", "art. 14", "art 14",
        "articulo 20", "artículo 20", "art. 20", "art 20",
        "articulo 6", "artículo 6", "art. 6", "art 6",
        "articulo 4", "artículo 4", "art. 4", "art 4",
        "derechos humanos", "derecho a la privacidad", "datos personales",
        "presuncion de inocencia", "presunción de inocencia", "debido proceso",
        "que dice la constitucion", "qué dice la constitución",
        "cuales son mis derechos", "cuáles son mis derechos",
        "no discriminacion", "no discriminación", "igualdad ante la ley",
        "derechos arco", "libertad de expresion", "libertad de expresión"
    ]
    if t.startswith("¿") or (("?" in t) and len(t.split()) <= 20):
        return True
    return any(p in t for p in patrones)

def identificar_caso(descripcion_caso: str) -> Dict[str, Any]:
    """
    Detecta si la descripción corresponde a uno de los casos ejemplo predefinidos,
    a una consulta pedagógica/ciudadana o extrae un título descriptivo y conciso para la bitácora.
    """
    desc_norm = descripcion_caso.lower().strip()

    # 1. Comparar con los casos de ejemplo precargados
    for c in CASOS_EJEMPLO:
        c_desc = c["descripcion"].lower().strip()
        c_tit = c["titulo"]
        # Coincidencia por título o por fragmento de descripción inicial
        if c_tit.lower() in desc_norm or c_desc[:65] in desc_norm or desc_norm[:65] in c_desc:
            return {
                "id": c["id"],
                "titulo": c["titulo"],
                "categoria": c["categoria"],
                "es_ejemplo": True,
                "es_conceptual": False
            }

    # 2. Si es una consulta conceptual de derechos humanos o constitución
    if es_pregunta_conceptual(desc_norm):
        if "16" in desc_norm or "privacidad" in desc_norm or "datos" in desc_norm:
            tit = "Consulta: Artículo 16 CPEUM (Privacidad y Protección de Datos frente a IA)"
            cat = "Privacidad y Datos Personales"
        elif "14" in desc_norm or "20" in desc_norm or "inocencia" in desc_norm or "debido proceso" in desc_norm or "juez" in desc_norm:
            tit = "Consulta: Debido Proceso y Presunción de Inocencia ante Algoritmos"
            cat = "Justicia y Debido Proceso"
        elif "1" in desc_norm or "discriminaci" in desc_norm or "igualdad" in desc_norm:
            tit = "Consulta: Artículo 1° CPEUM (Igualdad y No Discriminación Algorítmica)"
            cat = "Igualdad y No Discriminación"
        elif "6" in desc_norm or "7" in desc_norm or "expresi" in desc_norm or "informaci" in desc_norm:
            tit = "Consulta: Artículos 6° y 7° CPEUM (Libertad de Expresión y Veracidad)"
            cat = "Libertad de Expresión e Información"
        else:
            tit = "Consulta: Definición y Principios de los Derechos Humanos en México"
            cat = "Derechos Humanos Fundamentales"

        return {
            "id": "consulta_conceptual",
            "titulo": tit,
            "categoria": cat,
            "es_ejemplo": False,
            "es_conceptual": True
        }

    # 3. Si no es un ejemplo predefinido, generar un título a partir de los hechos
    lineas = [l.strip() for l in descripcion_caso.strip().split("\n") if l.strip()]
    primera_linea = lineas[0] if lineas else "Auditoría de Algoritmo"

    if 5 < len(primera_linea) <= 65:
        tit = primera_linea
    else:
        palabras = primera_linea.split()
        tit = " ".join(palabras[:8]) + ("..." if len(palabras) > 8 else "")

    if not tit.lower().startswith("caso"):
        tit = f"Caso: {tit}"

    return {
        "id": "caso_particular",
        "titulo": tit,
        "categoria": "Evaluación de Algoritmo",
        "es_ejemplo": False,
        "es_conceptual": False
    }

# Prompt optimizado con lenguaje accesible de México, sin tecnicismos barrocos y con soporte a preguntas pedagógicas
SYSTEM_PROMPT = """Eres un Asistente y Asesor Jurídico Especialista en Derechos Humanos y Normatividad de Inteligencia Artificial en México.
Tu labor es orientar a ciudadanos, estudiantes y profesionistas con rigor constitucional pero en un español latino (mexicano) claro, directo, empático y libre de tecnicismos excesivos o palabras rebuscadas (no utilices términos barrocos como "ponderación lexicológica", "exégesis hermenéutica", "tutela iusfundamental", "dimensión ontológica" o "infracción prima facie").

DIFERENCIACIÓN SEGÚN EL TIPO DE ENTRADA:

1. SI EL USUARIO HACE UNA PREGUNTA CONCEPTUAL (ej. "¿Qué son los derechos humanos?", "¿Qué dice el artículo 16 sobre privacidad e IA?", "¿Qué es la presunción de inocencia?"):
   - "titulo_caso": Título claro y conciso de la consulta.
   - "diagnostico_factico": DEFINICIÓN CLARA Y DIRECTA en español mexicano accesible: explica el concepto de manera comprensible, para qué sirve y por qué protege a todas las personas.
   - "veredicto": "CONSULTA CONCEPTUAL RESUELTA (DERECHO HUMANO FUNDAMENTAL)".
   - "nivel_riesgo_eu": "Protección Constitucional Máxima (Art. 1° CPEUM)".
   - "puntuacion_etica": 100.
   - "derechos_involucrados": Lista de artículos de la CPEUM aplicables (ej. "Art. 1° CPEUM (Dignidad Humana y No Discriminación)", "Art. 16 CPEUM (Privacidad y Protección de Datos Personales)").
   - "justificacion_nacional": Fundamentación en la Constitución Política de los Estados Unidos Mexicanos (CPEUM), la Suprema Corte (SCJN) y la CNDH. OBLIGATORIAMENTE incluye una sección clara con EJEMPLOS PRÁCTICOS DE LA VIDA COTIDIANA EN MÉXICO (ej. en el trabajo, la escuela, el banco o la calle) y EJEMPLOS DEL IMPACTO DE LA INTELIGENCIA ARTIFICIAL (ej. cámaras de reconocimiento facial en el metro, algoritmos que niegan créditos o descartan currículums) para justificar y evidenciar la importancia de este derecho.
   - "justificacion_internacional": Fundamentación en tratados internacionales ratificados por México (Pacto de San José / CADH, Declaración Universal de DDHH y Recomendación de la UNESCO sobre la Ética de la IA 2021).
   - "medidas_y_recomendaciones": Consejos y acciones prácticas para la ciudadanía (cómo ejercer Derechos ARCO ante empresas o apps, cómo presentar una queja ante la CNDH o denuncia ante el INAI, y cuándo procede el Juicio de Amparo).

2. SI EL USUARIO PRESENTA UN CASO PRÁCTICO O SISTEMA DE IA PARA AUDITAR:
   - "titulo_caso": Título representativo del caso evaluado.
   - "diagnostico_factico": Diagnóstico claro en lenguaje accesible de lo que hace el algoritmo y cómo afecta los derechos de las personas.
   - "veredicto": "VULNERA DERECHOS HUMANOS | RIESGO CONDICIONAL / MITIGABLE | NO VULNERA (PRÁCTICA POSITIVA Y ÉTICA)".
   - "nivel_riesgo_eu": "Riesgo Inaceptable (Prohibido) | Alto Riesgo | Riesgo Limitado | Riesgo Mínimo".
   - "puntuacion_etica": Calificación numérica de 0 a 100.
   - "derechos_involucrados": Lista de garantías de la CPEUM afectadas o respetadas.
   - "justificacion_nacional": Explicación fundamentada en la CPEUM y criterios de la SCJN en lenguaje claro de México, justificando con ejemplos las consecuencias para los ciudadanos.
   - "justificacion_internacional": Fundamentos según el Reglamento Europeo de IA (EU AI Act) y UNESCO 2021.
   - "medidas_y_recomendaciones": Medidas de remediación y buenas prácticas concretas (supervisión humana vinculante, aviso de privacidad integral, auditorías de sesgos).

Responde ÚNICAMENTE con un objeto JSON válido con esta estructura exacta:
{
  "titulo_caso": "Título sintético y representativo",
  "diagnostico_factico": "Definición pedagógica o diagnóstico fáctico claro en español de México accesible.",
  "veredicto": "CONSULTA CONCEPTUAL RESUELTA (DERECHO HUMANO FUNDAMENTAL) | VULNERA DERECHOS HUMANOS | RIESGO CONDICIONAL / MITIGABLE | NO VULNERA (PRÁCTICA POSITIVA Y ÉTICA)",
  "nivel_riesgo_eu": "Protección Constitucional Máxima (Art. 1° CPEUM) | Riesgo Inaceptable (Prohibido) | Alto Riesgo | Riesgo Limitado | Riesgo Mínimo",
  "puntuacion_etica": 100,
  "derechos_involucrados": ["Art. 1° CPEUM...", "Art. 16 CPEUM..."],
  "justificacion_nacional": "Fundamentación legal con artículos de la CPEUM, criterios de la Suprema Corte (SCJN) y ejemplos prácticos de la vida cotidiana y de IA.",
  "justificacion_internacional": "Fundamentación en tratados internacionales (CADH, UNESCO Ética de la IA 2021, EU AI Act).",
  "medidas_y_recomendaciones": ["Consejo o medida 1", "Consejo o medida 2", "Consejo o medida 3"]
}"""

# ==============================================================================
# PARSER ROBUSTO DE JSON
# ==============================================================================
def extraer_json_valido(texto_crudo: str, descripcion_caso: str = "") -> Dict[str, Any]:
    if not texto_crudo or not isinstance(texto_crudo, str):
        raise ValueError("El modelo retornó una respuesta vacía o no estructurada.")

    limpio = texto_crudo.strip()

    # 1. Intento directo
    try:
        data = json.loads(limpio)
        if isinstance(data, dict):
            return normalizar_dictamen(data, descripcion_caso)
    except Exception:
        pass

    # 2. Bloque de código Markdown
    patron_bloque = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", limpio, re.IGNORECASE)
    if patron_bloque:
        candidato = patron_bloque.group(1).strip()
        try:
            data = json.loads(candidato)
            if isinstance(data, dict):
                return normalizar_dictamen(data, descripcion_caso)
        except Exception:
            pass

    # 3. Delimitadores exteriores { ... }
    inicio = limpio.find("{")
    fin = limpio.rfind("}")
    if inicio != -1 and fin != -1 and fin > inicio:
        candidato = limpio[inicio : fin + 1]
        try:
            data = json.loads(candidato)
            if isinstance(data, dict):
                return normalizar_dictamen(data, descripcion_caso)
        except Exception:
            candidato_sin_comas = re.sub(r",\s*([\]}])", r"\1", candidato)
            candidato_sin_comas = candidato_sin_comas.replace("“", "\"").replace("”", "\"")
            try:
                data = json.loads(candidato_sin_comas)
                if isinstance(data, dict):
                    return normalizar_dictamen(data, descripcion_caso)
            except Exception:
                pass

    raise ValueError(f"Imposible parsear JSON de la respuesta: {limpio[:200]}...")

def normalizar_dictamen(d: Dict[str, Any], descripcion_caso: str = "") -> Dict[str, Any]:
    info_caso = identificar_caso(descripcion_caso) if descripcion_caso else {
        "id": "caso_particular",
        "titulo": "Caso Forense de IA",
        "categoria": "Evaluación Pericial",
        "es_ejemplo": False,
        "es_conceptual": False
    }

    es_conc = info_caso.get("es_conceptual", False) or es_pregunta_conceptual(descripcion_caso)
    titulo = str(d.get("titulo_caso") or info_caso.get("titulo") or ("Consulta Ciudadana Constitucional" if es_conc else "Caso Forense de IA")).strip()

    # Diagnóstico fáctico: garantiza observaciones completas de los hechos reales o explicación conceptual clara
    resumen = str(d.get("diagnostico_factico") or d.get("resumen_hechos") or "").strip()
    if not resumen or resumen.lower() in ["sin observaciones", "sin observaciones.", "--", "n/a"]:
        if descripcion_caso:
            if es_conc:
                resumen = f"Explicación ciudadana sobre la consulta planteada:\n{descripcion_caso}"
            else:
                resumen = f"Análisis y revisión legal sobre los hechos declarados:\n{descripcion_caso}"
        else:
            resumen = "Hechos evaluados y ponderados conforme a la doctrina constitucional y los estándares éticos de Inteligencia Artificial."

    veredicto = str(d.get("veredicto") or ("CONSULTA CONCEPTUAL RESUELTA (DERECHO HUMANO FUNDAMENTAL)" if es_conc else "RIESGO CONDICIONAL / MITIGABLE")).strip()
    if es_conc and "VULNERA" not in veredicto.upper() and ("RIESGO" in veredicto.upper() or "INFRACCIÓN" in veredicto.upper()):
        veredicto = "CONSULTA CONCEPTUAL RESUELTA (DERECHO HUMANO FUNDAMENTAL)"

    nivel_riesgo = str(d.get("nivel_riesgo_eu") or d.get("nivel_riesgo_etico") or ("Protección Constitucional Máxima (Art. 1° CPEUM)" if es_conc else "Alto Riesgo")).strip()
    if es_conc and nivel_riesgo in ["Alto Riesgo", "Riesgo Condicional", "Riesgo Inaceptable"]:
        nivel_riesgo = "Protección Constitucional Máxima (Art. 1° CPEUM)"

    puntuacion = d.get("puntuacion_etica")
    try:
        puntuacion = int(puntuacion)
        puntuacion = max(0, min(100, puntuacion))
    except Exception:
        if es_conc or "CONCEPTUAL" in veredicto.upper() or "FUNDAMENTAL" in veredicto.upper():
            puntuacion = 100
        elif "NO VULNERA" in veredicto.upper():
            puntuacion = 90
        elif "VULNERA" in veredicto.upper():
            puntuacion = 20
        else:
            puntuacion = 55

    derechos = d.get("derechos_involucrados") or d.get("articulos_constitucion_violados") or []
    if isinstance(derechos, str):
        derechos = [derechos]
    elif not isinstance(derechos, list) or len(derechos) == 0:
        if es_conc:
            derechos = [
                "Principio Pro Persona y Dignidad Humana (Art. 1° CPEUM)",
                "Privacidad y Protección de Datos Personales (Art. 16 CPEUM)",
                "Seguridad Jurídica y Debido Proceso (Arts. 14 y 16 CPEUM)"
            ]
        else:
            derechos = [
                "Privacidad y Protección de Datos Personales (Art. 16 CPEUM)",
                "Principio Pro Persona y Dignidad Humana (Art. 1° CPEUM)"
            ]

    just_nac = str(d.get("justificacion_nacional", "")).strip() or "Fundamentado en los preceptos de la Constitución Política de los Estados Unidos Mexicanos (CPEUM), la LFPDPPP y criterios de la Suprema Corte (SCJN)."
    just_int = str(d.get("justificacion_internacional", "")).strip() or "Fundamentado en los estándares internacionales de derechos humanos (Pacto de San José / CADH), la Recomendación de la UNESCO (2021) y el marco del EU AI Act."

    fund_completa = f"MARCO CONSTITUCIONAL MEXICANO (CPEUM / SCJN / CNDH):\n{just_nac}\n\nESTÁNDARES INTERNACIONALES (CADH / UNESCO 2021 / EU AI ACT):\n{just_int}"

    medidas = d.get("medidas_y_recomendaciones") or d.get("recomendaciones") or []
    if isinstance(medidas, str):
        medidas = [medidas]
    elif not isinstance(medidas, list) or len(medidas) == 0:
        if es_conc:
            medidas = [
                "Ejercer tus Derechos ARCO (Acceso, Rectificación, Cancelación y Oposición) ante empresas o plataformas digitales.",
                "Presentar una queja formal ante la CNDH o comisiones estatales de derechos humanos si una autoridad vulnera tus garantías.",
                "Acudir al INAI si una app o empresa comercial hace uso indebido de tus datos o imágenes biométricas.",
                "Promover un Juicio de Amparo ante jueces de distrito si una decisión automatizada de gobierno afecta tus derechos."
            ]
        else:
            medidas = [
                "Implementar auditorías independientes de sesgos y proporcionalidad técnica.",
                "Incorporar consentimiento informado y aviso de privacidad explícito conforme a la LFPDPPP.",
                "Garantizar la supervisión y validación humana vinculante en las decisiones críticas (Human-in-the-loop)."
            ]

    return {
        "titulo_caso": titulo,
        "categoria": info_caso.get("categoria", "Pedagogía y Derechos Humanos" if es_conc else "General"),
        "es_ejemplo": info_caso.get("es_ejemplo", False),
        "es_conceptual": es_conc,
        "veredicto": veredicto,
        "nivel_riesgo_eu": nivel_riesgo,
        "nivel_riesgo_etico": nivel_riesgo,
        "puntuacion_etica": puntuacion,
        "diagnostico_factico": resumen,
        "resumen_hechos": resumen,
        "derechos_involucrados": derechos,
        "articulos_constitucion_violados": derechos,
        "justificacion_nacional": just_nac,
        "justificacion_internacional": just_int,
        "fundamentacion_juridica": fund_completa,
        "medidas_y_recomendaciones": medidas,
        "recomendaciones": medidas
    }

# ==============================================================================
# MOTOR DE INFERENCIA Y PALABRAS CLAVE JURÍDICAS (OFFLINE)
# ==============================================================================
TAXONOMIA_JURIDICA = [
    {
        "categoria": "Vigilancia Biométrica Masiva",
        "keywords": [
            "reconocimiento facial", "cámaras", "cámara", "biometría", "biométrico", "biométrica",
            "iris", "huella dactilar", "rastreo", "geolocalización", "espionaje", "pegasus",
            "monitoreo masivo", "espacio público", "vía pública", "metro", "redes sociales",
            "sin orden judicial", "sin aviso de privacidad", "escaneo facial", "drones", "placas",
            "cctv", "vigilancia en tiempo real"
        ],
        "peso_gravedad": 85,
        "derechos": [
            "Derecho a la Privacidad e Intimidad (Art. 16 CPEUM)",
            "Protección de Datos Personales Sensibles (LFPDPPP Art. 3°)",
            "Libertad de Tránsito y Circulación (Art. 11 CPEUM)",
            "Protección de la Honra y Dignidad (Art. 11 CADH)"
        ],
        "riesgo_eu": "Riesgo Inaceptable (Prohibido)",
        "fundamento_nacional": (
            "Violación flagrante al Artículo 16 de la CPEUM, que consagra la inviolabilidad de las comunicaciones y el derecho a la "
            "protección de datos personales. El cruce indiscriminado de información biométrica sin orden judicial emitida por autoridad competente "
            "contraviene frontalmente los principios de proporcionalidad, licitud y finalidad exigidos por la LFPDPPP y la LGPDPPSO, además de las "
            "directrices jurisprudenciales de la SCJN en materia de vigilancia estatal y derechos digitales."
        ),
        "fundamento_internacional": (
            "De acuerdo con el Artículo 5 del Reglamento Europeo de IA (EU AI Act), el uso de sistemas de identificación biométrica remota "
            "en tiempo real en espacios públicos está catalogado como de RIESGO INACEPTABLE Y PROHIBIDO. Vulnera asimismo los principios de transparencia "
            "y rendición de cuentas de la Recomendación sobre la Ética de la IA de la UNESCO (2021) y el Art. 11 del Pacto de San José (CADH)."
        ),
        "recomendaciones": [
            "Cese inmediato de la captura y procesamiento biométrico masivo no autorizado.",
            "Eliminación y purga segura de las bases de datos biométricas recabadas sin consentimiento.",
            "Elaboración de una Evaluación de Impacto en la Protección de Datos Personales (EIPDP).",
            "Requerir autorización judicial expresa y fundada previa a cualquier despliegue tecnológico similar."
        ]
    },
    {
        "categoria": "Discriminación Algorítmica y Sesgos de Selección",
        "keywords": [
            "currículums", "reclutamiento", "contratación", "código postal", "edad", "género", "mujer",
            "mujeres", "etnia", "raza", "indígena", "embarazo", "descartar candidatos", "sesgo",
            "algoritmo de selección", "perfilamiento", "scoring crediticio", "crédito", "exclusión social",
            "salario", "despido automatizado", "discapacidad", "clasificación socioeconómica"
        ],
        "peso_gravedad": 75,
        "derechos": [
            "Derecho a la Igualdad y No Discriminación (Art. 1° CPEUM)",
            "Derecho al Trabajo Digno y Libre Elección (Art. 123 CPEUM)",
            "Principio de Equidad y Justicia Distributiva (UNESCO)",
            "Igualdad ante la Ley (Art. 24 CADH)"
        ],
        "riesgo_eu": "Alto Riesgo",
        "fundamento_nacional": (
            "Vulneración directa de la cláusula antidiscriminatoria del Artículo 1° de la CPEUM, que prohíbe toda discriminación por origen étnico, "
            "género, edad o condición social. En el ámbito laboral (Art. 123 CPEUM), los algoritmos de filtrado opaco generan una exclusión indirecta "
            "arbitraria, contraviniendo la Ley Federal para Prevenir y Eliminar la Discriminación (CONAPRED)."
        ),
        "fundamento_internacional": (
            "El Anexo III del Reglamento Europeo de IA (EU AI Act) clasifica los sistemas de IA utilizados para el empleo, contratación y promoción "
            "de personal como de ALTO RIESGO. Exige obligatoriamente mitigación de sesgos, trazabilidad y supervisión humana vinculante."
        ),
        "recomendaciones": [
            "Someter los algoritmos de filtrado a auditorías de sesgos algorítmicos por terceros independientes.",
            "Deshabilitar variables proxys correlacionadas indirectamente con atributos protegidos.",
            "Establecer obligatoriamente un mecanismo de revisión humana y derecho a ser informado de los motivos de exclusión."
        ]
    },
    {
        "categoria": "Justicia Penal, Debido Proceso y Decisiones Judiciales Automatizadas",
        "keywords": [
            "reincidencia penal", "juez ia", "sentencia automatizada", "evaluación de riesgo procesal",
            "prisión preventiva", "policía predictiva", "patrullaje predictivo", "culpabilidad", "perfil delictivo",
            "sospecha algorítmica", "tribunal", "sin revisión judicial", "caja negra", "derecho a la defensa",
            "presunción de inocencia", "medida cautelar", "código privativo"
        ],
        "peso_gravedad": 90,
        "derechos": [
            "Garantía de Audiencia y Debido Proceso Legal (Art. 14 CPEUM)",
            "Deber de Fundamentación y Motivación Judicial (Art. 16 CPEUM)",
            "Derecho a la Presunción de Inocencia (Art. 20 CPEUM)",
            "Garantías Judiciales y Protección Judicial (Arts. 8 y 25 CADH)"
        ],
        "riesgo_eu": "Alto Riesgo",
        "fundamento_nacional": (
            "Transgresión grave al Artículo 14 y 16 constitucional. Toda resolución que afecte la libertad personal exige fundamentación y motivación "
            "exhaustiva elaborada por una autoridad judicial humana. La delegación en algoritmos privativos opacos anula el derecho de defensa adecuada (Art. 20 CPEUM)."
        ),
        "fundamento_internacional": (
            "El EU AI Act encuadra los sistemas de IA destinados a la administración de justicia como de ALTO RIESGO, prohibiendo la evaluación de personas "
            "basada meramente en perfiles estadísticos opacos. El Art. 8 del Pacto de San José (CADH) demanda jueces independientes y decisiones motivadas accesibles."
        ),
        "recomendaciones": [
            "Prohibir el uso vinculante de algoritmos predictivos para la privación de la libertad personal.",
            "Garantizar la transparencia algorítmica total y acceso al código fuente por parte de la defensa técnica.",
            "Mantener a los sistemas de IA exclusivamente como herramientas de apoyo no determinante."
        ]
    },
    {
        "categoria": "Democracia, Libertad de Expresión y Deepfakes",
        "keywords": [
            "deepfake", "clonación de voz", "suplantación de identidad", "video sintético", "campaña electoral",
            "candidato", "elecciones", "desinformación", "fake news", "manipulación electoral", "sin marca de agua",
            "sin etiquetado", "propaganda política", "botnet", "suplantación"
        ],
        "peso_gravedad": 80,
        "derechos": [
            "Derecho a la Información Veraz y Oportuna (Art. 6° CPEUM)",
            "Libertad de Expresión y Prohibición de Censura Previa (Art. 7° CPEUM)",
            "Derechos Político-Electorales de la Ciudadanía (Art. 35 CPEUM)",
            "Libertad de Pensamiento y Expresión (Art. 13 CADH)"
        ],
        "riesgo_eu": "Riesgo Limitado / Específico con Deber de Transparencia",
        "fundamento_nacional": (
            "Afectación directa al derecho de la ciudadanía a recibir información fidedigna para emitir un voto libre y razonado (Arts. 6° y 35 CPEUM). "
            "La difusión dolosa de audios o videos sintéticos falsos violenta la equidad en la contienda electoral y los criterios del INE y TEPJF."
        ),
        "fundamento_internacional": (
            "El EU AI Act (Art. 50) impone estrictas obligaciones de transparencia para los sistemas generadores de ultrafalsificaciones (deepfakes): "
            "etiquetado obligatorio y marcas de agua digitales perceptibles. La UNESCO subraya la necesidad de combatir la desinformación sintética."
        ),
        "recomendaciones": [
            "Implementar etiquetado visual y auditivo indeleble de contenido sintético.",
            "Establecer canales expeditos de respuesta y desmentido ante autoridades electorales.",
            "Sancionar administrativa y penalmente la suplantación digital dolosa durante comicios."
        ]
    },
    {
        "categoria": "Protección de Niñas, Niños y Adolescentes",
        "keywords": [
            "niños", "niñas", "menores", "escuela", "estudiantes menores", "aula", "cámara web", "detección de emociones",
            "estrés infantil", "atención de alumnos", "datos de menores", "vigilancia escolar"
        ],
        "peso_gravedad": 85,
        "derechos": [
            "Principio del Interés Superior de la Niñez (Art. 4° CPEUM)",
            "Protección Especial de Datos de Menores (LGDNNA Arts. 76-80)",
            "Derecho a la Intimidad y Desarrollo Integral (Art. 19 CADH)"
        ],
        "riesgo_eu": "Riesgo Inaceptable / Prohibido en Entornos Educativos",
        "fundamento_nacional": (
            "Vulneración grave del Artículo 4° constitucional, párrafo noveno (Interés superior de la niñez). La Ley General de los Derechos de Niñas, "
            "Niños y Adolescentes (LGDNNA) protege estrictamente la intimidad de los menores, prohibiendo el perfilamiento biométrico o emocional en centros escolares."
        ),
        "fundamento_internacional": (
            "El EU AI Act prohíbe de forma terminante los sistemas de IA destinados a la inferencia de emociones en lugares de trabajo y en centros educativos (Art. 5)."
        ),
        "recomendaciones": [
            "Desmantelar de inmediato los sistemas de reconocimiento emocional en estudiantes.",
            "Requerir autorización informada y expresa de madres, padres o tutores para cualquier herramienta didáctica digital."
        ]
    }
]

FACTORES_POSITIVOS_ETICA = [
    "supervisión humana", "revisión humana", "consentimiento informado", "anonimizado", "anonimizados",
    "código abierto", "open source", "datos abiertos", "auditoría de sesgos", "explicabilidad",
    "aviso de privacidad", "médico especialista", "firma un especialista", "derechos arco",
    "evaluación de impacto", "inclusión", "lenguas indígenas", "náhuatl", "maya", "beneficio social",
    "patrimonio cultural", "trazabilidad", "validado por un médico", "human-in-the-loop"
]

def analizar_por_palabras_clave_e_inferencia(descripcion_caso: str) -> Dict[str, Any]:
    texto = descripcion_caso.lower()

    # 1. ATENCIÓN DE CONSULTAS PEDAGÓGICAS Y CONCEPTUALES EN MODO INFERENCIA LOCAL
    if es_pregunta_conceptual(texto):
        # A) Consulta sobre Artículo 16 / Privacidad / Datos Personales
        if "16" in texto or "privacidad" in texto or "datos personales" in texto or "biometr" in texto:
            return normalizar_dictamen({
                "titulo_caso": "Consulta Constitucional: Artículo 16 CPEUM (Privacidad y Protección de Datos frente a la IA)",
                "veredicto": "CONSULTA CONCEPTUAL RESUELTA (DERECHO HUMANO FUNDAMENTAL)",
                "nivel_riesgo_eu": "Protección Constitucional Máxima (Art. 1° CPEUM)",
                "puntuacion_etica": 100,
                "diagnostico_factico": (
                    "El Artículo 16 de la Constitución Mexicana (CPEUM) protege tu derecho a la privacidad, a la intimidad y a la seguridad jurídica. "
                    "Establece que nadie puede ser molestado en su persona, familia, domicilio o pertenencias sin una orden escrita de una autoridad competente "
                    "que justifique legalmente el motivo. Además, garantiza expresamente que toda persona tiene derecho a la protección de sus datos personales, "
                    "a decidir quién los usa y a solicitar su acceso, rectificación, cancelación u oposición (Derechos ARCO)."
                ),
                "derechos_involucrados": [
                    "Derecho a la Privacidad e Intimidad Personal y Familiar (Art. 16 CPEUM)",
                    "Derecho Fundamental a la Protección de Datos Personales (Art. 16, Párr. 2° CPEUM)",
                    "Inviolabilidad de las Comunicaciones Privadas (Art. 16, Párr. 12° CPEUM)",
                    "Principio Pro Persona y Dignidad Humana (Art. 1° CPEUM)"
                ],
                "justificacion_nacional": (
                    "FUNDAMENTO CONSTITUCIONAL Y SUPREMA CORTE (SCJN):\n"
                    "La Suprema Corte de Justicia de la Nación (SCJN) ha sostenido que la privacidad digital y los datos personales son garantías inviolables "
                    "frente a intromisiones arbitrarias de autoridades o empresas. La Ley Federal de Protección de Datos Personales (LFPDPPP) exige que todo "
                    "tratamiento de información personal o biométrica cuente con consentimiento expreso, aviso de privacidad integral y finalidades claras.\n\n"
                    "EJEMPLOS PRÁCTICOS EN LA VIDA COTIDIANA EN MÉXICO:\n"
                    "1. En la calle o transporte: Ninguna autoridad o policía puede quitarte tu celular ni obligarte a desbloquear tus conversaciones de WhatsApp o fotos sin una orden judicial.\n"
                    "2. En servicios comerciales: Las tiendas departamentales o bancos no pueden vender tu número telefónico ni enviarte publicidad de terceros sin tu autorización.\n\n"
                    "EJEMPLOS DEL IMPACTO DE LA INTELIGENCIA ARTIFICIAL:\n"
                    "1. Reconocimiento facial en la vía pública: Cámaras con IA instaladas en estaciones de metro o parques que graban y analizan los rostros de toda la ciudadanía en tiempo real sin orden judicial ni aviso de privacidad violan directamente el Artículo 16.\n"
                    "2. Aplicaciones móviles de préstamos: Apps que mediante algoritmos escanean tus fotos, contactos y ubicación para cobrarte o perfilarte sin consentimiento informado violan la ley mexicana."
                ),
                "justificacion_internacional": (
                    "El Artículo 11 de la Convención Americana sobre Derechos Humanos (CADH) prohíbe las injerencias arbitrarias en la vida privada. "
                    "Asimismo, el Reglamento Europeo de Inteligencia Artificial (EU AI Act) cataloga la vigilancia biométrica remota en tiempo real en espacios públicos "
                    "como de Riesgo Inaceptable y Prohibido, criterio ratificado en la Recomendación sobre Ética de la IA de la UNESCO (2021)."
                ),
                "medidas_y_recomendaciones": [
                    "Ejercer tus Derechos ARCO ante cualquier empresa o aplicación que trate tus datos o información biométrica.",
                    "Presentar una denuncia formal ante el INAI si una app comercial comparte o vende tus datos personales sin permiso.",
                    "Promover un Juicio de Amparo Indirecto ante juzgados de distrito si un gobierno implementa vigilancia biométrica masiva sin fundamento legal."
                ]
            }, descripcion_caso)

        # B) Consulta sobre Artículo 14 / 20 / Debido Proceso / Presunción de Inocencia
        elif "14" in texto or "20" in texto or "inocencia" in texto or "debido proceso" in texto or "juez" in texto or "caja negra" in texto:
            return normalizar_dictamen({
                "titulo_caso": "Consulta Constitucional: Debido Proceso y Presunción de Inocencia frente a Algoritmos",
                "veredicto": "CONSULTA CONCEPTUAL RESUELTA (DERECHO HUMANO FUNDAMENTAL)",
                "nivel_riesgo_eu": "Protección Constitucional Máxima (Art. 1° CPEUM)",
                "puntuacion_etica": 100,
                "diagnostico_factico": (
                    "Los Artículos 14, 16 y 20 de la Constitución Mexicana garantizan que ninguna persona puede ser juzgada, privada de su libertad o de sus derechos "
                    "sin un juicio donde se cumplan las formalidades de ley y cuente con derecho a defenderse. Toda persona se presume inocente hasta que se demuestre "
                    "su culpabilidad mediante una sentencia fundamentada y dictada por un juez humano imparcial."
                ),
                "derechos_involucrados": [
                    "Garantía de Audiencia y Debido Proceso Legal (Art. 14 CPEUM)",
                    "Principio de Presunción de Inocencia (Art. 20, Apartado B, Fracc. I CPEUM)",
                    "Deber de Motivación y Fundamentación de las Resoluciones (Art. 16 CPEUM)",
                    "Garantías Judiciales y Defensa Adecuada (Art. 8 CADH)"
                ],
                "justificacion_nacional": (
                    "FUNDAMENTO CONSTITUCIONAL Y SUPREMA CORTE (SCJN):\n"
                    "La Suprema Corte (SCJN) establece que toda decisión judicial o administrativa que afecte a una persona debe ser explicable, motivada y elaborada "
                    "por un juez o servidor público humano. Está prohibido utilizar fórmulas abstractas o delegar la justicia en modelos cerrados (cajas negras).\n\n"
                    "EJEMPLOS PRÁCTICOS EN LA VIDA COTIDIANA EN MÉXICO:\n"
                    "1. En un procedimiento penal o de tránsito: Tienes derecho a conocer las pruebas en tu contra, ser escuchado por el juez y contar con un abogado defensor antes de recibir cualquier sanción.\n"
                    "2. En el trabajo o escuela: No te pueden expulsar o despedir con una sanción inmediata sin darte la oportunidad de presentar tu versión y pruebas.\n\n"
                    "EJEMPLOS DEL IMPACTO DE LA INTELIGENCIA ARTIFICIAL:\n"
                    "1. Software predictivo de reincidencia delictiva: Si un juzgado utiliza un algoritmo privado para calcular si una persona 'podría volver a delinquir' y basar en eso la prisión preventiva sin permitir que la defensa revise cómo calcula el riesgo, se viola la presunción de inocencia y el debido proceso.\n"
                    "2. Sanciones automáticas por IA: Sistemas de fotomultas o despido algorítmico que aplican castigos sin revisión humana previa contravienen la Constitución."
                ),
                "justificacion_internacional": (
                    "El Artículo 8 del Pacto de San José (CADH) exige tribunales competentes e independientes. El EU AI Act encuadra a los sistemas de IA utilizados "
                    "en la administración de justicia como de Alto Riesgo, prohibiendo su uso determinante para privar de la libertad sin supervisión humana obligatoria."
                ),
                "medidas_y_recomendaciones": [
                    "Exigir la motivación humana vinculante y por escrito en cualquier determinación administrativa o judicial.",
                    "Impugnar el uso de algoritmos 'caja negra' como prueba pericial por violentar el derecho de contradicción y defensa adecuada.",
                    "Interponer recurso de apelación o Juicio de Amparo si una autoridad fundamenta una sanción exclusivamente en un cálculo algorítmico."
                ]
            }, descripcion_caso)

        # C) Consulta sobre Artículo 1° / Igualdad / No Discriminación
        elif "1" in texto or "discriminaci" in texto or "igualdad" in texto or "sesgo" in texto:
            return normalizar_dictamen({
                "titulo_caso": "Consulta Constitucional: Artículo 1° CPEUM (Igualdad y No Discriminación Algorítmica)",
                "veredicto": "CONSULTA CONCEPTUAL RESUELTA (DERECHO HUMANO FUNDAMENTAL)",
                "nivel_riesgo_eu": "Protección Constitucional Máxima (Art. 1° CPEUM)",
                "puntuacion_etica": 100,
                "diagnostico_factico": (
                    "El Artículo 1° de la Constitución Mexicana (CPEUM) prohíbe de manera absoluta toda discriminación que atente contra la dignidad humana. "
                    "Nadie puede ser discriminado por origen étnico o nacional, género, edad, discapacidad, condición social, salud, religión, preferencias sexuales "
                    "o estado civil. Asimismo, consagra el Principio Pro Persona, que obliga a todas las autoridades a aplicar siempre la norma que más proteja a la gente."
                ),
                "derechos_involucrados": [
                    "Cláusula Antidiscriminatoria y Dignidad Humana (Art. 1°, Párr. 5° CPEUM)",
                    "Principio Pro Persona e Interpretación Conforme (Art. 1°, Párr. 2° CPEUM)",
                    "Derecho al Trabajo Digno y Libre Elección (Art. 123 CPEUM)",
                    "Igualdad ante la Ley (Art. 24 CADH)"
                ],
                "justificacion_nacional": (
                    "FUNDAMENTO CONSTITUCIONAL Y SUPREMA CORTE (SCJN):\n"
                    "La Suprema Corte ha emitido jurisprudencia histórica señalando que la discriminación no solo es explícita, sino también indirecta o estructural. "
                    "La Ley Federal para Prevenir y Eliminar la Discriminación (CONAPRED) prohíbe cualquier práctica o criterio de selección que genere desventajas injustificadas.\n\n"
                    "EJEMPLOS PRÁCTICOS EN LA VIDA COTIDIANA EN MÉXICO:\n"
                    "1. En el empleo: Una empresa no puede exigir pruebas de embarazo para contratar, ni limitar puestos directivos exclusivamente a hombres o personas jóvenes.\n"
                    "2. En establecimientos públicos: Restaurantes o centros comerciales no pueden reservar el derecho de admisión por la vestimenta o tono de piel de una persona.\n\n"
                    "EJEMPLOS DEL IMPACTO DE LA INTELIGENCIA ARTIFICIAL:\n"
                    "1. Filtros de empleo con IA: Algoritmos de contratación que descartan automáticamente perfiles de mujeres mayores de 40 años o de personas que viven en colonias populares.\n"
                    "2. Scoring crediticio bancario con IA: Modelos que rechazan préstamos basándose en la marca del celular o la zona geográfica del solicitante generan discriminación indirecta prohibida por la ley mexicana."
                ),
                "justificacion_internacional": (
                    "El Anexo III del EU AI Act clasifica como de Alto Riesgo a los sistemas de IA utilizados para la contratación de personal y acceso a servicios esenciales, "
                    "exigiendo auditorías periódicas contra sesgos. La UNESCO (2021) prohíbe sistemas de IA que reproduzcan o amplifiquen la desigualdad social."
                ),
                "medidas_y_recomendaciones": [
                    "Presentar queja formal ante CONAPRED si un sistema automatizado te excluye por motivos discriminatorios.",
                    "Exigir a las empresas explicabilidad y derecho de audiencia humana sobre los motivos exactos de un rechazo laboral o crediticio.",
                    "Denunciar ante la Secretaría del Trabajo (STPS) y solicitar juicio laboral o amparo por discriminación algorítmica."
                ]
            }, descripcion_caso)

        # D) Consulta General: ¿Qué son los Derechos Humanos?
        else:
            return normalizar_dictamen({
                "titulo_caso": "Consulta Ciudadana: Definición y Principios Fundamentales de los Derechos Humanos",
                "veredicto": "CONSULTA CONCEPTUAL RESUELTA (DERECHO HUMANO FUNDAMENTAL)",
                "nivel_riesgo_eu": "Protección Constitucional Máxima (Art. 1° CPEUM)",
                "puntuacion_etica": 100,
                "diagnostico_factico": (
                    "Los derechos humanos son el conjunto de prerrogativas, libertades y protecciones inherentes a todas las personas por el simple hecho de existir. "
                    "Son indispensables para el desarrollo integral y para vivir con dignidad, paz, igualdad y libertad. No dependen de la nacionalidad, sexo, "
                    "origen étnico, color de piel, religión, idioma ni cualquier otra condición, y el Estado tiene la obligación estricta de respetarlos y protegerlos."
                ),
                "derechos_involucrados": [
                    "Principio de Universalidad, Interdependencia, Indivisibilidad y Progresividad (Art. 1° CPEUM)",
                    "Principio Pro Persona y Dignidad Humana (Art. 1° CPEUM)",
                    "Derecho a la Vida, Salud y Bienestar (Art. 4° CPEUM)",
                    "Libertad de Expresión y Acceso a la Información (Art. 6° CPEUM)",
                    "Seguridad Jurídica y Debido Proceso (Arts. 14 y 16 CPEUM)"
                ],
                "justificacion_nacional": (
                    "FUNDAMENTO CONSTITUCIONAL Y SUPREMA CORTE (SCJN):\n"
                    "A partir de la histórica reforma constitucional de 2011 en México, el Artículo 1° de la CPEUM reconoció que todas las personas gozan de los "
                    "derechos humanos consagrados en la Constitución y en los Tratados Internacionales. La Suprema Corte (SCJN) ha determinado que los derechos "
                    "humanos son el límite infranqueable del poder público y de las empresas privadas, rigiéndose bajo el Principio Pro Persona (elegir siempre "
                    "la interpretación legal que otorgue la protección más amplia a la persona).\n\n"
                    "EJEMPLOS PRÁCTICOS EN LA VIDA COTIDIANA EN MÉXICO:\n"
                    "1. En la salud y educación: Tienes derecho a recibir atención médica en instituciones públicas de salud y a que tus hijos reciban educación pública gratuita y laica (Arts. 3° y 4° CPEUM).\n"
                    "2. En el trabajo: Tienes derecho a un salario digno, descanso semanal, condiciones seguras y a no ser despedido injustificadamente (Art. 123 CPEUM).\n"
                    "3. En la libertad personal: Puedes expresar tus opiniones pacíficamente, transitar libremente por el país y profesar la fe o creencias que elijas (Arts. 6°, 11 y 24 CPEUM).\n\n"
                    "EJEMPLOS DEL IMPACTO DE LA INTELIGENCIA ARTIFICIAL:\n"
                    "1. Privacidad vulnerada por IA: Cuando una app o red social recopila tus datos biométricos o conversaciones para venderlos a anunciantes o entrenar modelos sin tu permiso, vulnera tu derecho a la privacidad (Art. 16 CPEUM).\n"
                    "2. Discriminación por algoritmos: Si una empresa utiliza un software que descarta aspirantes por su género o colonia, se violenta el derecho a la igualdad y no discriminación (Art. 1° CPEUM).\n"
                    "3. Desinformación electoral y deepfakes: Si se crean videos falsos con IA para manipular votaciones, se afecta el derecho ciudadano a la información veraz y al voto libre (Arts. 6° y 35 CPEUM)."
                ),
                "justificacion_internacional": (
                    "Reconocidos en la Declaración Universal de Derechos Humanos (1948) y en la Convención Americana sobre Derechos Humanos (Pacto de San José). "
                    "En el ámbito digital, la UNESCO aprobó en 2021 la Recomendación sobre la Ética de la Inteligencia Artificial, que establece que ningún desarrollo "
                    "tecnológico puede subordinar o violar la dignidad y los derechos humanos universales."
                ),
                "medidas_y_recomendaciones": [
                    "Acudir ante la Comisión Nacional de los Derechos Humanos (CNDH) o comisiones estatales si alguna autoridad vulnera tus garantías.",
                    "Presentar queja ante CONAPRED si sufres discriminación por parte de particulares, escuelas o empleadores.",
                    "Ejercer denuncia ante el INAI si empresas privadas o dependencias gubernamentales usan indebidamente tus datos personales o biométricos.",
                    "Promover un Juicio de Amparo ante el Poder Judicial Federal para suspender actos arbitrarios o normas contrarias a la Constitución."
                ]
            }, descripcion_caso)

    # 2. EVALUACIÓN DE CASOS PRÁCTICOS DE IA
    aciertos_positivos = [f for f in FACTORES_POSITIVOS_ETICA if f in texto]
    puntos_positivos = len(aciertos_positivos) * 15

    mejor_coincidencia = None
    mayor_puntaje = 0

    for regla in TAXONOMIA_JURIDICA:
        coincidencias = [kw for kw in regla["keywords"] if kw in texto]
        if coincidencias:
            score = len(coincidencias) * 12 + regla["peso_gravedad"]
            if score > mayor_puntaje:
                mayor_puntaje = score
                mejor_coincidencia = {
                    "regla": regla,
                    "coincidencias": coincidencias,
                    "score": score
                }

    es_caso_positivo = ("supervisión humana" in texto or "validado" in texto or "firma un" in texto or "lenguas indígenas" in texto or "código abierto" in texto) and ("sin aviso" not in texto and "sin orden" not in texto and "descarta" not in texto)

    if es_caso_positivo and len(aciertos_positivos) >= 2:
        veredicto = "NO VULNERA (PRÁCTICA POSITIVA Y ÉTICA)"
        riesgo = "Riesgo Mínimo" if ("lenguas" in texto or "educativo" in texto) else "Alto Riesgo Mitigado con Supervisión Humana"
        puntuacion = min(98, 75 + puntos_positivos)
        derechos = [
            "Derecho a la Protección de la Salud (Art. 4° CPEUM)" if "médic" in texto or "salud" in texto else "Derecho a la Educación e Inclusión (Art. 2° y 3° CPEUM)",
            "Protección de Datos con Consentimiento Pleno (LFPDPPP)",
            "Principio de Beneficio Humano y Diversidad Cultural (UNESCO)"
        ]
        just_nac = (
            "El sistema implementa salvaguardas robustas acordes al marco constitucional mexicano. Cuenta con consentimiento informado, "
            "disociación y anonimización de datos personales según la LFPDPPP, y mantiene una supervisión humana calificada que valida cada "
            "dictamen antes de surtir efectos, respetando la dignidad humana (Art. 1° CPEUM)."
        )
        just_int = (
            "Cumple cabalmente con la Recomendación de la UNESCO sobre la Ética de la IA (2021) al garantizar la supervisión humana "
            "(Human-in-the-Loop), la inclusión y la explicabilidad. Conforme al EU AI Act, al existir gobernanza de datos estricta y supervisión "
            "humana continua, el riesgo se encuentra adecuadamente controlado."
        )
        recomendaciones = [
            "Mantener bitácoras de auditoría de calibración técnica de manera trimestral.",
            "Publicar informes de transparencia sobre tasas de acierto y equidad demográfica.",
            "Continuar capacitando de forma obligatoria al personal humano evaluador."
        ]
    elif mejor_coincidencia:
        regla = mejor_coincidencia["regla"]
        derechos = regla["derechos"]
        riesgo = regla["riesgo_eu"]
        just_nac = regla["fundamento_nacional"]
        just_int = regla["fundamento_internacional"]
        recomendaciones = regla["recomendaciones"]

        if mayor_puntaje >= 95:
            veredicto = "VULNERA DERECHOS HUMANOS"
            puntuacion = max(10, 30 - len(mejor_coincidencia["coincidencias"]) * 4)
        else:
            veredicto = "RIESGO CONDICIONAL / MITIGABLE"
            puntuacion = max(35, 55 - len(mejor_coincidencia["coincidencias"]) * 3 + puntos_positivos)
    else:
        veredicto = "RIESGO CONDICIONAL / MITIGABLE"
        riesgo = "Alto Riesgo (Requiere Auditoría Técnica)"
        puntuacion = 50
        derechos = [
            "Derecho a la Privacidad y Protección de Datos Personales (Art. 16 CPEUM)",
            "Principio Pro Persona y Dignidad Humana (Art. 1° CPEUM)",
            "Deber de Transparencia Algorítmica (EU AI Act y UNESCO)"
        ]
        just_nac = (
            "El caso presentado involucra el despliegue de sistemas de decisión automatizada que impactan en los derechos de las personas. "
            "Se requiere acreditar el estricto cumplimiento de los principios de licitud, consentimiento, información y proporcionalidad tutelados "
            "por el Artículo 16 de la CPEUM y la LFPDPPP."
        )
        just_int = (
            "Conforme a los estándares del EU AI Act y la Recomendación de la UNESCO de 2021, todo sistema de inteligencia artificial que afecte "
            "aspectos sensibles de las personas debe ser sometido a un examen de idoneidad, minimización de datos y supervisión humana."
        )
        recomendaciones = [
            "Llevar a cabo una Evaluación de Impacto en los Derechos Fundamentales (FRIA).",
            "Publicar el aviso de privacidad detallando los algoritmos y finalidades del tratamiento.",
            "Garantizar la existencia de una vía expedita de recurso e inconformidad ante operadores humanos."
        ]

    dictamen_raw = {
        "veredicto": veredicto,
        "nivel_riesgo_eu": riesgo,
        "puntuacion_etica": puntuacion,
        "derechos_involucrados": derechos,
        "justificacion_nacional": just_nac,
        "justificacion_internacional": just_int,
        "medidas_y_recomendaciones": recomendaciones
    }
    return normalizar_dictamen(dictamen_raw, descripcion_caso)

# ==============================================================================
# MOTOR PRINCIPAL ASÍNCRONO DE ANÁLISIS (CON RESILIENCIA Y ULTRA VELOCIDAD)
# ==============================================================================
CACHE_RESPUESTAS: Dict[str, Any] = {}

async def analizar_caso_ia(
    descripcion_caso: str,
    modo: str = "api",
    api_key: str = "",
    local_url: str = "http://localhost:11434/v1/chat/completions",
    local_model: str = "qwen2.5:7b"
) -> Dict[str, Any]:
    modo_normalizado = modo.strip().lower()
    caso_limpio = descripcion_caso.strip()
    if not caso_limpio:
        raise ValueError("La descripción del caso a evaluar no puede estar vacía.")

    cache_key = f"{modo_normalizado}:{caso_limpio[:120]}"
    if cache_key in CACHE_RESPUESTAS:
        return CACHE_RESPUESTAS[cache_key]

    # MODO 1: INFERENCIA / PALABRAS CLAVE OFFLINE
    if modo_normalizado in ["keywords", "palabras_clave", "offline", "reglas", "inferencia", "heuristica", "heurística"]:
        resultado = analizar_por_palabras_clave_e_inferencia(caso_limpio)
        CACHE_RESPUESTAS[cache_key] = resultado
        return resultado

    es_conc = es_pregunta_conceptual(caso_limpio)
    if es_conc:
        user_prompt = (
            f"El usuario realiza la siguiente consulta conceptual o ciudadana sobre derechos humanos y normatividad en México:\n\n"
            f"\"{caso_limpio}\"\n\n"
            f"Por favor, responde en un lenguaje latino (mexicano) claro, directo, empático y sin tecnicismos excesivos. "
            f"Proporciona la definición directa, cita los artículos aplicables de la Constitución (CPEUM), la Suprema Corte (SCJN) y la CNDH, "
            f"y OBLIGATORIAMENTE incluye ejemplos prácticos de la vida cotidiana en México y ejemplos del impacto de la Inteligencia Artificial "
            f"para justificar la importancia de este derecho. Agrega consejos claros sobre cómo defenderlo."
        )
    else:
        user_prompt = (
            f"Analiza jurídica y éticamente el siguiente caso de Inteligencia Artificial para el contexto de México:\n\n"
            f"{caso_limpio}\n\n"
            f"Emite el dictamen en un lenguaje mexicano accesible, claro y sin palabras rebuscadas, "
            f"fundamentando en la CPEUM, la SCJN y estándares de ética en IA, justificando con ejemplos prácticos las consecuencias reales para las personas."
        )

    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user_prompt}
    ]

    # MODO 2: API GROQ EN LA NUBE (ULTRA RÁPIDO CON FALLBACK INTELIGENTE)
    if modo_normalizado in ["api", "groq", "nube", "cloud"]:
        active_key = api_key.strip() if api_key.strip() else get_groq_api_key()
        if not active_key or active_key.startswith("gsk_..."):
            # Si no hay llave, resolver vía motor heurístico
            return analizar_por_palabras_clave_e_inferencia(caso_limpio)

        headers = {
            "Authorization": f"Bearer {active_key}",
            "Content-Type": "application/json"
        }

        # Modelos optimizados de Groq: openai/gpt-oss-20b con reasoning_effort='low' es ultra rápido (~1s)
        # y no entra en colas saturadas como qwen/qwen3.8-27b
        content = ""
        groq_configs = [
            {
                "model": "openai/gpt-oss-20b",
                "payload": {
                    "model": "openai/gpt-oss-20b",
                    "messages": messages,
                    "reasoning_effort": "low",
                    "temperature": 0.1,
                    "max_tokens": 1800
                },
                "timeout": 12.0
            },
            {
                "model": "openai/gpt-oss-120b",
                "payload": {
                    "model": "openai/gpt-oss-120b",
                    "messages": messages,
                    "reasoning_effort": "low",
                    "temperature": 0.1,
                    "max_tokens": 1800
                },
                "timeout": 15.0
            },
            {
                "model": "qwen/qwen3.8-27b",
                "payload": {
                    "model": "qwen/qwen3.8-27b",
                    "messages": messages,
                    "temperature": 0.1,
                    "response_format": {"type": "json_object"}
                },
                "timeout": 12.0
            }
        ]

        async with httpx.AsyncClient(timeout=25.0) as client:
            for cfg in groq_configs:
                try:
                    resp = await client.post(
                        "https://api.groq.com/openai/v1/chat/completions",
                        headers=headers,
                        json=cfg["payload"],
                        timeout=cfg["timeout"]
                    )
                    if resp.status_code == 200:
                        resp_json = resp.json()
                        msg = resp_json.get("choices", [{}])[0].get("message", {})
                        raw_c = (msg.get("content") or "").strip()
                        if raw_c:
                            content = raw_c
                            break
                        # Respaldo en caso de que esté en reasoning
                        raw_r = (msg.get("reasoning") or "").strip()
                        if "{" in raw_r and "}" in raw_r:
                            content = raw_r
                            break
                    elif resp.status_code in [429, 503, 504]:
                        # Límite de tasa o saturación de cola en Groq, probar siguiente modelo rápido
                        continue
                except Exception:
                    continue

        # Si Groq respondió con contenido, parsearlo
        if content:
            try:
                resultado = extraer_json_valido(content, caso_limpio)
                CACHE_RESPUESTAS[cache_key] = resultado
                return resultado
            except Exception:
                pass

        # Si Groq está saturado, con rate-limit 429 o sin conexión:
        # Fallback instantáneo e infalible al motor heurístico jurídico para no dejar al usuario esperando
        resultado_fallback = analizar_por_palabras_clave_e_inferencia(caso_limpio)
        resultado_fallback["justificacion_internacional"] += " [Procesado con salvaguarda local de inferencia jurídica ante saturación temporal de la API en la nube]."
        CACHE_RESPUESTAS[cache_key] = resultado_fallback
        return resultado_fallback

    # MODO 3: MODELO LOCAL OLLAMA (RTX 3060 LAPTOP)
    elif modo_normalizado in ["local", "ollama", "local_ollama"]:
        endpoint = local_url.strip() if local_url.strip() else "http://localhost:11434/v1/chat/completions"
        endpoint = endpoint.rstrip("/")
        if not endpoint.endswith("/chat/completions"):
            if endpoint.endswith("/v1"):
                endpoint += "/chat/completions"
            else:
                endpoint += "/v1/chat/completions"

        modelo_usado = local_model.strip() if local_model.strip() else "qwen2.5:7b"

        payload = {
            "model": modelo_usado,
            "messages": messages,
            "temperature": 0.1,
            "stream": False,
            "response_format": {"type": "json_object"}
        }

        async with httpx.AsyncClient(timeout=45.0) as client:
            try:
                resp = await client.post(endpoint, json=payload, timeout=40.0)
                resp.raise_for_status()
                resp_json = resp.json()
                content = resp_json["choices"][0]["message"].get("content", "")
            except httpx.ConnectError:
                raise ValueError(
                    f"No se pudo conectar a Ollama en {endpoint}. "
                    f"Asegúrate de que Ollama esté abierto en tu laptop y ejecuta en tu terminal: 'ollama run {modelo_usado}'."
                )
            except Exception as e:
                raise ValueError(f"Error en la inferencia del modelo local Ollama ({modelo_usado}): {str(e)}")

        resultado = extraer_json_valido(content, caso_limpio)
        CACHE_RESPUESTAS[cache_key] = resultado
        return resultado

    else:
        raise ValueError(f"Modo '{modo}' no reconocido.")
