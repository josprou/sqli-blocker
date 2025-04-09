from flask import Flask, request, jsonify
import re
import datetime

app = Flask(__name__)

# Archivo de logs donde se guardan las consultas NO maliciosas
LOG_FILE = "logs_no_sqli.txt"

# Filtro previo: Detecta si hay caracteres sospechosos antes de ejecutar regex complejas
FILTER_PRECHECK = re.compile(r'[=;\'"()\-\#/\*]', re.IGNORECASE)

# Expresión regex única optimizada para detectar SQL Injection
SQLI_PATTERN = re.compile(
    r'(\b(UNION|SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|SLEEP|WAITFOR|BENCHMARK|LOAD_FILE|'
    r'INTO\s+OUTFILE|INTO\s+DUMPFILE|EXEC|DECLARE|CAST|CONVERT|ASCII|CHAR|SUBSTRING|LEN|LENGTH|'
    r'HAVING|GROUP\sBY|ORDER\sBY|IN|BETWEEN|LIKE|EXISTS|TRUE|FALSE|NULL|0x[0-9A-Fa-f]+|'
    r'DBMS_PIPE|XP_CMDSHELL|SYS|UTL_HTTP|UTL_FILE|CHR|UNICODE|HEX|CONCAT)\b|'
    r'\b\d+\s?=\s?\d+\b)',
    re.IGNORECASE
)

# Detección de estructuras SQL maliciosas (comentarios SQL)
SQLI_STRUCTURES = re.compile(r'(--|#|/\*.*?\*/)', re.IGNORECASE)

def detect_sql_injection(query):
    """Detecta SQL Injection optimizado con una única evaluación regex."""

    # 1 Filtro previo: Si no hay caracteres sospechosos, ignorar la evaluación regex
    if not FILTER_PRECHECK.search(query):
        return False, []

    detected_types = []

    # 2 Evaluar la regex única optimizada
    if SQLI_PATTERN.search(query):
        detected_types.append("Patrón SQL Injection detectado")
 
    # 3 Detectar estructuras SQL maliciosas
    if SQLI_STRUCTURES.search(query):
        detected_types.append("Estructura SQL sospechosa (comentarios, etc.)")
 
    return bool(detected_types), detected_types
 
def log_safe_query(query):
    """Registra en un archivo las consultas NO maliciosas."""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", encoding="utf-8") as log_file:
        log_file.write(f"[{timestamp}] {query}\n")
 
@app.route('/analizar', methods=['GET'])
def analizar():
    """Endpoint para analizar sentencias sospechosas."""
    query = request.args.get('sentencia', '')
 
    if not query:
        return jsonify({'error': 'No se proporcionó ninguna sentencia'}), 400
 
    is_malicious, detected_sqli_types = detect_sql_injection(query)
 
    # Si la consulta no es SQLi, la guardamos en el log
    if not is_malicious:
        log_safe_query(query)
        return jsonify({
            'sentencia': query,
            'es_malicioso': 'N'
        })
 
    return jsonify({
        'sentencia': query,
        'es_malicioso': 'S',
        'tipos_detectados': detected_sqli_types
    })
 
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
 
