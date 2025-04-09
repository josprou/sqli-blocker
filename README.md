# SQLi-Blocker

**SQLi-Blocker** es un proyecto diseñado para detectar y prevenir ataques de inyección SQL en aplicaciones web. Proporciona herramientas y scripts que ayudan a analizar y reforzar la seguridad de las aplicaciones contra este tipo de vulnerabilidades.

## Contenido del Repositorio

- `sql_analyzer_service.py`: Servicio en Python que analiza consultas SQL en busca de posibles inyecciones. Utiliza patrones y heurísticas para identificar consultas sospechosas y prevenir su ejecución.

- `sqlmap-tamper-tester.sh`: Script en Bash que automatiza la prueba de diferentes scripts de evasión (*tamper scripts*) de [sqlmap](https://sqlmap.org/). Permite evaluar la efectividad de estos scripts contra sistemas de detección de inyecciones SQL.

## Requisitos

- **Python 3.x**: Necesario para ejecutar `sql_analyzer_service.py`.
- **sqlmap**: Requerido para utilizar `sqlmap-tamper-tester.sh`. Puedes instalarlo siguiendo las instrucciones en [sqlmap.org](https://sqlmap.org/).

## Uso

### `sql_analyzer_service.py`

1. Asegúrate de tener Python 3.x instalado en tu sistema.
2. Ejecuta el script:
   ```bash
   python3 sql_analyzer_service.py
