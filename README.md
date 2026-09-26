# OpenHash

Si estás cansado de GUIs pesadas de 500MB hechas en Electron solo para verificar si un ISO de Linux bajó corrupto, bienvenido. **OpenHash** es una CLI en Python rápida, directa y sin tonterías para calcular hashes, verificar integridad de archivos y cazar duplicados en tu disco.

Diseñada para procesar archivos grandes en bloques sin devorarse la memoria RAM.

---

## Características

* **Cálculo por bloques:** Procesa archivos gigabyte por gigabyte sin hacer explotar la memoria del sistema.
* **Soporte total de hashlib:** Calcula cualquier algoritmo que tu instalación de Python soporte (`SHA256`, `MD5`, `SHA512`, `BLAKE2`, etc.).
* **Generación de HMAC:** Autenticación de mensajes con clave secreta sin depender de dependencias externas.
* **Caza de duplicados:** Escanea directorios en busca de archivos repetidos y te permite mandarlos al limbo.
* **Consulta en VirusTotal:** Revisa si un hash sospechoso ya fue reportado como malware vía API v3.
* **Reportes:** Exporta los resultados a JSON o CSV sin rodeos.

---

## Requisitos

Python 3.8+ y nada más para las funciones locales. 

Si quieres usar la integración con VirusTotal, instala `requests`:

```bash
pip install requests
Uso
Modo interactivo
Ejecuta el script sin parámetros y déjate llevar por el menú:

Bash
python openhash.py
Modo directo por terminal
Si solo necesitas el hash de un archivo de forma rápida sin pasar por menús:

Bash
python openhash.py -f ruta/al/archivo.iso -a sha256
Licencia
AGPL
Úsalo, modifícalo o rompe tu sistema con él. No me hago responsable si borras algo que no debías.
Me revente los putos dedos escrbiendo esto asi que solo disfruta sin culpa.
