import csv
import hashlib
import hmac
import json
import os
import sys
import time
from pathlib import Path

# Si no tienes requests instalado en 2026, de verdad no sé qué haces programando
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def _calcular_hash_archivo(filepath, algoritmo="sha256", chunk_size=65536):
    # Procesa en bloques para que tu computadora con 4GB de RAM no explote
    h = hashlib.new(algoritmo)
    with open(filepath, "rb") as f:
        while chunk := f.read(chunk_size):
            h.update(chunk)
    return h.hexdigest()


def procesar_entrada(target, esperado=None):
    p = Path(target)
    reporte = []
    datos_exportar = {"objetivo": target, "resultados": []}

    if p.is_file():
        print(f"\nCalculando hashes para el archivo (si es que no está corrupto): {p.name}")
        for algo in sorted(hashlib.algorithms_guaranteed):
            try:
                t0 = time.perf_counter()
                res = _calcular_hash_archivo(p, algo)
                t1 = time.perf_counter() - t0

                match = res.lower() == esperado.lower() if esperado else False
                str_match = " [MATCH! Por fin una buena noticia]" if match else ""
                
                linea = f"{algo:<12}: {res} ({t1:.4f}s){str_match}"
                print(linea)
                reporte.append(linea)
                
                datos_exportar["resultados"].append({
                    "algoritmo": algo,
                    "hash": res,
                    "tiempo_s": round(t1, 6),
                    "match": match
                })
            except (PermissionError, OSError) as e:
                # Obviamente no le diste permisos al archivo, clásico.
                print(f"{algo:<12}: Error de permisos o lectura ({e})")
    else:
        print(f"\nHashes para texto plano (porque no quisiste pasar un archivo): {target}")
        data = target.encode("utf-8")
        for algo in sorted(hashlib.algorithms_guaranteed):
            try:
                t0 = time.perf_counter()
                res = hashlib.new(algo, data).hexdigest()
                t1 = time.perf_counter() - t0

                match = res.lower() == esperado.lower() if esperado else False
                str_match = " [MATCH!]" if match else ""
                
                linea = f"{algo:<12}: {res} ({t1:.4f}s){str_match}"
                print(linea)
                reporte.append(linea)
                
                datos_exportar["resultados"].append({
                    "algoritmo": algo,
                    "hash": res,
                    "tiempo_s": round(t1, 6),
                    "match": match
                })
            except Exception as e:
                print(f"{algo:<12}: Rompiste algo: ({e})")

    with open("reporte_hashes.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(reporte) + "\n")

    return datos_exportar


def consultar_virustotal():
    if not HAS_REQUESTS:
        print("Instala 'requests' primero, no hago milagros: pip install requests")
        return

    api_key = input("Pega tu API Key de VirusTotal (prometo no robármela): ").strip()
    if not api_key:
        return

    target_hash = input("Hash SHA256 a buscar: ").strip()
    if not target_hash:
        return

    url = f"https://www.virustotal.com/api/v3/files/{target_hash}"
    headers = {"x-apikey": api_key}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            print(f"\nReporte de la paranoia para {target_hash[:10]}...")
            print(f"Maliciosos : {stats.get('malicious', 0)}")
            print(f"Sospechosos : {stats.get('suspicious', 0)}")
            print(f"Limpios     : {stats.get('harmless', 0) + stats.get('undetected', 0)}")
        elif resp.status_code == 404:
            print("El hash no existe en VT. O es muy nuevo o es malware tan raro que nadie conoce.")
        else:
            print(f"La API te rebotó con código HTTP {resp.status_code}. Revisa tu API key.")
    except requests.RequestException as e:
        print(f"Error de red (revisa si pagaste el internet): {e}")


def calcular_hmac():
    texto = input("Texto o ruta: ").strip()
    clave = input("Clave 'secreta' (que seguro es 123456): ").strip()
    if not texto or not clave:
        return

    p = Path(texto)
    h = hmac.new(clave.encode("utf-8"), digestmod=hashlib.sha256)

    if p.is_file():
        with open(p, "rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
    else:
        h.update(texto.encode("utf-8"))

    print(f"\nHMAC-SHA256 calculado: {h.hexdigest()}")


def buscar_duplicados():
    ruta = input("Carpeta para buscar basura duplicada: ").strip()
    p = Path(ruta)

    if not p.is_dir():
        print("Eso ni siquiera es una carpeta válida. Inténtalo de nuevo.")
        return

    hashes = {}
    duplicados = []

    print("Escaneando el desastre de tu disco...")
    for archivo in p.rglob("*"):
        if archivo.is_file():
            try:
                res = _calcular_hash_archivo(archivo, "sha256")
                if res in hashes:
                    duplicados.append((archivo, hashes[res]))
                else:
                    hashes[res] = archivo
            except (PermissionError, OSError):
                continue

    if duplicados:
        print(f"\nFelicidades, encontré {len(duplicados)} archivos repetidos ocupando espacio:")
        for dup, original in duplicados:
            print(f"Copia   : {dup}\nOriginal: {original}\n")
            borrar = input("¿Lo borro o le tienes cariño? (s/N): ").lower()
            if borrar == "s":
                os.remove(dup)
                print(f"Enviado al limbo: {dup.name}")
    else:
        print("Milagrosamente no hay duplicados.")


def gestor_checksums():
    print("\n1. Generar checksums.sha256\n2. Verificar si modificaron algo")
    op = input("Selecciona (1/2): ").strip()

    if op == "1":
        p = Path(input("Carpeta origen: ").strip())
        if not p.is_dir():
            return

        lineas = []
        for archivo in p.rglob("*"):
            if archivo.is_file() and archivo.name != "checksums.sha256":
                try:
                    res = _calcular_hash_archivo(archivo, "sha256")
                    lineas.append(f"{res}  {archivo.relative_to(p)}")
                except (PermissionError, OSError):
                    continue

        with open(p / "checksums.sha256", "w", encoding="utf-8") as f:
            f.write("\n".join(lineas) + "\n")
        print("Checksums generados. No lo vayas a perder.")

    elif op == "2":
        p_file = Path(input("Ruta del checksums.sha256: ").strip())
        if not p_file.is_file():
            return

        base_dir = p_file.parent
        with open(p_file, "r", encoding="utf-8") as f:
            for linea in f:
                linea = linea.strip()
                if not linea:
                    continue
                parts = linea.split("  ", 1)
                if len(parts) != 2:
                    continue

                expected_hash, rel_path = parts
                archivo = base_dir / rel_path

                if not archivo.is_file():
                    print(f"[ALGUIEN LO BORRÓ] {rel_path}")
                    continue

                res = _calcular_hash_archivo(archivo, "sha256")
                if res.lower() == expected_hash.lower():
                    print(f"[INTACTO] {rel_path}")
                else:
                    print(f"[MANOSEADO/MODIFICADO] {rel_path}")


def escanear_directorio():
    p = Path(input("Carpeta a escanear: ").strip())
    if not p.is_dir():
        return

    resultados = []
    for archivo in p.rglob("*"):
        if archivo.is_file():
            try:
                res = _calcular_hash_archivo(archivo, "sha256")
                print(f"{archivo.name:<30} | {res}")
                resultados.append({"archivo": str(archivo.relative_to(p)), "sha256": res})
            except (PermissionError, OSError) as e:
                print(f"Imposible leer {archivo.name}: {e}")

    with open("escaneo_directorio.json", "w", encoding="utf-8") as f:
        json.dump(resultados, f, indent=4)


def exportar_reporte(datos):
    if not datos.get("resultados"):
        print("No hay nada que exportar. Corre la opción 1 primero, por favor.")
        return

    fmt = input("Formato (json/csv): ").strip().lower()

    if fmt == "json":
        with open("reporte_hashes.json", "w", encoding="utf-8") as f:
            json.dump(datos, f, indent=4)
        print("Listo. Revisa reporte_hashes.json")
    elif fmt == "csv":
        with open("reporte_hashes.csv", "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["algoritmo", "hash", "tiempo_s", "match"])
            writer.writeheader()
            writer.writerows(datos["resultados"])
        print("Listo. Revisa reporte_hashes.csv")


def main():
    ultimos_datos = {"objetivo": None, "resultados": []}

    while True:
        print("\n--- HASHER TOOL (o lo que sea) ---")
        print("1. Sacar hashes")
        print("2. Buscar duplicados")
        print("3. Consultar VirusTotal")
        print("4. Gestor de checksums")
        print("5. Generar HMAC")
        print("6. Escanear directorio a JSON")
        print("7. Exportar último reporte")
        print("8. Salir de esta tortura")

        op = input("\nElige una opción antes de que colapse el programa: ").strip()

        if op in ("8", "exit", "q"):
            print("Por fin. Adiós.")
            break
        elif op == "1":
            target = input("Pasa la ruta o el texto: ").strip()
            if not target:
                continue
            check = input("Hash esperado (presiona Enter si no te importa): ").strip() or None
            ultimos_datos = procesar_entrada(target, check)
        elif op == "2":
            buscar_duplicados()
        elif op == "3":
            consultar_virustotal()
        elif op == "4":
            gestor_checksums()
        elif op == "5":
            calcular_hmac()
        elif op == "6":
            escanear_directorio()
        elif op == "7":
            exportar_reporte(ultimos_datos)


if __name__ == "__main__":
    main()
