"""Iniciador de producción para Google Cloud Run y servidores web."""

import os
import uvicorn

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"Iniciando Corrector Pro Server en {host}:{port}...")
    uvicorn.run("server_app:app", host=host, port=port, log_level="info")
