"""
main.py
=======
Entry point for the Phishing Detection API.

Runs the FastAPI application using uvicorn.
"""

import sys

import uvicorn

from src.config import API_HOST, API_PORT, API_RELOAD

if __name__ == "__main__":
    print(f"Starting server at http://{API_HOST}:{API_PORT}")
    try:
        uvicorn.run(
            "src.api.app:app",
            host=API_HOST,
            port=API_PORT,
            reload=API_RELOAD,
            log_level="info",
        )
    except KeyboardInterrupt:
        print("\nShutting down server.")
        sys.exit(0)
