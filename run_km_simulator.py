from qumail.km_simulator.app import create_app
from dotenv import load_dotenv
import os

if __name__ == "__main__":
    load_dotenv()
    host = os.getenv("KM_HOST", "127.0.0.1")
    port = int(os.getenv("KM_PORT", "5001"))
    app = create_app()
    app.run(host=host, port=port, debug=True)
