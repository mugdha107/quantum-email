from dotenv import load_dotenv
from qumail.web_app.app import create_app

if __name__ == "__main__":
    load_dotenv()
    app = create_app()
    app.run(host="127.0.0.1", port=5002, debug=True)
