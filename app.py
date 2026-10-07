from flask import Flask

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'dev-placeholder-change-later'

    @app.route('/')
    def index():
        return "ULTRON is running."

    @app.route('/health')
    def health():
        return {"status": "ok"}

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)