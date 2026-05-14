import os
import logging
from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, current_user

from database import create_tables, get_user_by_id, get_user_by_username, add_user
from routes.auth_routes import auth_bp
from routes.scanner_routes import scanner_bp
from routes.admin_routes import admin_bp

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/portscan.log'),
        logging.StreamHandler()
    ]
)

def create_app(config_name='development'):
    app = Flask(__name__)
    
    app.config['SECRET_KEY'] = 'portscan-secret-key-2026'
    app.config['SESSION_COOKIE_HTTPONLY'] = True
    
    create_tables()
    
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Por favor, faça login para continuar.'
    
    @login_manager.user_loader
    def load_user(user_id):
        return get_user_by_id(int(user_id))
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(admin_bp)
    
    create_demo_users()
    
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('scanner.dashboard'))
        return redirect(url_for('auth.login'))
    
    @app.route('/dashboard')
    def dashboard():
        return redirect(url_for('scanner.dashboard'))
    
    @app.errorhandler(403)
    def forbidden(e):
        return render_template('error.html', 
                             error='Acesso Negado',
                             message='Você não tem permissão para acessar esta área.'), 403
    
    @app.errorhandler(404)
    def not_found(e):
        return render_template('error.html',
                             error='Página Não Encontrada',
                             message='A página que você procura não existe.'), 404
    
    @app.errorhandler(500)
    def server_error(e):
        return render_template('error.html',
                             error='Erro do Servidor',
                             message='Ocorreu um erro interno. Por favor, tente novamente.'), 500
    
    return app

def create_demo_users():
    demo_users = [
        {
            'username': 'admin',
            'email': 'admin@portscan.local',
            'password': 'senha123',
            'role': 'administrador',
            'department': 'Segurança'
        },
        {
            'username': 'gestor',
            'email': 'gestor@portscan.local',
            'password': 'senha123',
            'role': 'gestor',
            'department': 'Segurança'
        },
        {
            'username': 'analista',
            'email': 'analista@portscan.local',
            'password': 'senha123',
            'role': 'analista',
            'department': 'Segurança'
        },
        {
            'username': 'operador',
            'email': 'operador@portscan.local',
            'password': 'senha123',
            'role': 'operador',
            'department': 'Operações'
        }
    ]
    
    for user_data in demo_users:
        if not get_user_by_username(user_data['username']):
            if add_user(
                user_data['username'],
                user_data['email'],
                user_data['password'],
                user_data['role'],
                user_data['department']
            ):
                logging.info(f'[INIT] Usuário demo criado: {user_data["username"]} ({user_data["role"]})')

if __name__ == '__main__':
    app = create_app(os.getenv('FLASK_ENV', 'development'))
    logging.info('[STARTUP] portScan iniciando...')
    app.run(debug=True, host='127.0.0.1', port=5000)
