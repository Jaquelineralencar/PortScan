"""
Rotas de autenticação
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user
from database import get_user_by_username, add_user
from auth.rbac import Role
import logging

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = get_user_by_username(username)
        
        if user and user.verify_password(password) and user.is_active:
            login_user(user, remember=request.form.get('remember'))
            logging.info(f'[AUDIT] Usuário {username} (role: {user.role}) fez login')
            return redirect(url_for('dashboard'))
        else:
            flash('Usuário ou senha inválidos.', 'error')
    
    return render_template('login.html')

@auth_bp.route('/logout')
def logout():
    if current_user and current_user.is_authenticated:
        logging.info(f'[AUDIT] Usuário {current_user.username} fez logout')
    logout_user()
    flash('Você foi desconectado.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validações simples
        if not username or len(username) < 3:
            flash('Usuário deve ter pelo menos 3 caracteres.', 'error')
            return redirect(url_for('auth.register'))
        
        if not email or '@' not in email:
            flash('Email inválido.', 'error')
            return redirect(url_for('auth.register'))
        
        if password != confirm_password:
            flash('Senhas não conferem.', 'error')
            return redirect(url_for('auth.register'))
        
        if len(password) < 6:
            flash('Senha deve ter pelo menos 6 caracteres.', 'error')
            return redirect(url_for('auth.register'))
        
        if get_user_by_username(username):
            flash('Usuário já existe.', 'error')
            return redirect(url_for('auth.register'))
        
        # Novo usuário começa como 'operador'
        if add_user(username, email, password, role='operador'):
            logging.info(f'[AUDIT] Novo usuário {username} registrado com role: operador')
            flash('Cadastro realizado com sucesso! Faça login.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('Email já cadastrado.', 'error')
            return redirect(url_for('auth.register'))
    
    return render_template('register.html')
