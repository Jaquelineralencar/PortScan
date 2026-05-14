from functools import wraps
from flask import redirect, url_for, flash, abort
from flask_login import current_user
from .rbac import Role

def role_required(required_role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Você precisa estar autenticado.', 'error')
                return redirect(url_for('auth.login'))
            
            if not Role.validate_role(required_role):
                abort(500)
            
            user_level = Role.get_role_level(current_user.role)
            required_level = Role.get_role_level(required_role)
            
            if user_level < required_level:
                flash('Você não tem permissão para acessar esta área.', 'error')
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def permission_required(permission):
  
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Você precisa estar autenticado.', 'error')
                return redirect(url_for('auth.login'))
            
            if not Role.has_permission(current_user.role, permission):
                flash('Você não tem permissão para realizar esta ação.', 'error')
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def scan_target_allowed(target_type):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash('Você precisa estar autenticado.', 'error')
                return redirect(url_for('auth.login'))
            
            if not Role.can_scan_target(current_user.role, target_type):
                flash(f'Você não tem permissão para fazer scan em alvos {target_type}.', 'error')
                abort(403)
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator
