"""
Rotas de Administração - Gerenciamento de Usuários
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_required, current_user
from database import (get_all_users, update_user_role, update_user_status, count_stats, get_all_scans,
                      add_access_log, get_access_logs, get_user_by_id)
from auth.rbac import Role
from auth.decorators import role_required
import logging

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.route('/users')
@login_required
@role_required('gestor')  # Gestor e Admin podem acessar
def manage_users():
    """Página de gerenciamento de usuários"""
    users = get_all_users()
    role_hierarchy = Role.ROLES_HIERARCHY
    
    return render_template('admin/manage_users.html', 
                         users=users, 
                         role_hierarchy=role_hierarchy,
                         current_role_level=Role.get_role_level(current_user.role))

@admin_bp.route('/users/<int:user_id>/promote', methods=['POST'])
@login_required
@role_required('gestor')
def promote_user(user_id):
    """Promove um usuário para um role superior"""
    users = get_all_users()
    user = next((u for u in users if u.id == user_id), None)
    
    if not user:
        flash('Usuário não encontrado.', 'error')
        return redirect(url_for('admin.manage_users'))
    
    new_role = request.form.get('new_role')
    
    # Validações
    if not Role.validate_role(new_role):
        flash('Role inválido.', 'error')
        return redirect(url_for('admin.manage_users'))
    
    # ⚠️ PROTEÇÃO CRÍTICA: Apenas admin pode modificar outro admin
    if user.role == 'administrador' and current_user.role != 'administrador':
        flash('Apenas administradores podem modificar a função de outro administrador.', 'error')
        logging.warning(f'[AUDIT] ACESSO NEGADO: {current_user.username} tentou promover admin {user.username}')
        add_access_log(
            admin_user_id=current_user.id,
            target_user_id=user.id,
            action_type='role_change_denied',
            old_role=user.role,
            new_role=new_role,
            description=f'Tentativa não autorizada de promoção negada'
        )
        return redirect(url_for('admin.manage_users'))
    
    # Gestor pode promover até seu próprio nível
    # Admin pode promover para qualquer nível
    current_user_level = Role.get_role_level(current_user.role)
    new_role_level = Role.get_role_level(new_role)
    
    if current_user.role != 'administrador' and new_role_level >= current_user_level:
        flash('Você não pode promover para um role igual ou superior ao seu.', 'error')
        logging.warning(f'[AUDIT] Tentativa não autorizada: {current_user.username} tentou promover {user.username} para {new_role}')
        add_access_log(
            admin_user_id=current_user.id,
            target_user_id=user.id,
            action_type='role_change_denied',
            old_role=user.role,
            new_role=new_role,
            description=f'Tentativa de promoção para role não autorizado'
        )
        return redirect(url_for('admin.manage_users'))
    
    old_role = user.role
    update_user_role(user.id, new_role)
    
    # Registra a mudança no banco de dados
    add_access_log(
        admin_user_id=current_user.id,
        target_user_id=user.id,
        action_type='role_change',
        old_role=old_role,
        new_role=new_role,
        description=f'Usuário promovido de {old_role} para {new_role}'
    )
    
    logging.info(f'[AUDIT] {current_user.username} promoveu {user.username} de {old_role} para {new_role}')
    flash(f'Usuário {user.username} promovido de {old_role} para {new_role}.', 'success')
    
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/<int:user_id>/demote', methods=['POST'])
@login_required
@role_required('gestor')
def demote_user(user_id):
    """Rebaixa um usuário para um role inferior"""
    users = get_all_users()
    user = next((u for u in users if u.id == user_id), None)
    
    if not user:
        flash('Usuário não encontrado.', 'error')
        return redirect(url_for('admin.manage_users'))
    
    new_role = request.form.get('new_role')
    
    # Validações
    if not Role.validate_role(new_role):
        flash('Role inválido.', 'error')
        return redirect(url_for('admin.manage_users'))
    
    # ⚠️ PROTEÇÃO CRÍTICA: Apenas admin pode modificar outro admin
    if user.role == 'administrador' and current_user.role != 'administrador':
        flash('Apenas administradores podem modificar a função de outro administrador.', 'error')
        logging.warning(f'[AUDIT] ACESSO NEGADO: {current_user.username} tentou rebaixar admin {user.username}')
        add_access_log(
            admin_user_id=current_user.id,
            target_user_id=user.id,
            action_type='role_change_denied',
            old_role=user.role,
            new_role=new_role,
            description=f'Tentativa não autorizada de rebaixamento negada'
        )
        return redirect(url_for('admin.manage_users'))
    
    # Gestor pode rebaixar até seu próprio nível
    # Admin pode rebaixar para qualquer nível
    current_user_level = Role.get_role_level(current_user.role)
    new_role_level = Role.get_role_level(new_role)
    
    if current_user.role != 'administrador' and new_role_level >= current_user_level:
        flash('Você não pode rebaixar para um role igual ou superior ao seu.', 'error')
        logging.warning(f'[AUDIT] Tentativa não autorizada: {current_user.username} tentou rebaixar {user.username} para {new_role}')
        add_access_log(
            admin_user_id=current_user.id,
            target_user_id=user.id,
            action_type='role_change_denied',
            old_role=user.role,
            new_role=new_role,
            description=f'Tentativa de rebaixamento para role não autorizado'
        )
        return redirect(url_for('admin.manage_users'))
    
    old_role = user.role
    update_user_role(user.id, new_role)
    
    # Registra a mudança no banco de dados
    add_access_log(
        admin_user_id=current_user.id,
        target_user_id=user.id,
        action_type='role_change',
        old_role=old_role,
        new_role=new_role,
        description=f'Usuário rebaixado de {old_role} para {new_role}'
    )
    
    logging.info(f'[AUDIT] {current_user.username} rebaixou {user.username} de {old_role} para {new_role}')
    flash(f'Usuário {user.username} rebaixado de {old_role} para {new_role}.', 'success')
    
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/users/<int:user_id>/toggle-status', methods=['POST'])
@login_required
@role_required('gestor')
def toggle_user_status(user_id):
    """Ativa ou desativa um usuário"""
    users = get_all_users()
    user = next((u for u in users if u.id == user_id), None)
    
    if not user:
        flash('Usuário não encontrado.', 'error')
        return redirect(url_for('admin.manage_users'))
    
    # ⚠️ PROTEÇÃO: Não permitir desativar administrador (exceto a si mesmo)
    if user.role == 'administrador' and user.id != current_user.id:
        flash('Não é possível desativar o administrador.', 'error')
        return redirect(url_for('admin.manage_users'))
    
    # PROTEÇÃO: Apenas admin pode desativar/ativar outro admin
    if user.role == 'administrador' and current_user.role != 'administrador':
        flash('Apenas administradores podem modificar status de outro administrador.', 'error')
        logging.warning(f'[AUDIT] ACESSO NEGADO: {current_user.username} tentou modificar status do admin {user.username}')
        add_access_log(
            admin_user_id=current_user.id,
            target_user_id=user.id,
            action_type='status_change_denied',
            old_status=user.is_active,
            description=f'Tentativa não autorizada de mudança de status negada'
        )
        return redirect(url_for('admin.manage_users'))
    
    new_status = not user.is_active
    old_status = user.is_active
    update_user_status(user.id, new_status)
    
    # Registra a mudança de status no banco de dados
    add_access_log(
        admin_user_id=current_user.id,
        target_user_id=user.id,
        action_type='status_change',
        old_status=old_status,
        new_status=new_status,
        description=f'Usuário {"ativado" if new_status else "desativado"}'
    )
    
    status_text = 'ativado' if new_status else 'desativado'
    logging.info(f'[AUDIT] {current_user.username} {status_text} o usuário {user.username}')
    flash(f'Usuário {user.username} foi {status_text}.', 'success')
    
    return redirect(url_for('admin.manage_users'))

@admin_bp.route('/audit-logs')
@login_required
@role_required('administrador')  # Apenas administrador
def audit_logs():
    """Visualiza logs de auditoria"""
    page = request.args.get('page', 1, type=int)
    access_logs, total = get_access_logs(page=page, per_page=50)
    
    # Enriquece os logs com nomes de usuários
    for log in access_logs:
        log.admin_user = get_user_by_id(log.admin_user_id)
        log.target_user = get_user_by_id(log.target_user_id)
    
    return render_template('admin/audit_logs.html', 
                         access_logs=access_logs,
                         page=page,
                         total=total,
                         per_page=50)

@admin_bp.route('/statistics')
@login_required
@role_required('gestor')
def statistics():
    """Estatísticas do sistema"""
    stats = count_stats()
    
    # Usuários por role
    users = get_all_users()
    users_by_role = {}
    for user in users:
        users_by_role[user.role] = users_by_role.get(user.role, 0) + 1
    
    # Scans por usuário (top 10)
    scans, _ = get_all_scans(page=1, per_page=1000)
    scans_by_user = {}
    for scan in scans:
        for user in users:
            if user.id == scan.user_id:
                scans_by_user[user.username] = scans_by_user.get(user.username, 0) + 1
                break
    
    scans_by_user = sorted(scans_by_user.items(), key=lambda x: x[1], reverse=True)[:10]
    
    stats['users_by_role'] = users_by_role
    stats['scans_by_user'] = scans_by_user
    success_rate = (stats['completed_scans'] / stats['total_scans'] * 100) if stats['total_scans'] > 0 else 0
    stats['success_rate'] = round(success_rate, 1)
    
    return render_template('admin/statistics.html', stats=stats)
