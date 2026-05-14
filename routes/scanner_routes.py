from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from flask_login import login_required, current_user
from database import add_scan_log, get_scan_log, get_user_scans, delete_scan_log, update_scan_log, get_all_users
from auth.rbac import Role
from auth.decorators import permission_required
from scanner.port_scanner import PortScanner
from datetime import datetime
import logging
import json

scanner_bp = Blueprint('scanner', __name__, url_prefix='/scan')

@scanner_bp.route('/dashboard')
@login_required
def dashboard():
    page = request.args.get('page', 1, type=int)
    scans, total = get_user_scans(current_user.id, page, per_page=10)
    
    # Simular paginação
    class Paginated:
        def __init__(self, items, total, page, per_page):
            self.items = items
            self.total = total
            self.pages = (total + per_page - 1) // per_page
            self.page = page
            self.per_page = per_page
        
        def __iter__(self):
            return iter(self.items)
    
    scans = Paginated(scans, total, page, 10)
    
    role_info = Role.ROLES_HIERARCHY.get(current_user.role, {})
    permissions = Role.get_permissions(current_user.role)
    
    return render_template('dashboard.html', 
                         scans=scans, 
                         role_info=role_info,
                         permissions=permissions)

@scanner_bp.route('/new', methods=['GET', 'POST'])
@login_required
def new_scan():
    """Interface para criar novo scan"""
    
    if not Role.has_permission(current_user.role, 'escanear_rede_interna'):
        flash('Você não tem permissão para criar scans.', 'error')
        return redirect(url_for('scanner.dashboard'))
    
    if request.method == 'POST':
        target_ip = request.form.get('target_ip')
        ports = request.form.get('ports', 'common')
        scan_type = request.form.get('scan_type', 'basic')
        
        # Validações
        if not target_ip:
            flash('IP de destino é obrigatório.', 'error')
            return redirect(url_for('scanner.new_scan'))
        
        if not PortScanner.validate_ip(target_ip):
            flash('IP inválido.', 'error')
            return redirect(url_for('scanner.new_scan'))
        
        # Verificar permissões por tipo de alvo
        if target_ip.startswith('192.168') or target_ip.startswith('10.'):
            target_type = 'internal'
        else:
            target_type = 'external'
        
        if not Role.can_scan_target(current_user.role, target_type):
            tipo_texto = 'interna' if target_type == 'internal' else 'externa' if target_type == 'external' else 'crítica'
            flash(f'Você não tem permissão para escanear IPs de rede {tipo_texto}.', 'error')
            logging.warning(f'[AUDIT] {current_user.username} tentou scan não autorizado em {target_ip}')
            return redirect(url_for('scanner.dashboard'))
        
        # Criar registro de scan
        scan_id = add_scan_log(current_user.id, target_ip, ports=ports, scan_type=scan_type)
        
        # Executar scan
        try:
            scanner = PortScanner(timeout=2)
            hostname = scanner.get_hostname(target_ip)
            
            if ports == 'common':
                result = scanner.scan_common_ports(target_ip)
            else:
                try:
                    start_port, end_port = map(int, ports.split('-'))
                    result = scanner.scan_port_range(target_ip, start_port, end_port)
                except:
                    update_scan_log(scan_id, 'failed', error_message='Formato de portas inválido')
                    flash('Formato de portas inválido. Use: 80-443', 'error')
                    return redirect(url_for('scanner.new_scan'))
            
            if result['status'] == 'success':
                update_scan_log(
                    scan_id,
                    'completed',
                    results=json.dumps(result['results']),
                    completed_at=datetime.utcnow()
                )
                logging.info(f'[AUDIT] {current_user.username} completou scan em {target_ip}')
            else:
                update_scan_log(
                    scan_id,
                    'failed',
                    error_message=result.get('message', 'Erro desconhecido'),
                    completed_at=datetime.utcnow()
                )
        
        except Exception as e:
            update_scan_log(
                scan_id,
                'failed',
                error_message=str(e),
                completed_at=datetime.utcnow()
            )
            logging.error(f'[AUDIT] Erro em scan: {str(e)}')
        
        flash('Scan completado com sucesso!', 'success')
        return redirect(url_for('scanner.view_scan', scan_id=scan_id))
    
    role_info = Role.ROLES_HIERARCHY.get(current_user.role, {})
    can_scan_external = Role.has_permission(current_user.role, 'escanear_rede_externa')
    
    return render_template('scan.html', role_info=role_info, can_scan_external=can_scan_external)

@scanner_bp.route('/view/<int:scan_id>')
@login_required
def view_scan(scan_id):
    """Visualiza detalhes de um scan"""
    scan = get_scan_log(scan_id)
    
    if not scan:
        flash('Scan não encontrado.', 'error')
        return redirect(url_for('scanner.dashboard'))
    
    # Verificar se o usuário é dono do scan ou administrador
    if scan.user_id != current_user.id and current_user.role != 'administrador':
        flash('Você não tem acesso a este scan.', 'error')
        return redirect(url_for('scanner.dashboard'))
    
    results = json.loads(scan.results) if scan.results else {}
    
    return render_template('scan_details.html', scan=scan, results=results)

@scanner_bp.route('/delete/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    """Deleta um scan"""
    scan = get_scan_log(scan_id)
    
    if not scan:
        flash('Scan não encontrado.', 'error')
        return redirect(url_for('scanner.dashboard'))
    
    # Verificar permissão
    if scan.user_id != current_user.id and current_user.role != 'administrador':
        flash('Você não tem permissão para deletar este scan.', 'error')
        return redirect(url_for('scanner.dashboard'))
    
    logging.info(f'[AUDIT] {current_user.username} deletou scan ID {scan_id}')
    delete_scan_log(scan_id)
    
    flash('Scan deletado com sucesso.', 'success')
    return redirect(url_for('scanner.dashboard'))
