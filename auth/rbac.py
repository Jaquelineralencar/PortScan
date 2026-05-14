"""
RBAC Hierárquico - Role-Based Access Control
Estrutura de permissões:
- Administrador > Gestor > Analista > Operador
"""

class Role:
    """Define roles e suas permissões"""
    
    # Hierarquia: Administrador herda todas as permissões de níveis inferiores
    ROLES_HIERARCHY = {
        'administrador': {
            'level': 4,
            'description': 'Administrador - Controle total do sistema',
            'permissions': [
                'escanear_rede_interna',
                'escanear_rede_externa',
                'escanear_infraestrutura_critica',
                'criar_escaneamentos_agressivos',
                'gerenciar_usuarios',
                'visualizar_logs_auditoria',
                'configurar_sistema',
                'deletar_resultados_scan',
            ]
        },
        'gestor': {
            'level': 3,
            'description': 'Gestor de Segurança - Escopo moderado',
            'permissions': [
                'escanear_rede_interna',
                'escanear_infraestrutura_critica',
                'criar_escaneamentos_agressivos',
                'visualizar_logs_auditoria',
                'gerar_relatorios',
            ]
        },
        'analista': {
            'level': 2,
            'description': 'Analista de Segurança - Escopo limitado',
            'permissions': [
                'escanear_rede_interna',
                'criar_escaneamentos_basicos',
                'visualizar_proprios_scans',
                'exportar_resultados',
            ]
        },
        'operador': {
            'level': 1,
            'description': 'Operador - Escopo restrito',
            'permissions': [
                'visualizar_proprios_scans',
                'criar_escaneamentos_basicos',
            ]
        }
    }
    
    @staticmethod
    def get_permissions(role):
        """Retorna todas as permissões para um role"""
        if role not in Role.ROLES_HIERARCHY:
            return []
        
        role_data = Role.ROLES_HIERARCHY[role]
        permissions = set(role_data['permissions'])
        
        # Herança de permissões de roles inferiores
        for r, data in Role.ROLES_HIERARCHY.items():
            if data['level'] < role_data['level']:
                permissions.update(data['permissions'])
        
        return list(permissions)
    
    @staticmethod
    def get_role_level(role):
        """Retorna o nível hierárquico do role"""
        return Role.ROLES_HIERARCHY.get(role, {}).get('level', 0)
    
    @staticmethod
    def has_permission(user_role, permission):
        """Verifica se um role tem uma permissão específica"""
        permissions = Role.get_permissions(user_role)
        return permission in permissions
    
    @staticmethod
    def can_scan_target(user_role, target_type):
        """
        Verifica se um usuário pode fazer scan em um tipo de alvo
        target_type: 'internal', 'external', 'critical'
        """
        permission_map = {
            'internal': 'escanear_rede_interna',
            'external': 'escanear_rede_externa',
            'critical': 'escanear_infraestrutura_critica'
        }
        
        required_permission = permission_map.get(target_type)
        if not required_permission:
            return False
        
        return Role.has_permission(user_role, required_permission)
    
    @staticmethod
    def validate_role(role):
        """Valida se um role existe"""
        return role in Role.ROLES_HIERARCHY
