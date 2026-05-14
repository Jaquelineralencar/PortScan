import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime

DATABASE_PATH = 'portscan.db'

def get_connection():
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row 
    return conn

def create_tables():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analista' NOT NULL,
            department TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            target_ip TEXT NOT NULL,
            target_hostname TEXT,
            ports TEXT,
            scan_type TEXT DEFAULT 'basic',
            status TEXT DEFAULT 'pending',
            results TEXT,
            error_message TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            completed_at TEXT,
            duration_seconds INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')

    conn.commit()
    conn.close()

class User:
    def __init__(self, id, username, email, password_hash, role, department, is_active, created_at):
        self.id = id
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.role = role
        self.department = department
        self.is_active = is_active
        self.created_at = created_at
        self.is_authenticated = True
        self.is_active = bool(is_active)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_id(self):
        return str(self.id)

def get_user_by_id(user_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(*row)
    return None

def get_user_by_username(username):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return User(*row)
    return None

def add_user(username, email, password, role='analista', department=None):
    conn = get_connection()
    cursor = conn.cursor()
    password_hash = generate_password_hash(password)
    try:
        cursor.execute('''
            INSERT INTO users (username, email, password_hash, role, department)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, email, password_hash, role, department))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def update_user_role(user_id, new_role):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET role = ? WHERE id = ?', (new_role, user_id))
    conn.commit()
    conn.close()

def update_user_status(user_id, is_active):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET is_active = ? WHERE id = ?', (int(is_active), user_id))
    conn.commit()
    conn.close()

def get_all_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    rows = cursor.fetchall()
    conn.close()
    return [User(*row) for row in rows]

class ScanLog:
    def __init__(self, id, user_id, target_ip, target_hostname, ports, scan_type, status, results, error_message, created_at, completed_at, duration_seconds):
        self.id = id
        self.user_id = user_id
        self.target_ip = target_ip
        self.target_hostname = target_hostname
        self.ports = ports
        self.scan_type = scan_type
        self.status = status
        self.results = results
        self.error_message = error_message
        self.created_at = created_at
        self.completed_at = completed_at
        self.duration_seconds = duration_seconds

def add_scan_log(user_id, target_ip, target_hostname=None, ports=None, scan_type='basic'):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO scan_logs (user_id, target_ip, target_hostname, ports, scan_type, status)
        VALUES (?, ?, ?, ?, ?, 'pending')
    ''', (user_id, target_ip, target_hostname, ports, scan_type))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def get_scan_log(scan_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM scan_logs WHERE id = ?', (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return ScanLog(*row)
    return None

def get_user_scans(user_id, page=1, per_page=10):
    conn = get_connection()
    cursor = conn.cursor()
    offset = (page - 1) * per_page
    cursor.execute('''
        SELECT * FROM scan_logs 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
    ''', (user_id, per_page, offset))
    rows = cursor.fetchall()
    
    cursor.execute('SELECT COUNT(*) FROM scan_logs WHERE user_id = ?', (user_id,))
    total = cursor.fetchone()[0]
    conn.close()
    
    return [ScanLog(*row) for row in rows], total

def get_all_scans(page=1, per_page=10):
    conn = get_connection()
    cursor = conn.cursor()
    offset = (page - 1) * per_page
    cursor.execute('''
        SELECT * FROM scan_logs 
        ORDER BY created_at DESC 
        LIMIT ? OFFSET ?
    ''', (per_page, offset))
    rows = cursor.fetchall()
    
    cursor.execute('SELECT COUNT(*) FROM scan_logs')
    total = cursor.fetchone()[0]
    conn.close()
    
    return [ScanLog(*row) for row in rows], total

def update_scan_log(scan_id, status, results=None, error_message=None, completed_at=None, duration_seconds=None):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE scan_logs 
        SET status = ?, results = ?, error_message = ?, completed_at = ?, duration_seconds = ?
        WHERE id = ?
    ''', (status, results, error_message, completed_at, duration_seconds, scan_id))
    conn.commit()
    conn.close()

def delete_scan_log(scan_id):
    """Deleta um scan log"""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM scan_logs WHERE id = ?', (scan_id,))
    conn.commit()
    conn.close()

def count_stats():
    conn = get_connection()
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM users')
    total_users = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scan_logs')
    total_scans = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scan_logs WHERE status = "completed"')
    completed_scans = cursor.fetchone()[0]
    
    cursor.execute('SELECT COUNT(*) FROM scan_logs WHERE status = "failed"')
    failed_scans = cursor.fetchone()[0]
    
    conn.close()
    
    return {
        'total_users': total_users,
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans,
    }