import os
from datetime import timedelta

class Config:
    SECRET_KEY = 'portscan-secret-key-2026'
    SESSION_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)
    
    # Database
    SQLALCHEMY_DATABASE_URI = 'sqlite:///portscan.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    LOG_DIR = os.path.join(os.path.dirname(__file__), 'logs')
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False

class TestingConfig(Config):
    DEBUG = True
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

config = {
    'development': DevelopmentConfig,
    'testing': TestingConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
