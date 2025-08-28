"""
API Blueprint Registry
Centralizes all API blueprint imports for easy management
"""

from .files import files_bp
from .analysis import analysis_bp
from .reports import reports_bp
from .rules import rules_bp
from .containers import containers_bp
from .config import config_bp
from .threat_hunting import threat_hunting_bp

# List of all API blueprints for easy registration
API_BLUEPRINTS = [
    files_bp,
    analysis_bp, 
    reports_bp,
    rules_bp,
    containers_bp,
    config_bp,
    threat_hunting_bp
]

def register_api_blueprints(app):
    """
    Convenience function to register all API blueprints with a Flask app
    
    Args:
        app: Flask application instance
    """
    for blueprint in API_BLUEPRINTS:
        app.register_blueprint(blueprint)

__all__ = [
    'files_bp',
    'analysis_bp', 
    'reports_bp',
    'rules_bp',
    'containers_bp',
    'config_bp',
    'threat_hunting_bp',
    'API_BLUEPRINTS',
    'register_api_blueprints'
]