"""
====================================================
Network Intrusion Detection System (NIDS)

Module : Dashboard App Factory

Initializes the Flask application for the dashboard.
====================================================
"""

import os
from flask import Flask

# Get absolute path to the templates and static folders
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
template_dir = os.path.join(parent_dir, 'templates')
static_dir = os.path.join(parent_dir, 'static')

app = Flask(
    __name__,
    template_folder=template_dir,
    static_folder=static_dir
)

# Suppress Flask default logging to keep console output clean
import logging
try:
    from flask import cli
    cli.show_server_banner = lambda *args: None
except Exception:
    pass

log = logging.getLogger('werkzeug')
log.disabled = True

from dashboard import routes
