#!/usr/bin/env python3
""" DocDocDocDocDocDoc
"""
from flask import Blueprint

app_views = Blueprint("app_views", __name__, url_prefix="/api/v1")

# Import views after creating app_views
from api.v1.views.index import *
from api.v1.views.users import *

# If you need to load User data, do it here
from models.user import User
User.load_from_file()
