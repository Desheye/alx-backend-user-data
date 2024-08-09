#!/usr/bin/env python3
""" DocDocDocDocDocDoc
"""
from flask import Blueprint

app_views = Blueprint("app_views", __name__, url_prefix="/api/v1")

# Import views after creating app_views
from api.v1.views.index import *  # noqa: E402
from api.v1.views.users import *  # noqa: E402

# If you need to load User data, do it here
from models.user import User  # noqa: E402
User.load_from_file()
