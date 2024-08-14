#!/usr/bin/env python3
"""Defines API endpoints for the Authentication Service"""
from auth import Auth
from flask import Flask, jsonify, request, abort, redirect

app = Flask(__name__)
AUTH = Auth()

@app.route('/', methods=['GET'])
def hello_world() -> str:
    """ Root endpoint for the authentication service API """
    msg = {"message": "Bienvenue"}
    return jsonify(msg)

@app.route('/users', methods=['POST'])
def register_user() -> str:
    """Creates a new user account if the email is not already registered"""
    try:
        email = request.form['email']
        password = request.form['password']
    except KeyError:
        abort(400)
    try:
        user = AUTH.register_user(email, password)
    except ValueError:
        return jsonify({"message": "email already registered"}), 400
    msg = {"email": email, "message": "user created"}
    return jsonify(msg)

@app.route('/sessions', methods=['POST'])
def log_in() -> str:
    """ Authenticates a user and issues a session ID """
    try:
        email = request.form['email']
        password = request.form['password']
    except KeyError:
        abort(400)
    if not AUTH.valid_login(email, password):
        abort(401)
    session_id = AUTH.create_session(email)
    msg = {"email": email, "message": "logged in"}
    response = jsonify(msg)
    response.set_cookie("session_id", session_id)
    return response

@app.route('/sessions', methods=['DELETE'])
def log_out() -> str:
    """Terminates a user session
    If the session exists, end it and redirect to the root.
    If the session doesn't exist, return a 403 HTTP status.
    """
    session_id = request.cookies.get("session_id", None)
    if session_id is None:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    AUTH.destroy_session(user.id)
    return redirect('/')

@app.route('/profile', methods=['GET'])
def profile() -> str:
    """ Retrieves user profile information
    Returns a 200 HTTP status and JSON payload if the user exists,
    otherwise returns a 403 HTTP status.
    """
    session_id = request.cookies.get("session_id", None)
    if session_id is None:
        abort(403)
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        abort(403)
    msg = {"email": user.email}
    return jsonify(msg), 200

@app.route('/reset_password', methods=['POST'])
def reset_password() -> str:
    """Initiates password reset process
    Returns a 403 status code if the email is not registered.
    Otherwise, generates a token and returns a 200 HTTP status with JSON payload.
    """
    try:
        email = request.form['email']
    except KeyError:
        abort(403)
    try:
        reset_token = AUTH.get_reset_password_token(email)
    except ValueError:
        abort(403)
    msg = {"email": email, "reset_token": reset_token}
    return jsonify(msg), 200

@app.route('/reset_password', methods=['PUT'])
def update_password() -> str:
    """ Completes password reset process
    Returns:
        - 400 for invalid request
        - 403 for invalid reset token
        - 200 and JSON payload for successful update
    """
    try:
        email = request.form['email']
        reset_token = request.form['reset_token']
        new_password = request.form['new_password']
    except KeyError:
        abort(400)
    try:
        AUTH.update_password(reset_token, new_password)
    except ValueError:
        abort(403)
    msg = {"email": email, "message": "Password updated"}
    return jsonify(msg), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000", threaded=False)
