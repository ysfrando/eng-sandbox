from flask import Flask, request, jsonify
import jwt
import uuid
import datetime
from functools import wraps
from db import db
from models import User, Client, AccessToken, AuthCode

app = Flask(__name__)

OAUTH_SCOPES = {
    "basic": "Access profile information",
    "post": "Create posts on your behalf",
    "follower_list": "Access your follower list",
    "direct_messages": "Access direct messages"
}

JWT_SECRET = "oauth_secret_key" # In production, usse secure environment variable or reference it from a secure credential manager (e.g, AWS secrets manager)


def require_client_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        client_id = request.headers.get('client_id')
        client_secret = request.headers.get('client_secret')
        
        if not client_id or client_secret:
            return jsonify({"error": "Missing client credentials"}), 401
        
        client = Client.query.filter_by(
            client_id=client_id,
            client_secret=client_secret
        ).first()
        
        if not client:
            return jsonify({"error": "Invalid client credentials"}), 401
        
        return f(client, *args, **kwargs)
    return decorated

@app.route('/oauth/authorize', methods=['GET'])
def authorize():
    # Parameters validation
    client_id = request.headers.get('client_id')
    redirect_uri = request.args.get('redirect_uri')
    scope = request.args.get('scope', 'basic')
    state = request.args.get('state')
    
    # Validate client & redirect_uri in database
    client = Client.query.filter_by(client_id=client_id)
    if not client or redirect_uri not in client.redirect_uri:
        return jsonify({"error": "Invalid client or redirect URI"}), 400
    
    # Check if scope is valid
    requested_scopes = scope.split()
    for s in requested_scopes:
        if s not in OAUTH_SCOPES:
            return jsonify({"error": f"Invalid scope: {s}"}), 400
            
    # In practice, redirect to consent screen
    # For this example, assume consent is given
    auth_code = str(uuid.uuid4())
    
    # Store auth code with associated client_id, redirect_uri, and user info
    # Return auth code to client app via redirect
    redirect_response=f"{redirect_uri}?code={auth_code}"
    if state:
        redirect_response += f"&state={state}"
        
    return jsonify({"redirect": redirect_response})

@app.route('/oauth/token', methods=['POST'])
@require_client_auth
def token(client):
    grant_type = request.form.get('grant_type')
    
    if grant_type == 'authorization_code':
        code = request.form.get('code')
        redirect_uri = request.form.get('redirect_uri')
        
        # Validate code exists and hasn't expired
        auth_code = AuthCode.filter_by(code=code, client_id=client.id).first()
        if not auth_code or auth_code.is_expired():
            return jsonify({"error": "Invalid authorization code"})
        
        # Create OAuth access token
        access_token = create_access_token(auth_code.user_id, auth_code.scope, client.id)
        refresh_token = str(uuid.uuid4())
        
        # Save tokens to database
        token = AccessToken(
            access_token=access_token,
            refresh_token=refresh_token,
            client_id=client.id,
            user_id=auth_code.user_id,
            scope=auth_code.scope,
            expires_at=datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        )
        
        db.session.add(token)
        db.session.delete(auth_code) # One-time use
        db.session.commit()
        
        return jsonify({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token,
            "scope": auth_code.scope
        })
        
    elif grant_type == 'refresh_token':
        refresh_token = request.form.get('refresh_token')
        
        # Validate refresh token
        token = AccessToken.query.filter_by(
            refresh_token=refresh_token,
            client_id=client.id
        ).first()
        
        if not token:
            return jsonify({"error": "Invalid refresh token"}), 400

        new_access_token = create_access_token(token.user_id, token.scope, client.id)
        
        # Update in database
        token.access_token = new_access_token
        token.expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        db.session.commit()
        
        return jsonify({
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_at": 3600,
            "scope": token.scope
        })
    
    return jsonify({"error": "Unsupported grant type"}), 400
    
def create_access_token(user_id, scope, client_id):
    payload = {
        "sub": user_id,
        "scope": scope,
        "aud": client_id,
        "iss": "instagram.com",
        "iat": datetime.datetime.utcnow(),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")
