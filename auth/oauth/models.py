import datetime
import bcrypt
import secrets
from db import db

### User Model ###
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    def set_password(self, password):
        """Hashes and sets the password."""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode(), salt).decode()

    def check_password(self, password):
        """Verifies a password against the stored hash."""
        return bcrypt.checkpw(password.encode(), self.password_hash.encode())

    def __repr__(self):
        return f"<User(id={self.id}, username={self.username}, email={self.email})>"


### OAuth Client Model ###
class Client(db.Model):
    __tablename__ = "oauth_clients"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    client_id = db.Column(db.String(100), unique=True, nullable=False, default=lambda: secrets.token_urlsafe(32))
    client_secret = db.Column(db.String(100), unique=True, nullable=False, default=lambda: secrets.token_urlsafe(64))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    redirect_uri = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

    user = db.relationship("User", backref="clients")

    def __repr__(self):
        return f"<OAuthClient(id={self.id}, client_id={self.client_id}, user_id={self.user_id})>"


### OAuth Authorization Code Model ###
class AuthCode(db.Model):
    __tablename__ = "oauth_auth_codes"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    code = db.Column(db.String(100), unique=True, nullable=False, default=lambda: secrets.token_urlsafe(32))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    client_id = db.Column(db.Integer, db.ForeignKey("oauth_clients.id"), nullable=False)
    redirect_uri = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.datetime.utcnow() + datetime.timedelta(minutes=10))
    used = db.Column(db.Boolean, default=False)  # Mark as used after exchange

    user = db.relationship("User", backref="auth_codes")
    client = db.relationship("OAuthClient", backref="auth_codes")

    def is_expired(self):
        """Checks if the auth code is expired."""
        return datetime.datetime.utcnow() > self.expires_at

    def mark_used(self):
        """Marks the auth code as used."""
        self.used = True

    def __repr__(self):
        return f"<AuthCode(user_id={self.user_id}, client_id={self.client_id}, used={self.used})>"


### OAuth Access Token Model ###
class AccessToken(db.Model):
    __tablename__ = "oauth_access_tokens"
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    access_token = db.Column(db.String(100), unique=True, nullable=False, default=lambda: secrets.token_urlsafe(40))
    refresh_token = db.Column(db.String(100), unique=True, nullable=False, default=lambda: secrets.token_urlsafe(40))
    client_id = db.Column(db.Integer, db.ForeignKey("oauth_clients.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    scope = db.Column(db.Text, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.datetime.utcnow() + datetime.timedelta(hours=1))
    revoked = db.Column(db.Boolean, default=False)

    user = db.relationship("User", backref="access_tokens")
    client = db.relationship("OAuthClient", backref="access_tokens")

    def is_expired(self):
        """Checks if the token is expired."""
        return datetime.datetime.utcnow() > self.expires_at

    def revoke(self):
        """Revokes the token."""
        self.revoked = True

    def __repr__(self):
        return f"<AccessToken(user_id={self.user_id}, client_id={self.client_id}, revoked={self.revoked})>"
