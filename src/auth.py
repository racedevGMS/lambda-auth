import os
import jwt
import bcrypt
from datetime import datetime, timedelta, timezone
from db import get_user_by_email, store_token, get_token, update_last_login

JWT_SECRET = os.environ.get('JWT_SECRET')
if not JWT_SECRET:
    raise ValueError("JWT_SECRET environment variable not set")

def login_user(email, password):
    """
    Authenticate user and create session token
    
    Args:
        email: User's email
        password: User's password (plain text)
        
    Returns:
        dict: {'success': bool, 'token': str, 'user': dict} or {'success': bool, 'error': str}
    """
    try:
        # Get user from database
        user = get_user_by_email(email)
        
        if not user:
            return {'success': False, 'error': 'Invalid credentials'}
        
        # Check if user is active
        if not user.get('isActive', False):
            return {'success': False, 'error': 'Account is disabled'}
        
        # Verify password
        password_hash = user['passwordHash']
        if not bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8')):
            return {'success': False, 'error': 'Invalid credentials'}
        
        # Create JWT token
        token_payload = {
            'userId': user['userId'],
            'email': user['email'],
            'role': user['role'],
            'appPermissions': user['appPermissions'],
            'iat': datetime.now(timezone.utc),
            'exp': datetime.now(timezone.utc) + timedelta(days=7)
        }
        
        token = jwt.encode(token_payload, JWT_SECRET, algorithm='HS256')
        
        # Store token in database
        store_token(token, user['userId'])
        
        # Update last login
        update_last_login(user['userId'])
        
        # Return success with user info (no sensitive data)
        user_info = {
            'userId': user['userId'],
            'email': user['email'],
            'firstName': user['firstName'],
            'lastName': user['lastName'],
            'role': user['role'],
            'appPermissions': user['appPermissions']
        }
        
        return {
            'success': True,
            'token': token,
            'user': user_info
        }
        
    except Exception as e:
        print(f"Login error: {str(e)}")
        return {'success': False, 'error': 'Login failed'}


def validate_token(token):
    """
    Validate JWT token
    
    Args:
        token: JWT token string
        
    Returns:
        dict: {'valid': bool, 'user': dict} or {'valid': bool, 'error': str}
    """
    try:
        # Verify JWT signature and expiration
        payload = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        
        # Check if token exists in database (not revoked)
        token_data = get_token(token)
        
        if not token_data:
            return {'valid': False, 'error': 'Token revoked or invalid'}
        
        # Return user info from token
        user_info = {
            'userId': payload['userId'],
            'email': payload['email'],
            'role': payload['role'],
            'appPermissions': payload['appPermissions']
        }
        
        return {
            'valid': True,
            'user': user_info
        }
        
    except jwt.ExpiredSignatureError:
        return {'valid': False, 'error': 'Token expired'}
    except jwt.InvalidTokenError:
        return {'valid': False, 'error': 'Invalid token'}
    except Exception as e:
        print(f"Validation error: {str(e)}")
        return {'valid': False, 'error': 'Validation failed'}