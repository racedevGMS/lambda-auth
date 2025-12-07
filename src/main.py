import json
from auth import login_user, validate_token

def handler(event, context):
    """
    Simple Lambda handler - accepts direct JSON events
    
    Login event:
    {
      "action": "login",
      "email": "user@example.com",
      "password": "password123"
    }
    
    Validate event:
    {
      "action": "validate",
      "token": "jwt-token-string"
    }
    
    Logout event:
    {
      "action": "logout",
      "token": "jwt-token-string"
    }
    """
    try:
        action = event.get('action')
        
        if action == 'login':
            return handle_login(event)
        
        elif action == 'validate':
            return handle_validate(event)
        
        elif action == 'logout':
            return handle_logout(event)
        
        else:
            return {
                'success': False,
                'error': 'Invalid action. Must be: login, validate, or logout'
            }
            
    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return {
            'success': False,
            'error': f'Internal error: {str(e)}'
        }


def handle_login(event):
    """Handle user login"""
    try:
        email = event.get('email')
        password = event.get('password')
        
        if not email or not password:
            return {
                'success': False,
                'error': 'Email and password required'
            }
        
        # Attempt login
        result = login_user(email, password)
        return result
            
    except Exception as e:
        print(f"Login error: {str(e)}")
        return {
            'success': False,
            'error': f'Login failed: {str(e)}'
        }


def handle_validate(event):
    """Validate token"""
    try:
        token = event.get('token')
        
        if not token:
            return {
                'valid': False,
                'error': 'Token required'
            }
        
        # Validate token
        result = validate_token(token)
        return result
            
    except Exception as e:
        print(f"Validation error: {str(e)}")
        return {
            'valid': False,
            'error': f'Validation failed: {str(e)}'
        }


def handle_logout(event):
    """Handle user logout"""
    try:
        token = event.get('token')
        
        if not token:
            return {
                'success': False,
                'error': 'Token required'
            }
        
        # Import here to avoid circular import
        from db import delete_token
        
        # Delete token from database
        delete_token(token)
        
        return {
            'success': True,
            'message': 'Logged out successfully'
        }
        
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return {
            'success': False,
            'error': f'Logout failed: {str(e)}'
        }