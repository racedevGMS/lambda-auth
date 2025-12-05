import json
import os
from auth import login_user, validate_token
from utils import create_response, parse_cookies

def handler(event, context):
    """
    Main Lambda handler for authentication endpoints
    """
    try:
        # Get HTTP method and path
        http_method = event.get('httpMethod', '')
        path = event.get('path', '')
        
        print(f"Request: {http_method} {path}")
        
        # Route to appropriate handler
        if path == '/auth/login' and http_method == 'POST':
            return handle_login(event)
        
        elif path == '/auth/validate' and http_method == 'GET':
            return handle_validate(event)
        
        elif path == '/auth/logout' and http_method == 'POST':
            return handle_logout(event)
        
        else:
            return create_response(404, {'error': 'Endpoint not found'})
            
    except Exception as e:
        print(f"Error: {str(e)}")
        return create_response(500, {'error': 'Internal server error'})


def handle_login(event):
    """Handle user login"""
    try:
        # Parse request body
        body = json.loads(event.get('body', '{}'))
        email = body.get('email')
        password = body.get('password')
        
        if not email or not password:
            return create_response(400, {'error': 'Email and password required'})
        
        # Attempt login
        result = login_user(email, password)
        
        if result['success']:
            # Create cookie with token
            cookie_header = (
                f"token={result['token']}; "
                f"HttpOnly; Secure; SameSite=Strict; "
                f"Max-Age=604800; Path=/"
            )
            
            return create_response(
                200, 
                {
                    'message': 'Login successful',
                    'user': result['user']
                },
                headers={'Set-Cookie': cookie_header}
            )
        else:
            return create_response(401, {'error': result['error']})
            
    except Exception as e:
        print(f"Login error: {str(e)}")
        return create_response(500, {'error': 'Login failed'})


def handle_validate(event):
    """Validate existing token from cookie"""
    try:
        # Get token from cookie
        cookies = parse_cookies(event.get('headers', {}))
        token = cookies.get('token')
        
        if not token:
            return create_response(401, {'error': 'No token provided'})
        
        # Validate token
        result = validate_token(token)
        
        if result['valid']:
            return create_response(200, {
                'valid': True,
                'user': result['user']
            })
        else:
            return create_response(401, {
                'valid': False,
                'error': result['error']
            })
            
    except Exception as e:
        print(f"Validation error: {str(e)}")
        return create_response(500, {'error': 'Validation failed'})


def handle_logout(event):
    """Handle user logout (invalidate token)"""
    try:
        # Get token from cookie
        cookies = parse_cookies(event.get('headers', {}))
        token = cookies.get('token')
        
        if token:
            # TODO: Delete token from userTokens table
            from db import delete_token
            delete_token(token)
        
        # Clear cookie
        cookie_header = (
            "token=; "
            "HttpOnly; Secure; SameSite=Strict; "
            "Max-Age=0; Path=/"
        )
        
        return create_response(
            200,
            {'message': 'Logged out successfully'},
            headers={'Set-Cookie': cookie_header}
        )
        
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return create_response(500, {'error': 'Logout failed'})