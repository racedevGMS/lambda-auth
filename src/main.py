import json
import os
from auth import login_user, validate_token

def get_cors_headers():
    """
    Return CORS headers for API Gateway responses
    Note: When using credentials (cookies), origin cannot be '*'
    """
    # Get allowed origin from environment variable or use a default
    # In production, set this to your frontend domain
    allowed_origin = os.environ.get('ALLOWED_ORIGIN', '*')

    return {
        'Access-Control-Allow-Origin': allowed_origin,
        'Access-Control-Allow-Headers': 'Content-Type,Authorization,Cookie',
        'Access-Control-Allow-Methods': 'OPTIONS,POST,GET',
        'Access-Control-Allow-Credentials': 'true'
    }

def create_response(status_code, body, set_cookie=None):
    """
    Create a properly formatted Lambda response for API Gateway

    Args:
        status_code: HTTP status code
        body: Response body (will be JSON stringified)
        set_cookie: Optional Set-Cookie header value
    """
    headers = get_cors_headers()

    if set_cookie:
        headers['Set-Cookie'] = set_cookie

    return {
        'statusCode': status_code,
        'headers': headers,
        'body': json.dumps(body)
    }

def create_auth_cookie(token):
    """
    Create a secure authentication cookie

    Args:
        token: JWT token string

    Returns:
        str: Set-Cookie header value
    """
    # 7 days in seconds
    max_age = 7 * 24 * 60 * 60

    # HttpOnly: prevents JavaScript access (XSS protection)
    # Secure: only sent over HTTPS
    # SameSite=Strict: CSRF protection
    # Max-Age: cookie expiration in seconds
    return f'authToken={token}; HttpOnly; Secure; SameSite=Strict; Max-Age={max_age}; Path=/'

def create_logout_cookie():
    """
    Create a cookie that expires immediately (for logout)

    Returns:
        str: Set-Cookie header value that clears the cookie
    """
    return 'authToken=; HttpOnly; Secure; SameSite=Strict; Max-Age=0; Path=/'

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
        # Handle OPTIONS request for CORS preflight
        if event.get('httpMethod') == 'OPTIONS':
            return create_response(200, {'message': 'OK'})

        # Parse body if it's a string (from API Gateway)
        if isinstance(event.get('body'), str):
            body = json.loads(event['body'])
        else:
            body = event

        action = body.get('action')

        if action == 'login':
            result = handle_login(body)
            status_code = 200 if result.get('success') else 401

            # Set authentication cookie if login successful
            cookie = create_auth_cookie(result['token']) if result.get('success') else None
            return create_response(status_code, result, set_cookie=cookie)

        elif action == 'validate':
            result = handle_validate(body, event)
            status_code = 200 if result.get('valid') else 401
            return create_response(status_code, result)

        elif action == 'logout':
            result = handle_logout(body, event)
            status_code = 200 if result.get('success') else 400

            # Clear the authentication cookie
            cookie = create_logout_cookie() if result.get('success') else None
            return create_response(status_code, result, set_cookie=cookie)

        else:
            return create_response(400, {
                'success': False,
                'error': 'Invalid action. Must be: login, validate, or logout'
            })

    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return create_response(500, {
            'success': False,
            'error': f'Internal error: {str(e)}'
        })


def handle_login(body):
    """Handle user login"""
    email = body.get('email')
    password = body.get('password')

    if not email or not password:
        return {
            'success': False,
            'error': 'Email and password required'
        }

    # Attempt login
    return login_user(email, password)


def get_token_from_request(body, event):
    """
    Extract token from request body or cookie

    Args:
        body: Parsed request body
        event: Lambda event object

    Returns:
        str: Token string or None
    """
    # First check body
    token = body.get('token')
    if token:
        return token

    # Then check cookies
    cookies = event.get('headers', {}).get('Cookie', '')
    if cookies:
        for cookie in cookies.split(';'):
            cookie = cookie.strip()
            if cookie.startswith('authToken='):
                return cookie.split('=', 1)[1]

    return None


def handle_validate(body, event):
    """Validate token from body or cookie"""
    token = get_token_from_request(body, event)

    if not token:
        return {
            'valid': False,
            'error': 'Token required'
        }

    # Validate token
    return validate_token(token)


def handle_logout(body, event):
    """Handle user logout"""
    token = get_token_from_request(body, event)

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