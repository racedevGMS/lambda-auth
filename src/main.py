import json
from auth import login_user, validate_token

def create_response(status_code, body, set_cookie=None):
    """Create Lambda response"""
    response = {
        'statusCode': status_code,
        'body': json.dumps(body)
    }

    if set_cookie:
        response['headers'] = {'Set-Cookie': set_cookie}

    return response

def create_auth_cookie(token):
    """Create auth cookie - 7 days, HttpOnly, Secure"""
    max_age = 7 * 24 * 60 * 60
    return f'authToken={token}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age={max_age}'

def handler(event, context):
    """
    Lambda handler for authentication

    Login: {"action": "login", "email": "...", "password": "..."}
    Validate: {"action": "validate", "token": "..."} or use cookie
    Logout: {"action": "logout", "token": "..."} or use cookie
    """
    try:
        # Parse body
        if isinstance(event.get('body'), str):
            body = json.loads(event['body'])
        else:
            body = event

        action = body.get('action')

        if action == 'login':
            result = handle_login(body)
            status_code = 200 if result.get('success') else 401
            cookie = create_auth_cookie(result['token']) if result.get('success') else None
            return create_response(status_code, result, cookie)

        elif action == 'validate':
            result = handle_validate(body)
            status_code = 200 if result.get('valid') else 401
            return create_response(status_code, result)

        elif action == 'logout':
            result = handle_logout(body)
            status_code = 200 if result.get('success') else 400
            return create_response(status_code, result)

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


def handle_validate(body):
    """Validate token"""
    token = body.get('token')

    if not token:
        return {
            'valid': False,
            'error': 'Token required'
        }

    return validate_token(token)


def handle_logout(body):
    """Handle user logout"""
    token = body.get('token')

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