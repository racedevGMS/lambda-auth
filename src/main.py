import json
from auth import login_user, validate_token

def get_cors_headers():
    """
    Return CORS headers for API Gateway responses
    """
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'OPTIONS,POST,GET'
    }

def create_response(status_code, body):
    """
    Create a properly formatted Lambda response for API Gateway
    """
    return {
        'statusCode': status_code,
        'headers': get_cors_headers(),
        'body': json.dumps(body)
    }

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
            return create_response(status_code, result)

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

    # Validate token
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