import json

def create_response(status_code, body, headers=None):
    """
    Create API Gateway Lambda proxy response
    
    Args:
        status_code: HTTP status code
        body: Response body (will be JSON encoded)
        headers: Optional additional headers
        
    Returns:
        dict: Lambda proxy response object
    """
    default_headers = {
        'Content-Type': 'application/json',
        'Access-Control-Allow-Origin': '*',  # Configure this properly for production
        'Access-Control-Allow-Credentials': 'true',
        'Access-Control-Allow-Headers': 'Content-Type,Authorization',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS'
    }
    
    if headers:
        default_headers.update(headers)
    
    return {
        'statusCode': status_code,
        'headers': default_headers,
        'body': json.dumps(body)
    }


def parse_cookies(headers):
    """
    Parse cookies from request headers
    
    Args:
        headers: Request headers dict
        
    Returns:
        dict: Parsed cookies as key-value pairs
    """
    cookies = {}
    
    # Check both 'Cookie' and 'cookie' (case insensitive)
    cookie_header = headers.get('Cookie') or headers.get('cookie')
    
    if cookie_header:
        for cookie in cookie_header.split(';'):
            cookie = cookie.strip()
            if '=' in cookie:
                key, value = cookie.split('=', 1)
                cookies[key.strip()] = value.strip()
    
    return cookies