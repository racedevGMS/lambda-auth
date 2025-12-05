import boto3
import time
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Initialize DynamoDB
dynamodb = boto3.resource('dynamodb')
users_table = dynamodb.Table('users')
tokens_table = dynamodb.Table('userTokens')


def get_user_by_email(email):
    """
    Query user by email using GSI
    
    Args:
        email: User's email address
        
    Returns:
        dict: User object or None if not found
    """
    try:
        response = users_table.query(
            IndexName='email-index',
            KeyConditionExpression='email = :email',
            ExpressionAttributeValues={
                ':email': email
            }
        )
        
        items = response.get('Items', [])
        return items[0] if items else None
        
    except ClientError as e:
        print(f"Error querying user by email: {e}")
        return None


def get_user_by_id(user_id):
    """
    Get user by userId
    
    Args:
        user_id: User's ID
        
    Returns:
        dict: User object or None if not found
    """
    try:
        response = users_table.get_item(Key={'userId': user_id})
        return response.get('Item')
        
    except ClientError as e:
        print(f"Error getting user by ID: {e}")
        return None


def update_last_login(user_id):
    """
    Update user's lastLogin timestamp
    
    Args:
        user_id: User's ID
    """
    try:
        users_table.update_item(
            Key={'userId': user_id},
            UpdateExpression='SET lastLogin = :now',
            ExpressionAttributeValues={
                ':now': datetime.now(timezone.utc).isoformat()
            }
        )
    except ClientError as e:
        print(f"Error updating last login: {e}")


def store_token(token, user_id):
    """
    Store authentication token in userTokens table
    
    Args:
        token: JWT token string
        user_id: User's ID
    """
    try:
        now = datetime.now(timezone.utc)
        seven_days_from_now = int(time.time()) + (7 * 24 * 60 * 60)
        
        tokens_table.put_item(
            Item={
                'token': token,
                'userId': user_id,
                'issuedAt': now.isoformat(),
                'expiresAt': seven_days_from_now,  # Unix timestamp for TTL
                'lastValidated': now.isoformat()
            }
        )
    except ClientError as e:
        print(f"Error storing token: {e}")
        raise


def get_token(token):
    """
    Get token from userTokens table
    
    Args:
        token: JWT token string
        
    Returns:
        dict: Token object or None if not found
    """
    try:
        response = tokens_table.get_item(Key={'token': token})
        return response.get('Item')
        
    except ClientError as e:
        print(f"Error getting token: {e}")
        return None


def delete_token(token):
    """
    Delete token from userTokens table (logout)
    
    Args:
        token: JWT token string
    """
    try:
        tokens_table.delete_item(Key={'token': token})
    except ClientError as e:
        print(f"Error deleting token: {e}")


def update_token_validation(token):
    """
    Update lastValidated timestamp for token
    
    Args:
        token: JWT token string
    """
    try:
        tokens_table.update_item(
            Key={'token': token},
            UpdateExpression='SET lastValidated = :now',
            ExpressionAttributeValues={
                ':now': datetime.now(timezone.utc).isoformat()
            }
        )
    except ClientError as e:
        print(f"Error updating token validation: {e}")