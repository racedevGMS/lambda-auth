import boto3
import time
import uuid
import bcrypt
from datetime import datetime, timezone
from botocore.exceptions import ClientError

# Initialize DynamoDB
dynamodb = boto3.resource("dynamodb")
users_table = dynamodb.Table("users")
tokens_table = dynamodb.Table("userTokens")


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
            IndexName="email-index",
            KeyConditionExpression="email = :email",
            ExpressionAttributeValues={":email": email},
        )

        items = response.get("Items", [])
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
        response = users_table.get_item(Key={"userId": user_id})
        return response.get("Item")

    except ClientError as e:
        print(f"Error getting user by ID: {e}")
        return None


def get_all_users():
    """
    Get all users from the users table

    Returns:
        dict: {'success': bool, 'users': list} or {'success': bool, 'error': str}
    """
    try:
        response = users_table.scan()
        users = response.get("Items", [])

        # Remove sensitive data from all users
        users_info = []
        for user in users:
            # Convert carNumber to string if it's a number
            car_number = user.get("carNumber")
            if car_number is not None:
                car_number = str(car_number)

            users_info.append(
                {
                    "userId": user.get("userId"),
                    "email": user.get("email"),
                    "firstName": user.get("firstName"),
                    "lastName": user.get("lastName"),
                    "role": user.get("role"),
                    "carNumber": car_number,
                    "appPermissions": user.get("appPermissions", []),
                    "isActive": user.get("isActive", False),
                    "createdAt": user.get("createdAt"),
                    "lastLogin": user.get("lastLogin"),
                }
            )

        return {"success": True, "users": users_info, "count": len(users_info)}

    except ClientError as e:
        print(f"Error getting all users: {e}")
        return {"success": False, "error": f"Failed to get users: {str(e)}"}
    except Exception as e:
        print(f"Unexpected error getting all users: {e}")
        return {"success": False, "error": "Failed to get users"}


def update_last_login(user_id):
    """
    Update user's lastLogin timestamp

    Args:
        user_id: User's ID
    """
    try:
        users_table.update_item(
            Key={"userId": user_id},
            UpdateExpression="SET lastLogin = :now",
            ExpressionAttributeValues={":now": datetime.now(timezone.utc).isoformat()},
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
                "token": token,
                "userId": user_id,
                "issuedAt": now.isoformat(),
                "expiresAt": seven_days_from_now,  # Unix timestamp for TTL
                "lastValidated": now.isoformat(),
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
        response = tokens_table.get_item(Key={"token": token})
        return response.get("Item")

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
        tokens_table.delete_item(Key={"token": token})
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
            Key={"token": token},
            UpdateExpression="SET lastValidated = :now",
            ExpressionAttributeValues={":now": datetime.now(timezone.utc).isoformat()},
        )
    except ClientError as e:
        print(f"Error updating token validation: {e}")


def create_user(email, first_name, last_name, role, car_number=None):
    """
    Create a new user in the users table (without password initially)

    Args:
        email: User's email
        first_name: User's first name
        last_name: User's last name
        role: User role (e.g., 'user', 'admin')
        car_number: Optional car number

    Returns:
        dict: {'success': bool, 'userId': str, 'user': dict} or {'success': bool, 'error': str}
    """
    try:
        # TODO: TESTING ONLY - Remove duplicate email check for testing
        # Check if user already exists
        # existing_user = get_user_by_email(email)
        # if existing_user:
        #     return {"success": False, "error": "User with this email already exists"}

        # Generate user ID and timestamps
        user_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Create user object without password (to be set via verification link)
        new_user = {
            "userId": user_id,
            "email": email,
            "passwordHash": None,  # Will be set when user verifies email
            "firstName": first_name,
            "lastName": last_name,
            "role": role,
            "carNumber": car_number,
            "appPermissions": [],  # Empty list initially
            "createdAt": now,
            "updatedAt": now,
            "lastLogin": None,
            "isActive": False,  # Inactive until email verified and password set
        }

        # Insert into DynamoDB
        users_table.put_item(Item=new_user)

        # Return user info (no sensitive data)
        user_info = {
            "userId": user_id,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "role": role,
            "carNumber": car_number,
            "appPermissions": [],
        }

        return {"success": True, "userId": user_id, "user": user_info}

    except ClientError as e:
        print(f"Error creating user: {e}")
        return {"success": False, "error": f"Failed to create user: {str(e)}"}
    except Exception as e:
        print(f"Unexpected error creating user: {e}")
        return {"success": False, "error": "Failed to create user"}


def verify_and_set_password(user_id, password):
    """
    Verify user and set their password (called from email verification link)

    Args:
        user_id: User's ID
        password: Plain text password (will be hashed)

    Returns:
        dict: {'success': bool} or {'success': bool, 'error': str}
    """
    try:
        # Get user
        user = get_user_by_id(user_id)
        if not user:
            return {"success": False, "error": "User not found"}

        # Hash password
        password_hash = bcrypt.hashpw(
            password.encode("utf-8"), bcrypt.gensalt()
        ).decode("utf-8")

        # Update user: set password and activate account
        users_table.update_item(
            Key={"userId": user_id},
            UpdateExpression="SET passwordHash = :pwd, isActive = :active, updatedAt = :now",
            ExpressionAttributeValues={
                ":pwd": password_hash,
                ":active": True,
                ":now": datetime.now(timezone.utc).isoformat(),
            },
        )

        return {"success": True, "message": "Password set and account activated"}

    except ClientError as e:
        print(f"Error setting password: {e}")
        return {"success": False, "error": f"Failed to set password: {str(e)}"}
    except Exception as e:
        print(f"Unexpected error setting password: {e}")
        return {"success": False, "error": "Failed to set password"}


def update_user_permissions(user_id, app_permissions):
    """
    Update user's app permissions

    Args:
        user_id: User's ID
        app_permissions: List of app permissions

    Returns:
        dict: {'success': bool} or {'success': bool, 'error': str}
    """
    try:
        # Get user to verify they exist
        user = get_user_by_id(user_id)
        if not user:
            return {"success": False, "error": "User not found"}

        # Update permissions
        users_table.update_item(
            Key={"userId": user_id},
            UpdateExpression="SET appPermissions = :perms, updatedAt = :now",
            ExpressionAttributeValues={
                ":perms": app_permissions,
                ":now": datetime.now(timezone.utc).isoformat(),
            },
        )

        return {
            "success": True,
            "message": "Permissions updated",
            "appPermissions": app_permissions,
        }

    except ClientError as e:
        print(f"Error updating permissions: {e}")
        return {"success": False, "error": f"Failed to update permissions: {str(e)}"}
    except Exception as e:
        print(f"Unexpected error updating permissions: {e}")
        return {"success": False, "error": "Failed to update permissions"}


def update_user_role(user_id, role):
    """
    Update user's role

    Args:
        user_id: User's ID
        role: New role (e.g., 'user', 'admin')

    Returns:
        dict: {'success': bool} or {'success': bool, 'error': str}
    """
    try:
        # Get user to verify they exist
        user = get_user_by_id(user_id)
        if not user:
            return {"success": False, "error": "User not found"}

        # Update role
        users_table.update_item(
            Key={"userId": user_id},
            UpdateExpression="SET #role = :role, updatedAt = :now",
            ExpressionAttributeNames={"#role": "role"},
            ExpressionAttributeValues={
                ":role": role,
                ":now": datetime.now(timezone.utc).isoformat(),
            },
        )

        return {"success": True, "message": "Role updated", "role": role}

    except ClientError as e:
        print(f"Error updating role: {e}")
        return {"success": False, "error": f"Failed to update role: {str(e)}"}
    except Exception as e:
        print(f"Unexpected error updating role: {e}")
        return {"success": False, "error": "Failed to update role"}
