import json
from auth import login_user, validate_token


def create_response(status_code, body):
    """Create Lambda response"""
    return {"statusCode": status_code, "body": json.dumps(body)}


def handler(event, context):
    """
    Lambda handler for authentication

    Login: {"action": "login", "email": "...", "password": "..."}
    Validate: {"action": "validate", "token": "..."}
    Logout: {"action": "logout", "token": "..."}
    Add User: {"action": "add_user", "email": "...", "firstName": "...", "lastName": "...", "role": "...", "carNumber": "..."}
    Verify & Set Password: {"action": "verify_password", "userId": "...", "password": "..."}
    Update Permissions: {"action": "update_permissions", "userId": "...", "appPermissions": [...]}
    Update Role: {"action": "update_role", "userId": "...", "role": "admin|user", "appPermissions": [...]} (appPermissions optional)
    Get All Users: {"action": "get_all_users"}
    Delete User: {"action": "delete_user", "userId": "..."}
    """
    try:
        # Parse body
        if isinstance(event.get("body"), str):
            body = json.loads(event["body"])
        else:
            body = event

        action = body.get("action")

        if action == "login":
            result = handle_login(body)
            status_code = 200 if result.get("success") else 401
            return create_response(status_code, result)

        elif action == "validate":
            result = handle_validate(body)
            status_code = 200 if result.get("valid") else 401
            return create_response(status_code, result)

        elif action == "logout":
            result = handle_logout(body)
            status_code = 200 if result.get("success") else 400
            return create_response(status_code, result)

        elif action == "add_user":
            result = handle_add_user(body)
            status_code = 201 if result.get("success") else 400
            return create_response(status_code, result)

        elif action == "verify_password":
            result = handle_verify_password(body)
            status_code = 200 if result.get("success") else 400
            return create_response(status_code, result)

        elif action == "update_permissions":
            result = handle_update_permissions(body)
            status_code = 200 if result.get("success") else 400
            return create_response(status_code, result)

        elif action == "get_all_users":
            result = handle_get_all_users(body)
            status_code = 200 if result.get("success") else 400
            return create_response(status_code, result)

        elif action == "update_role":
            result = handle_update_role(body)
            status_code = 200 if result.get("success") else 400
            return create_response(status_code, result)

        elif action == "delete_user":
            result = handle_delete_user(body)
            status_code = 200 if result.get("success") else 400
            return create_response(status_code, result)

        else:
            return create_response(
                400,
                {
                    "success": False,
                    "error": "Invalid action. Must be: login, validate, logout, add_user, verify_password, update_permissions, get_all_users, update_role, or delete_user",
                },
            )

    except Exception as e:
        print(f"Error: {str(e)}")
        import traceback

        traceback.print_exc()
        return create_response(
            500, {"success": False, "error": f"Internal error: {str(e)}"}
        )


def handle_login(body):
    """Handle user login"""
    email = body.get("email")
    password = body.get("password")

    if not email or not password:
        return {"success": False, "error": "Email and password required"}

    # Attempt login
    return login_user(email, password)


def handle_validate(body):
    """Validate token"""
    token = body.get("token")

    if not token:
        return {"valid": False, "error": "Token required"}

    return validate_token(token)


def handle_logout(body):
    """Handle user logout"""
    token = body.get("token")

    if not token:
        return {"success": False, "error": "Token required"}

    # Import here to avoid circular import
    from db import delete_token

    # Delete token from database
    delete_token(token)

    return {"success": True, "message": "Logged out successfully"}


def handle_add_user(body):
    """Handle adding a new user (no password initially)"""
    email = body.get("email")
    first_name = body.get("firstName")
    last_name = body.get("lastName")
    role = body.get("role", "user")  # Default to 'user' role
    car_number = body.get("carNumber")  # Optional

    # Validate required fields
    if not email:
        return {"success": False, "error": "Email required"}

    if not first_name or not last_name:
        return {"success": False, "error": "First name and last name required"}

    # Import here to avoid circular import
    from db import create_user

    # Create the user (without password, inactive)
    return create_user(email, first_name, last_name, role, car_number)


def handle_verify_password(body):
    """Handle user verification and password setting"""
    user_id = body.get("userId")
    password = body.get("password")

    # Validate required fields
    if not user_id:
        return {"success": False, "error": "User ID required"}

    if not password:
        return {"success": False, "error": "Password required"}

    # Import here to avoid circular import
    from db import verify_and_set_password

    # Set password and activate account
    return verify_and_set_password(user_id, password)


def handle_update_permissions(body):
    """Handle updating user permissions"""
    user_id = body.get("userId")
    app_permissions = body.get("appPermissions", [])

    # Validate required fields
    if not user_id:
        return {"success": False, "error": "User ID required"}

    # Import here to avoid circular import
    from db import update_user_permissions

    # Update permissions
    return update_user_permissions(user_id, app_permissions)


def handle_get_all_users(body):
    """Handle getting all users"""
    # Import here to avoid circular import
    from db import get_all_users

    # Get all users
    return get_all_users()


def handle_update_role(body):
    """Handle updating user role"""
    user_id = body.get("userId")
    role = body.get("role")
    app_permissions = body.get("appPermissions")  # Optional

    # Validate required fields
    if not user_id:
        return {"success": False, "error": "User ID required"}

    if not role:
        return {"success": False, "error": "Role required"}

    # Import here to avoid circular import
    from db import update_user_role

    # Update role (and optionally permissions)
    return update_user_role(user_id, role, app_permissions)


def handle_delete_user(body):
    """Handle deleting a user"""
    user_id = body.get("userId")

    # Validate required fields
    if not user_id:
        return {"success": False, "error": "User ID required"}

    # Import here to avoid circular import
    from db import delete_user

    # Delete user
    return delete_user(user_id)
