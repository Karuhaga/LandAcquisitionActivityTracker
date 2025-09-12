from functools import wraps
from flask import request, redirect, url_for, flash
from flask_login import current_user
from ActivityTracker.models import get_db_connection


def role_required(*workflow_names):
    """Decorator to restrict access to users with at least one of the required workflows."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated:
                flash("Please log in first.", "warning")
                return redirect(url_for('login_page'))

            # Fetch user roles from the database
            conn = get_db_connection()
            if conn is None:
                flash("Database connection failed.", "danger")
                return redirect(url_for('login_page'))

            cursor = conn.cursor()

            # Get the role IDs assigned to the current user
            cursor.execute("SELECT role_id FROM user_role WHERE user_id = ?", (current_user.id,))
            user_roles = [row[0] for row in cursor.fetchall()]  # List of role IDs

            if not user_roles:  # If user has no roles, deny access
                flash("Access Denied: No assigned roles.", "danger")
                conn.close()
                return redirect(url_for('login_page'))

            # Get allowed workflow breakdown IDs for these roles
            cursor.execute("""
                SELECT wb.id 
                FROM workflow_breakdown wb
                LEFT OUTER JOIN role_workflow_breakdown rwb ON wb.id = rwb.workflow_breakdown_id 
                WHERE rwb.role_id IN ({})
            """.format(",".join("?" * len(user_roles))), tuple(user_roles))

            allowed_workflows = {row[0] for row in cursor.fetchall()}  # Set of workflow breakdown IDs
            conn.close()

            # Check if any required workflow ID is in the allowed list
            if not any(workflow in allowed_workflows for workflow in workflow_names):
                flash("You do not have permission to access this section.", "danger")
                return redirect(url_for('dashboard_page'))

            return f(*args, **kwargs)

        return decorated_function

    return decorator
