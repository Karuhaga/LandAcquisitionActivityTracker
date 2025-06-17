import os
from flask import Flask, session, jsonify, redirect, flash, request, url_for
from flask_mail import Mail
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, current_user
from BankReconciliation.database import get_db_connection
from datetime import timedelta


app = Flask(__name__)
app.config['SECRET_KEY'] = '4f4726d4610186d9cedfd91b'

# Uploading Files
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')  # Use absolute path
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'txt', 'xls', 'xlsx', 'doc', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)  # Ensure folder exists


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# Flask-Login setup
bcrypt = Bcrypt(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login_page"
login_manager.login_message_category = "info"
login_manager.session_protection = "strong"  # Set to 'strong' or 'None' if needed
app.app_context().push()

# Mail Configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'  # e.g., smtp.gmail.com
app.config['MAIL_PORT'] = 587  # or 465 for SSL
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'kardel111@gmail.com'
app.config['MAIL_PASSWORD'] = 'wove wiiy mhns ogid'
app.config['MAIL_DEFAULT_SENDER'] = 'kardel111@gmail.com'
app.config['MAIL_TIMEOUT'] = 60

mail = Mail(app)

# Import routes after app creation to avoid circular imports
from BankReconciliation import routes


@app.context_processor
def inject_menu_items():
    """Dynamically inject menu items based on user's roles."""
    if not current_user.is_authenticated:
        return {'menu_items': []}

    conn = get_db_connection()
    if conn is None:
        return {'menu_items': []}  # No menu items if the DB connection fails

    cursor = conn.cursor()

    # Get the role IDs assigned to the current user
    cursor.execute("SELECT role_id FROM user_role WHERE user_id = ? AND start_datetime <= GETDATE() AND "
                   "expiry_datetime >= GETDATE()", (current_user.id, ))
    user_roles = [row[0] for row in cursor.fetchall()]

    if not user_roles:  # If user has no roles, return an empty menu
        conn.close()
        return {'menu_items': []}

    # Fetch workflows assigned to these roles
    cursor.execute("""
        SELECT mi.name
        FROM workflow_breakdown wb
        LEFT OUTER JOIN menu_item mi ON wb.menu_item_id = mi.id
        LEFT OUTER JOIN role_workflow_breakdown rwb ON wb.id = rwb.workflow_breakdown_id 
        WHERE rwb.role_id IN ({})
    """.format(",".join("?" * len(user_roles))), tuple(user_roles))

    menu_items = [row[0] for row in cursor.fetchall()]
    conn.close()

    return {'menu_items': menu_items}


@app.context_processor
def inject_pending_approvals_count():
    if current_user.is_authenticated:
        from BankReconciliation.models import FileUpload  # Moved inside the function
        count = FileUpload.get_reconciliations_pending_approval_count(current_user.id)
    else:
        count = 0
    return dict(pending_approvals_count=count)


# Set session timeout duration
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)  # Change to your preferred timeout


# Ensure sessions are marked as permanent
@app.before_request
def make_session_permanent():
    session.permanent = True


# Detect session expiration
@app.before_request
def check_session_expiry():
    if request.endpoint not in ['login_page', 'static'] and not current_user.is_authenticated:
        # Check if it's an AJAX request
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({"redirect": url_for('login_page'), "message": "Your session expired. You have been "
                                                                          "redirected to login page."}), 401
        else:
            flash("Your session expired. You have been redirected to login page.", "warning")
            return redirect(url_for('login_page'))
