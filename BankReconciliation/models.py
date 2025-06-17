import pyodbc
from sqlalchemy import null

from BankReconciliation import app, login_manager
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime
from BankReconciliation.database import get_db_connection
from BankReconciliation import mail  # Import mail from __init__.py
from flask_mail import Message

bcrypt = Bcrypt(app)  # Initialize bcrypt


@login_manager.user_loader
def load_user(username):
    return User.get_by_username(username)  # User lookup


# User model for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, fname, mname, sname, password_hash, email_address, is_activated):
        self.id = id
        self.username = username
        self.fname = fname
        self.mname = mname
        self.sname = sname
        self.password_hash = password_hash
        self.email_address = email_address
        self.is_activated = is_activated
        self.roles = self.get_roles()

    def get_roles(self):
        """Fetch user roles from the database."""
        conn = get_db_connection()
        if conn is None:
            return []  # Return an empty list if the database connection fails

        cursor = conn.cursor()

        try:
            cursor.execute(
                "SELECT r.name FROM role r INNER JOIN user_role ur ON r.id = ur.role_id WHERE ur.user_id = ?",
                (self.id,))
            return [row[0] for row in cursor.fetchall()]  # Return a list of role names
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_by_username(username):
        conn = get_db_connection()
        if conn is None:
            return None  # Return None if the database connection fails

        cursor = conn.cursor()
        cursor.execute("SELECT ID, Username, Fname, Mname, Sname, Password, Email, is_active"
                       " FROM users WHERE Username = ?",
                       (username,))
        row = cursor.fetchone()
        conn.close()

        if row:
            return User(*row)
        return None

    @staticmethod
    def load_user(self, username):
        """Load user from database by user_id."""
        conn = get_db_connection()
        if conn is None:
            return None  # Return None if the database connection fails

        cursor = conn.cursor()

        try:
            cursor.execute("SELECT ID, Username, Fname, Mname, Sname, Password, Email FROM users WHERE Username = ?",
                           (username,))
            row = cursor.fetchone()
            if row:
                return User(row.id, row.username, row.fname, row.mname, row.sname, row.password,
                            row.email)  # Create a User object
            return None
        except Exception as e:
            print("Database error:", e)
            return None
        finally:
            cursor.close()
            conn.close()

    def get_id(self):
        return self.username  # Ensure Flask-Login gets username instead of an integer ID

    @staticmethod
    def hash_password(password):
        return bcrypt.generate_password_hash(password).decode('utf-8')  # Hash password

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)  # Verify password

    def has_permission(self, work_flow_breakdown_name):
        # Check if the user has permission for a specific workflow breakdown
        return any(
            work_flow_breakdown_name in [wfb.name for r in self.roles for wfb in r.workflows]
        )


class UserSummary:
    def __init__(self, id=None, username=None, name=None, email_address=None, email=None, organisation_unit_tier_name=None, organisation_unit_name=None, status=None, fname=None, mname=None, sname=None, password=None, is_active=None):
        self.id = id
        self.username = username
        self.name = name
        self.email_address = email_address
        self.email = email
        self.organisation_unit_tier_name = organisation_unit_tier_name
        self.organisation_unit_name = organisation_unit_name
        self.status = status
        self.fname = fname
        self.mname = mname
        self.sname = sname
        self.password = password
        self.is_active = is_active

    @staticmethod
    def get_all_users_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT 
                            Username AS username, 
                            LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name, 
                            Email AS email_address, 
                            out.name AS organisation_unit_tier_name, 
                            ou.name AS organisation_unit_name,
                            CASE 
                                WHEN u.is_active = 1 THEN 'Active' 
                                ELSE 'Disabled' 
                            END AS status
                        FROM users u 
                        LEFT OUTER JOIN organisation_unit ou ON u.organisation_unit_id = ou.id
                        LEFT OUTER JOIN organisation_unit_tier out ON u.organisation_unit_tier_id = out.id
                        ORDER BY u.Username;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            user_details = [
                UserSummary(username=row.username, name=row.name, email_address=row.email_address, organisation_unit_tier_name=row.organisation_unit_tier_name, organisation_unit_name=row.organisation_unit_name, status=row.status)
                for row in result
            ]
            return user_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_organisation_unit_tier():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                SELECT id, name FROM organisation_unit_tier ORDER BY name
            """
            cursor.execute(query, )
            result = cursor.fetchall()

            org_unit = [
                UserSummary(id=row.id, name=row.name)
                for row in result
            ]
            return org_unit
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_organisation_units():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                SELECT id, name FROM organisation_unit ORDER BY name
            """
            cursor.execute(query, )
            result = cursor.fetchall()

            org_unit = [
                UserSummary(id=row.id, name=row.name)
                for row in result
            ]
            return org_unit
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_organisation_units_by_tier(org_unit_tier_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                SELECT id, name FROM organisation_unit WHERE org_unit_tier_id = ? ORDER BY name
            """
            cursor.execute(query, (org_unit_tier_id,))
            result = cursor.fetchall()

            org_unit = [
                UserSummary(id=row.id, name=row.name)
                for row in result
            ]
            return org_unit
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_user(username, email, fname, mname, sname, password, org_unit_tier_id, org_unit_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

            query = """
                INSERT INTO users (username, fname, mname, sname, password, email, organisation_unit_id, organisation_unit_tier_id, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(query, (username, fname, mname, sname, password_hash, email, org_unit_id, org_unit_tier_id, 1))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new user: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_user(username, email, fname, mname, sname, org_unit_tier_id, org_unit_id, is_active):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE users
                SET fname = ?, mname = ?, sname = ?, email = ?, organisation_unit_id = ?, organisation_unit_tier_id = ?, is_active = ?
                WHERE username = ?
            """
            cursor.execute(query, (fname, mname, sname, email, org_unit_id, org_unit_tier_id, is_active, username))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update user: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def username_exists(username):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM users WHERE username = ?"
            cursor.execute(query, (username,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check username existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_user_account_details(username):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT username, fname, mname, sname, email, out.name AS organisation_unit_tier_name, ou.name AS organisation_unit_name, is_active 
                        FROM users u
                        LEFT OUTER JOIN organisation_unit ou ON u.organisation_unit_id = ou.id
                        LEFT OUTER JOIN organisation_unit_tier out ON u.organisation_unit_tier_id = out.id
                        WHERE Username = ?
                    """
            cursor.execute(query, (username,))
            result = cursor.fetchall()

            user_details = [
                {
                    "username": row.username,
                    "fname": row.fname,
                    "mname": row.mname,
                    "sname": row.sname,
                    "email": row.email,
                    "organisation_unit_tier_name": row.organisation_unit_tier_name,
                    "organisation_unit_name": row.organisation_unit_name,
                    "is_active": row.is_active
                }
                for row in result
            ]

            return user_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_user_password(username, password):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            password = bcrypt.generate_password_hash(password).decode('utf-8')

            query = """
                UPDATE users SET password = ? WHERE username = ?
            """
            cursor.execute(query, (password, username))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update user password: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_usernames():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                SELECT id, username FROM users ORDER BY username
            """
            cursor.execute(query, )
            result = cursor.fetchall()

            usernames = [
                UserSummary(id=row.id, username=row.username)
                for row in result
            ]
            return usernames
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()


class EmailHelper(UserMixin):
    def __init__(self):
        self.id = id

    @staticmethod
    def send_submitted_reconciliations_email(current_fname, next_approver_email, next_approver_fname, files):
        subject = "Bank Reconwiliations Submitted for Approval"

        # Email body with Poppins font and inline styles
        body = f"""
        <html>
        <head>
            <link href="https:get_reconciliations_pending_approval_report/fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Poppins', sans-serif; margin: 20px; color: #333;">
            <p style="font-size: 14px;">Dear {next_approver_fname},</p>
            <p style="font-size: 14px;">{current_fname} has submitted reconciliation files that require your approval.</p>

            <p style="font-size: 14px; font-weight: bold; margin-top: 25px;">Submitted Reconciliations:</p>

            <table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center; padding: 8px;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Bank Account ID</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Year</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Month</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">File Name</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, file in enumerate(files, start=1):
            body += f"""
                    <tr>
                        <td style="border: 1px solid #ddd; text-align: center; padding: 8px;">{index}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('bank_account_id')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('year')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('month')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('file_name')}</td>
                    </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 25px; margin-bottom: 25px;">
                🔗 <a href="http://127.0.0.1:5000/approve-reconciliations" 
                style="color: #4270a8; text-decoration: none; font-weight: 600;">Click here to review and approve</a>
            </p>

            <p style="font-size: 14px;">Your timely action is appreciated.</p>

            <p style="font-size: 14px;">
                <strong>Best Regards,</strong><br>
                Bank Reconciliation Tracker<br>
                📧 support@yourcompany.com | ☎️ +256 [Your Contact Number]
            </p>
        </body>
        </html>
        """

        try:
            msg = Message(subject, recipients=[next_approver_email])
            msg.html = body  # Set HTML content
            mail.send(msg)
            print(f"Approval email sent to {next_approver_email}")
        except Exception as e:
            print(f"Error sending email: {e}")

    @staticmethod
    def send_email_notification_to_next_approver(current_fname, next_approver_email, next_approver_fname, files):
        subject = "Bank Reconciliations Approval"

        # Email body with Poppins font and inline styles
        body = f"""
        <html>
        <head>
            <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Poppins', sans-serif; margin: 20px; color: #333;">
            <p style="font-size: 14px;">Dear {next_approver_fname},</p>
            <p style="font-size: 14px;">Please be notified that the following reconciliations have been forwarded to you for approval:</p>

            <table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center; padding: 8px;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Bank Account ID</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Year</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Month</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">File Name</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, file in enumerate(files, start=1):
            body += f"""
                    <tr>
                        <td style="border: 1px solid #ddd; text-align: center; padding: 8px;">{index}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('bank_account_id')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('year')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('month')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('file_name')}</td>
                    </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 25px; margin-bottom: 25px;">
                🔗 <a href="http://127.0.0.1:5000/approve-reconciliations" 
                style="color: #4270a8; text-decoration: none; font-weight: 600;">Click here to review and approve</a>
            </p>

            <p style="font-size: 14px;">Your timely action is appreciated.</p>

            <p style="font-size: 14px;">
                <strong>Best Regards,</strong><br>
                Bank Reconciliation Tracker<br>
                📧 support@yourcompany.com | ☎️ +256 [Your Contact Number]
            </p>
        </body>
        </html>
        """

        try:
            msg = Message(subject, recipients=[next_approver_email])
            msg.html = body  # Set HTML content
            mail.send(msg)
            print(f"Approval email sent to {next_approver_email}")
        except Exception as e:
            print(f"Error sending email: {e}")

    @staticmethod
    def send_approval_summary_emails(current_fname, initiator_approver_email, initiator_approver_fname, files, action):
        action_for_email_subject = "Approval" if action == "approved" else "Rejection"
        subject = "Bank Reconciliation(s) " + action_for_email_subject

        # Email body with Poppins font and inline styles
        body = f"""
        <html>
        <head>
            <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Poppins', sans-serif; margin: 20px; color: #333;">
            <p style="font-size: 14px;">Dear {initiator_approver_fname},</p>
            <p style="font-size: 14px;">The following reconciliation(s) that you submitted have been {action} by {current_fname}.</p>

            <table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center; padding: 8px;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Bank Account ID</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Year</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Month</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">File Name</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, file in enumerate(files, start=1):
            body += f"""
                    <tr>
                        <td style="border: 1px solid #ddd; text-align: center; padding: 8px;">{index}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('bank_account_id')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('year')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('month')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('file_name')}</td>
                    </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 25px; margin-bottom: 25px;">
                🔗 <a href="http://127.0.0.1:5000/submitted-reconciliations" 
                style="color: #4270a8; text-decoration: none; font-weight: 600;">Click here to view the approved reconciliations</a>
            </p>

            <p style="font-size: 14px;">
                <strong>Best Regards,</strong><br>
                Bank Reconciliation Tracker<br>
                📧 support@yourcompany.com | ☎️ +256 [Your Contact Number]
            </p>
        </body>
        </html>
        """

        try:
            msg = Message(subject, recipients=[initiator_approver_email])
            msg.html = body  # Set HTML content
            mail.send(msg)
            print(f"Email of approval sent to {initiator_approver_email}")
        except Exception as e:
            print(f"Error sending email: {e}")

    @staticmethod
    def email_reminder_to_initiator_reconciliations_pending_submission(current_fname, initiator_approver_email, details):
        subject = "Bank Reconciliations Pending Submission"

        # Email body with Poppins font and inline styles
        body = f"""
        <html>
        <head>
            <link href="https:get_reconciliations_pending_submission/fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Poppins', sans-serif; margin: 20px; color: #333;">
            <p style="font-size: 14px;">Dear {current_fname},</p>
            <p style="font-size: 14px;">The following reconciliations are pending your submission.</p>

            <p style="font-size: 14px; font-weight: bold; margin-top: 25px;">Reconciliations Pending Submission:</p>

            <table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center; padding: 8px;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Bank Account</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Year</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Month</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Days Overdue</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, detail in enumerate(details, start=1):
            body += f"""
                    <tr>
                        <td style="border: 1px solid #ddd; text-align: center; padding: 8px;">{index}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.bank_account}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.year}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.month}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.days_overdue}</td>
                    </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 25px; margin-bottom: 25px;">
                🔗 <a href="http://127.0.0.1:5000/submit-reconciliations" 
                style="color: #4270a8; text-decoration: none; font-weight: 600;">Click here to submit</a>
            </p>

            <p style="font-size: 14px;">Your timely action is appreciated.</p>

            <p style="font-size: 14px;">
                <strong>Best Regards,</strong><br>
                Bank Reconciliation Tracker<br>
                📧 support@yourcompany.com | ☎️ +256 [Your Contact Number]
            </p>
        </body>
        </html>
        """

        try:
            msg = Message(subject, recipients=[initiator_approver_email])
            msg.html = body  # Set HTML content
            mail.send(msg)
            print(f"Email reminder about Pending Reconciliation(s) Submission sent to Initiator, {initiator_approver_email}")
        except Exception as e:
            print(f"Error sending email: {e}")

    @staticmethod
    def email_reminder_to_approver_reconciliations_pending_submission(approver_fname, approver_email, details):
        subject = "Bank Reconciliations Pending Submission"

        # Email body with Poppins font and inline styles
        body = f"""
        <html>
        <head>
            <link href="https:get_reconciliations_pending_submission/fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Poppins', sans-serif; margin: 20px; color: #333;">
            <p style="font-size: 14px;">Dear {approver_fname},</p>
            <p style="font-size: 14px;">The following reconciliations are pending submission.</p>

            <p style="font-size: 14px; font-weight: bold; margin-top: 25px;">Reconciliations Pending Submission:</p>

            <table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center; padding: 8px;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Bank Account</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Year</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Month</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Days Overdue</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Responsible Person(s)</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, detail in enumerate(details, start=1):
            body += f"""
                    <tr>
                        <td style="border: 1px solid #ddd; text-align: center; padding: 8px;">{index}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.bank_account}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.year}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.month}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.days_overdue}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.responsible_users}</td>
                    </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 25px; margin-bottom: 25px;">
                🔗 <a href="http://127.0.0.1:5000/report-reconciliations-pending-submission" 
                style="color: #4270a8; text-decoration: none; font-weight: 600;">Click here to view report on reconciliations pending submission</a>
            </p>

            <p style="font-size: 14px;">Your timely action is appreciated.</p>

            <p style="font-size: 14px;">
                <strong>Best Regards,</strong><br>
                Bank Reconciliation Tracker<br>
                📧 support@yourcompany.com | ☎️ +256 [Your Contact Number]
            </p>
        </body>
        </html>
        """

        try:
            msg = Message(subject, recipients=[approver_email])
            msg.html = body  # Set HTML content
            mail.send(msg)
            print(f"Email reminder about Pending Reconciliation(s) Submission sent to Supervisor, {approver_email}")
        except Exception as e:
            print(f"Error sending email: {e}")

    @staticmethod
    def email_reminder_to_approve_submitted_reconciliations(approver_fname, approver_email, details):
        subject = "Bank Reconciliations Pending Approval"

        # Email body with Poppins font and inline styles
        body = f"""
        <html>
        <head>
            <link href="https:get_reconciliations_pending_submission/fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Poppins', sans-serif; margin: 20px; color: #333;">
            <p style="font-size: 14px;">Dear {approver_fname},</p>
            <p style="font-size: 14px;">The following reconciliations are pending your approval.</p>

            <p style="font-size: 14px; font-weight: bold; margin-top: 25px;">Reconciliations Pending Approval:</p>

            <table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center; padding: 8px;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Bank Account</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Year</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Month</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, detail in enumerate(details, start=1):
            body += f"""
                    <tr>
                        <td style="border: 1px solid #ddd; text-align: center; padding: 8px;">{index}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.bank_account}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.year}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.month}</td>
                    </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 25px; margin-bottom: 25px;">
                🔗 <a href="http://127.0.0.1:5000/approve-reconciliations" 
                style="color: #4270a8; text-decoration: none; font-weight: 600;">Click here to review and approve reconciliation(s)</a>
            </p>

            <p style="font-size: 14px;">Your timely action is appreciated.</p>

            <p style="font-size: 14px;">
                <strong>Best Regards,</strong><br>
                Bank Reconciliation Tracker<br>
                📧 support@yourcompany.com | ☎️ +256 [Your Contact Number]
            </p>
        </body>
        </html>
        """

        try:
            msg = Message(subject, recipients=[approver_email])
            msg.html = body  # Set HTML content
            mail.send(msg)
            print(f"Email reminder about Pending Reconciliation(s) Approval sent to Approver, {approver_email}")
        except Exception as e:
            print(f"Error sending email: {e}")


class FileUploadBatch:
    def __init__(self, id, user_id, date_time):
        self.id = id
        self.user_id = user_id
        self.date_time = date_time

    @staticmethod
    def check_batch_submission_status(user_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        # check if User has a request pending submission
        cursor.execute("SELECT COUNT(submission_status) FROM file_upload_batch WHERE submission_status = ? and "
                       "user_id = ? ", (0, user_id))

        number_of_unsubmitted_batches = cursor.fetchone()[0]
        conn.close()
        return number_of_unsubmitted_batches

    @staticmethod
    def allocate_batch_id():
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # Get the last batch_id
            cursor.execute("SELECT COALESCE(MAX(id), 0) FROM file_upload_batch")
            last_batch_id = cursor.fetchone()[0]  # Fetch last batch_id

            # Set new batch_id
            new_batch_id = (last_batch_id + 1) if last_batch_id else 1

            return new_batch_id
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_into_file_upload_batch(user_id, new_batch_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        # Insert new batch record
        now = datetime.now()

        try:
            cursor.execute(
                "INSERT INTO file_upload_batch (id, user_id, date_time, submission_status) VALUES (?, ?, ?, ?)",
                (new_batch_id, user_id, now, 0),
            )
            conn.commit()
            return new_batch_id
        except pyodbc.Error as e:
            print("Database insert error:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def get_latest_batch_pending_submission_by_user(user_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # check if User has a request pending submission
            cursor.execute("SELECT COALESCE(MAX(id), 0) FROM file_upload_batch WHERE submission_status = 0 AND "
                           "user_id = ? ", user_id)

            batch_id = cursor.fetchone()[0]  # Fetch last batch_id
            return batch_id
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_count_of_batch_pending_submission_by_user(user_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # check if User has a request pending submission
            cursor.execute("SELECT COALESCE(COUNT(id), 0) FROM file_upload_batch WHERE submission_status = 0 AND "
                           "user_id = ? ", user_id)

            batch_id = cursor.fetchone()[0]  # Fetch last batch_id
            return batch_id
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_batch_id_of_reconciliation_record_to_approve(bank_account_id, year, month, file_name):
        """
        Updates the submission_status of a batch in the file_upload_batch table.
        """
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # pick bank_account_id of bank_name in the uploadedFilesTable
            cursor.execute("SELECT id FROM bank_account WHERE name = ?", (bank_account_id,))
            bank_account_id = cursor.fetchone()[0]  # Fetch last batch_id
            # pick value of month of name of month in the uploadedFilesTable
            # Mapping of month names to their corresponding integer values
            month_map = {
                "January": 1,
                "February": 2,
                "March": 3,
                "April": 4,
                "May": 5,
                "June": 6,
                "July": 7,
                "August": 8,
                "September": 9,
                "October": 10,
                "November": 11,
                "December": 12
            }

            # Convert the month name to an integer using the month_map
            month_int = month_map.get(month, None)  # Default to None if not found

            if month_int is None:
                raise ValueError(f"Invalid month name: {month}")

            cursor.execute(
                "SELECT batch_id FROM file_upload WHERE bank_account_id = ? AND year = ? AND month = ? AND file_name "
                "= ?", (bank_account_id, year, month_int, file_name))

            batch_id = cursor.fetchone()[0]  # Fetch last batch_id
            return batch_id
        except Exception as e:
            print("Database error:", e)
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_batch_submission_status(batch_id):
        """
        Updates the submission_status of a batch in the file_upload_batch table.
        """
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            query = """
                UPDATE file_upload_batch
                SET submission_status = submission_status + 1
                WHERE id = ? AND submission_status = 0
            """
            cursor.execute(query, (batch_id,))
            conn.commit()

            return batch_id
        except Exception as e:
            print(f"Error updating batch submission status: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_id_of_file_upload(bank_account_id, year, month, file_name):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # pick bank_account_id of bank_name in the uploadedFilesTable
            cursor.execute("SELECT id FROM bank_account WHERE name = ? ", bank_account_id)
            bank_account_id = cursor.fetchone()[0]  # Fetch last batch_id
            # pick value of month of name of month in the uploadedFilesTable
            # Mapping of month names to their corresponding integer values
            month_map = {
                "January": 1,
                "February": 2,
                "March": 3,
                "April": 4,
                "May": 5,
                "June": 6,
                "July": 7,
                "August": 8,
                "September": 9,
                "October": 10,
                "November": 11,
                "December": 12
            }

            # Convert the month name to an integer using the month_map
            month_int = month_map.get(month, None)  # Default to None if not found

            if month_int is None:
                raise ValueError(f"Invalid month name: {month}")

            # check if User has a request pending submission
            cursor.execute("SELECT COALESCE(MAX(id), 0) FROM file_upload WHERE bank_account_id = ? AND "
                           "year = ? AND month = ? AND file_name = ?", bank_account_id, year, month_int, file_name)

            id_of_file_upload = cursor.fetchone()[0]  # Fetch last batch_id

            return id_of_file_upload
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_reconciliation_initiator_user_id(bank_account_id, year, month, file_name):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # pick bank_account_id of bank_name in the uploadedFilesTable
            cursor.execute("SELECT id FROM bank_account WHERE name = ? ", bank_account_id)
            bank_account_id = cursor.fetchone()[0]  # Fetch last batch_id
            # pick value of month of name of month in the uploadedFilesTable
            # Mapping of month names to their corresponding integer values
            month_map = {
                "January": 1,
                "February": 2,
                "March": 3,
                "April": 4,
                "May": 5,
                "June": 6,
                "July": 7,
                "August": 8,
                "September": 9,
                "October": 10,
                "November": 11,
                "December": 12
            }

            # Convert the month name to an integer using the month_map
            month_int = month_map.get(month, None)  # Default to None if not found

            if month_int is None:
                raise ValueError(f"Invalid month name: {month}")

            # check if User has a request pending submission
            cursor.execute("SELECT fub.user_id FROM file_upload fu LEFT OUTER JOIN file_upload_batch fub ON "
                           "fu.batch_id = fub.id WHERE fu.bank_account_id = ? AND fu.year = ? AND fu.month = ? AND "
                           "fu.file_name = ?", bank_account_id, year, month_int, file_name)

            id_of_initiator = cursor.fetchone()[0]  # Fetch last batch_id

            return id_of_initiator
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_reconciliation_initiator_email_and_fname(user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """      
                SELECT DISTINCT Fname, Email FROM users WHERE id = ? ;
            """

            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            # Return a list of dictionaries instead of trying to map to FileUpload
            return [{"Fname": row[0], "Email": row[1]} for row in result]

        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()


class FileUpload:
    def __init__(self, id=None, ID=None, bank_account=None, year=None, month=None, batch_id=None, file_name=None,
                 date_time=None, approve_as=None, responsible_users=None, next_approver=None, status=None, email=None,
                 fname=None, submission_status=None, name=None, approver=None, rejected_on=None, comment=None,
                 days_overdue=None):
        self.id = id
        self.ID = ID
        self.bank_account = bank_account
        self.year = year
        self.month = month
        self.batch_id = batch_id
        self.file_name = file_name
        self.date_time = date_time
        self.approve_as = approve_as
        self.responsible_users = responsible_users
        self.next_approver = next_approver
        self.status = status
        self.email = email
        self.fname = fname
        self.submission_status = submission_status
        self.name = name
        self.approver = approver
        self.rejected_on = rejected_on
        self.comment = comment
        self.days_overdue = days_overdue

    @staticmethod
    def insert_into_file_upload(batch_id, file_name, bank_account, year, month):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        # Get the last batch_id
        cursor.execute("SELECT MAX(id) FROM file_upload")
        last_file_id = cursor.fetchone()[0]  # Fetch last batch_id

        # Set new batch_id
        new_file_id = (last_file_id + 1) if last_file_id else 1

        # Insert new batch record
        now = datetime.now()

        try:
            cursor.execute(
                "INSERT INTO file_upload (id, batch_id, file_name, bank_account_id, year, month, "
                "removed_by_user_on_upload_page, creation_datetime)"
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (new_file_id, batch_id, file_name, bank_account, year, month, 0, now),
            )
            conn.commit()
            return new_file_id
        except pyodbc.Error as e:
            print("Database insert error:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def get_batch_id(bank_account_id, year, month, file_name):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # pick bank_account_id of bank_name in the uploadedFilesTable
            cursor.execute("SELECT id FROM bank_account WHERE name = ? ", bank_account_id)
            bank_account_id = cursor.fetchone()[0]  # Fetch last batch_id
            # pick value of month of name of month in the uploadedFilesTable
            # Mapping of month names to their corresponding integer values
            month_map = {
                "January": 1,
                "February": 2,
                "March": 3,
                "April": 4,
                "May": 5,
                "June": 6,
                "July": 7,
                "August": 8,
                "September": 9,
                "October": 10,
                "November": 11,
                "December": 12
            }

            # Convert the month name to an integer using the month_map
            month_int = month_map.get(month, None)  # Default to None if not found

            if month_int is None:
                raise ValueError(f"Invalid month name: {month}")

            # check if User has a request pending submission
            cursor.execute("SELECT COALESCE(MAX(batch_id), 0) FROM file_upload WHERE bank_account_id = ? AND "
                           "year = ? AND month = ? AND file_name = ?", bank_account_id, year, month_int, file_name)

            id_of_file_upload = cursor.fetchone()[0]  # Fetch last batch_id

            return id_of_file_upload
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def unsubmitted_files_num(user_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # Check if a record with the given bank_account, year, and month exists
            cursor.execute(
                "SELECT COUNT(*) FROM file_upload a LEFT OUTER JOIN bank_account b ON a.bank_account_id = b.id "
                "LEFT OUTER JOIN file_upload_batch c ON c.id = a.batch_id "
                "LEFT OUTER JOIN users d on d.id = c.user_id WHERE c.user_id = ? AND a.submission_status = 0 "
                "AND removed_by_user_on_upload_page = 0", user_id  # Parameters must be in a tuple
            )

            result = cursor.fetchone()[0]  # Fetch the result, which is a tuple like
            return result
        except Exception as e:
            print("Database error:", e)
            return None  # Return None to indicate an error occurred
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_uploaded_pending_submission_files_by_user(user_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # Raw MSSQL Query to fetch all files that are not marked as removed
            query = """
                        SELECT b.name as bank_account_id, year, 
                        (select DateName(month, DateAdd(month, month, 0) - 1)) as month, file_name, batch_id,
                            CASE 
                                WHEN c.submission_status = 0 THEN 'Pending Submission' 
                                ELSE 'Rejected' 
                            END AS submission_status 
                        FROM file_upload a 
                        LEFT OUTER JOIN bank_account b ON a.bank_account_id = b.id
                        LEFT OUTER JOIN file_upload_batch c ON c.id = a.batch_id
                        LEFT OUTER JOIN users d on d.id = c.user_id
                        WHERE c.user_id = ? AND a.submission_status = 0 AND removed_by_user_on_upload_page = 0
                        ORDER BY b.name
                    """
            # Execute the query with user_id as parameter
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            # Convert query results to a list of dictionaries
            files = [
                {
                    "bank_account": row.bank_account_id,
                    "year": row.year,
                    "month": row.month,
                    "file_name": row.file_name,
                    "batch_id": row.batch_id,
                    "submission_status": row.submission_status
                }
                for row in result
            ]
            return files
        except Exception as e:
            print("Database error:", e)
            return None
        finally:
            # Close cursor and connection
            cursor.close()
            conn.close()

    @staticmethod
    def get_submitted_reconciliations(user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        DECLARE @workflow_id INT = 1; -- workflow_id from workflow table
                        DECLARE @is_workflow_level INT = 1;
                        
                        SELECT c.name AS bank_account, b.year, DATENAME(month, DATEADD(month, b.month - 1, 0)) AS month,
                          (
                            SELECT TOP 1
                              CASE 
                                WHEN ra.decision = 1 THEN 'Submitted by'
                                WHEN ra.decision = 2 THEN 'Approved by'
                                WHEN ra.decision = 3 THEN 'Rejected by'
                                ELSE 'Unknown'
                              END + ' ' + r.name
                            FROM reconciliation_approvals ra
                            LEFT JOIN workflow_breakdown wb ON ra.level = wb.level 
                            LEFT JOIN role_workflow_breakdown rwb ON wb.id = rwb.workflow_breakdown_id
                            LEFT JOIN role r ON rwb.role_id = r.id
                            WHERE 
                              ra.file_upload_id = b.id AND  -- correlate to outer query
                              wb.workflow_id = @workflow_id AND 
                              wb.is_workflow_level = @is_workflow_level
                            ORDER BY ra.id DESC  -- optional: choose latest approval
                          ) AS status,
                          b.file_name,
                          FORMAT(b.creation_datetime, 'yyyy-MM-dd HH:mm:ss') AS date_time
                        FROM 
                          file_upload_batch a
                        LEFT JOIN file_upload b ON a.id = b.batch_id
                        LEFT JOIN bank_account c ON b.bank_account_id = c.id
                        WHERE 
                          a.user_id = ? AND 
                          b.submission_status != 0 AND 
                          b.removed_by_user_on_upload_page = 0
                        ORDER BY 
                          c.name;
            """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            reconciliations = [
                FileUpload(bank_account=row.bank_account, year=row.year, month=row.month, status=row.status,
                           file_name=row.file_name, date_time=row.date_time)
                for row in result
            ]
            return reconciliations
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_reconciliations_pending_approval_report():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                    DECLARE @workflow_id INT = 1; -- workflow_id from workflow table
                    DECLARE @is_workflow_level INT = 1;
                    
                    SELECT c.name as bank_account, b.year, (select DateName(month, DateAdd(month, b.month, 
                    0) - 1)) as month, b.file_name, FORMAT(b.creation_datetime, 'yyyy-MM-dd HH:mm:ss') AS 
                    date_time, (SELECT r.name FROM role r LEFT OUTER JOIN role_workflow_breakdown rwb ON r.id = 
                    rwb.role_id LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id WHERE 
                    wb.workflow_id = @workflow_id AND wb.is_workflow_level = @is_workflow_level AND wb.level = 
                    b.submission_status + 1) as next_approver FROM file_upload_batch a LEFT OUTER JOIN file_upload b ON 
                    a.id = b.batch_id LEFT OUTER JOIN bank_account c ON b.bank_account_id = c.id WHERE 
                    b.submission_status != 0 AND b.submission_status < (SELECT COALESCE(MAX(level), 0) FROM workflow wf 
                    LEFT OUTER JOIN workflow_breakdown wb ON wf.id = wb.workflow_id WHERE wf.id = @workflow_id) AND 
                    b.removed_by_user_on_upload_page = 0 ORDER BY c.name, b.year, b.month ASC;
                """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            reconciliations = [
                FileUpload(bank_account=row.bank_account, year=row.year, month=row.month,
                           file_name=row.file_name, date_time=row.date_time, next_approver=row.next_approver)
                for row in result
            ]
            return reconciliations
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_rejected_reconciliations_report():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT 
                            ra.id, 
                            ba.name AS bank_account, 
                            fu.year, 
                            (SELECT DATENAME(month, DATEADD(month, fu.month, 0) - 1)) AS month,
                            fu.file_name, 
                            LTRIM(RTRIM(COALESCE(r.name + ' - ' + u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS approver,
                            CONVERT(VARCHAR(19), ra.date_time, 120) AS rejected_on,  -- YYYY-MM-DD HH:MI:SS
                            ra.comment
                        FROM reconciliation_approvals ra
                        LEFT OUTER JOIN file_upload fu ON ra.file_upload_id = fu.id
                        LEFT OUTER JOIN bank_account ba ON fu.bank_account_id = ba.id
                        LEFT OUTER JOIN users u ON ra.approver_id = u.ID
                        LEFT OUTER JOIN role r ON ra.level = r.id
                        WHERE ra.decision = 3
                        ORDER BY bank_account, rejected_on;
                """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            reconciliations = [
                FileUpload(id=row.id, bank_account=row.bank_account, year=row.year, month=row.month, file_name=row.file_name,
                           approver=row.approver, rejected_on=row.rejected_on, comment=row.comment)
                for row in result
            ]
            return reconciliations
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_fully_approved_reconciliations_report():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        DECLARE @workflow_id INT = 1; -- workflow_id from workflow table
                        DECLARE @is_workflow_level INT = 1;
                        
                        SELECT c.name as bank_account, b.year, (select DateName(month, DateAdd(month, b.month, 
                        0) - 1)) as month, b.file_name, ( SELECT TOP 1 CASE WHEN ra.decision = 1 THEN 'Submitted by' 
                        WHEN ra.decision = 2 THEN 'Approved by' WHEN ra.decision = 3 THEN 'Rejected by' ELSE 
                        'Unknown' END + ' ' + r.name FROM reconciliation_approvals ra LEFT JOIN workflow_breakdown wb 
                        ON ra.level = wb.level LEFT JOIN role_workflow_breakdown rwb ON wb.id = 
                        rwb.workflow_breakdown_id LEFT JOIN role r ON rwb.role_id = r.id WHERE ra.file_upload_id = 
                        b.id AND wb.workflow_id = @workflow_id AND wb.is_workflow_level = @is_workflow_level ORDER BY 
                        ra.id DESC ) AS status, FORMAT((SELECT MAX(ra.date_time) FROM reconciliation_approvals ra 
                        WHERE file_upload_id = b.id), 'yyyy-MM-dd HH:mm:ss') AS date_time FROM file_upload_batch a 
                        LEFT OUTER JOIN file_upload b ON a.id = b.batch_id LEFT OUTER JOIN bank_account c ON 
                        b.bank_account_id = c.id WHERE b.submission_status != 0 AND b.submission_status = (SELECT 
                        COALESCE(MAX( wb.level), 0) FROM workflow wf LEFT OUTER JOIN workflow_breakdown wb ON wf.id = 
                        wb.workflow_id WHERE wf.id = @workflow_id) AND b.removed_by_user_on_upload_page = 0 ORDER BY 
                        c.name, b.year, b.month ASC;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            reconciliations = [
                FileUpload(bank_account=row.bank_account, year=row.year, month=row.month,
                           file_name=row.file_name, status=row.status, date_time=row.date_time)
                for row in result
            ]
            return reconciliations
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_submitted_reconciliations():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        DECLARE @workflow_id INT = 1; -- workflow_id from workflow table
                        DECLARE @is_workflow_level INT = 1;
                        
                        SELECT c.name as bank_account, b.year, ( select DateName( month, DateAdd(month, 
                        b.month, 0) -1 ) ) as month, ( SELECT TOP 1 CASE WHEN ra.decision = 1 THEN 'Submitted by' 
                        WHEN ra.decision = 2 THEN 'Approved by' WHEN ra.decision = 3 THEN 'Rejected by' ELSE 
                        'Unknown' END + ' ' + r.name FROM reconciliation_approvals ra LEFT JOIN workflow_breakdown wb 
                        ON ra.level = wb.level LEFT JOIN role_workflow_breakdown rwb ON wb.id = 
                        rwb.workflow_breakdown_id LEFT JOIN role r ON rwb.role_id = r.id WHERE ra.file_upload_id = 
                        b.id AND wb.workflow_id = @workflow_id AND wb.is_workflow_level = 
                        @is_workflow_level ORDER BY ra.id DESC) AS status, 
                        b.file_name, FORMAT( b.creation_datetime, 'yyyy-MM-dd HH:mm:ss' ) AS date_time FROM 
                        file_upload_batch a LEFT OUTER JOIN file_upload b ON a.id = b.batch_id LEFT OUTER JOIN 
                        bank_account c ON b.bank_account_id = c.id LEFT OUTER JOIN users d ON a.user_id = d.ID WHERE 
                        b.submission_status != 0 AND b.removed_by_user_on_upload_page = 0 ORDER BY c.name, b.year, 
                        b.month
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            reconciliations = [
                FileUpload(bank_account=row.bank_account, year=row.year, month=row.month, status=row.status,
                           file_name=row.file_name, date_time=row.date_time)
                for row in result
            ]
            return reconciliations
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_reconciliations_pending_submission():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        WITH MonthList AS (
                            SELECT 
                                ba.id AS bank_account_id,
                                ba.name AS bank_account,
                                DATEFROMPARTS(YEAR(ba.creation_date), MONTH(ba.creation_date), 1) AS start_month
                            FROM 
                                bank_account ba
                        ), AllMonths AS (
                            SELECT 
                                ml.bank_account_id,
                                ml.bank_account,
                                ml.start_month AS recon_month
                            FROM 
                                MonthList ml
                            
                            UNION ALL
                            
                            SELECT 
                                am.bank_account_id,
                                am.bank_account,
                                DATEADD(MONTH, 1, am.recon_month)
                            FROM 
                                AllMonths am
                            WHERE 
                                am.recon_month < DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)
                        )
                        SELECT 
                            c.name AS bank_account,
                            YEAR(am.recon_month) AS year,
                            MONTH(am.recon_month) AS month_number,
                            DATENAME(month, am.recon_month) AS month,
                            DATEDIFF(
                                DAY,
                                DATEADD(MONTH, 1, am.recon_month),  -- First day after the recon month
                                GETDATE()
                            ) AS days_overdue,
                            STRING_AGG(
                                LTRIM(RTRIM(
                                    COALESCE(u.Fname, '') + 
                                    CASE WHEN u.Mname IS NOT NULL AND u.Mname <> '' THEN ' ' + u.Mname ELSE '' END + 
                                    CASE WHEN u.Sname IS NOT NULL AND u.Sname <> '' THEN ' ' + u.Sname ELSE '' END
                                )),
                                ', '
                            ) AS responsible_users
                        FROM 
                            AllMonths am
                        LEFT JOIN 
                            file_upload f ON f.bank_account_id = am.bank_account_id 
                                           AND f.year = YEAR(am.recon_month)
                                           AND f.month = MONTH(am.recon_month)
                                           AND f.removed_by_user_on_upload_page = 0
                        INNER JOIN 
                            bank_account c ON am.bank_account_id = c.id
                        LEFT JOIN 
                            bank_account_responsible_user bru ON bru.bank_account_id = c.id
                        LEFT JOIN 
                            users u ON bru.user_id = u.ID
                        WHERE 
                            f.id IS NULL
                            AND am.recon_month < DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)
                        GROUP BY 
                            c.name,
                            am.recon_month, -- Needed for DATEDIFF
                            YEAR(am.recon_month),
                            MONTH(am.recon_month),
                            DATENAME(month, am.recon_month)
                        ORDER BY 
                            c.name, year, month_number
                        OPTION (MAXRECURSION 1000);
                        """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            reconciliations = [
                FileUpload(
                    bank_account=row.bank_account,
                    year=row.year,
                    month=row.month,
                    responsible_users=row.responsible_users,
                    days_overdue=row.days_overdue
                )
                for row in result
            ]
            return reconciliations
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_approved_reconciliations(user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        DECLARE @workflow_id INT = 1; 
                        DECLARE @is_workflow_level INT = 1;
                        
                        SELECT
                            b.name AS bank_account,
                            a.year,
                            DATENAME(month, DATEADD(month, a.month - 1, 0)) AS month,                                                
                            (
                                SELECT TOP 1
                                    CASE 
                                        WHEN ra2.decision = 1 THEN 'Submitted by'
                                        WHEN ra2.decision = 2 THEN 'Approved by'
                                        WHEN ra2.decision = 3 THEN 'Rejected by'
                                        ELSE 'Unknown'
                                    END + ' ' + r.name
                                FROM reconciliation_approvals ra2
                                LEFT JOIN workflow_breakdown wb ON ra2.level = wb.level AND wb.workflow_id = @workflow_id
                                LEFT JOIN role_workflow_breakdown rwb ON wb.id = rwb.workflow_breakdown_id
                                LEFT JOIN role r ON rwb.role_id = r.id
                                WHERE ra2.file_upload_id = a.id
                                ORDER BY ra2.id DESC
                            ) AS status, a.file_name,
                            FORMAT(a.creation_datetime, 'yyyy-MM-dd HH:mm:ss') AS date_time
                        FROM file_upload a
                        LEFT JOIN bank_account b ON a.bank_account_id = b.id
                        WHERE EXISTS (
                            SELECT 1 FROM reconciliation_approvals ra
                            WHERE ra.file_upload_id = a.id
                            AND ra.approver_id = ? 
                            AND ra.decision IN (2, 3) -- Only Approved or Rejected
                        )
                        ORDER BY b.name, a.year, a.month;
                    """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            reconciliations = [
                FileUpload(bank_account=row.bank_account, year=row.year, month=row.month, file_name=row.file_name,
                           status=row.status, date_time=row.date_time)
                for row in result
            ]
            return reconciliations
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_reconciliations_pending_approval(user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
               DECLARE @logged_in_user_id INT = ?; -- Set logged-in user's ID

                ;WITH GlobalFiles AS (
                    -- Get files where responsibility is global
                    SELECT 
                        ba.name AS bank_account, 
                        f.year, 
                        DATENAME(month, DATEADD(month, f.month, 0) - 1) AS month,
                        f.file_name, 
                        FORMAT(f.creation_datetime, 'yyyy-MM-dd HH:mm:ss') AS date_time, 
                        (SELECT TOP 1 r.name 
                         FROM role r 
                         LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                         LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                         LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                         WHERE wb.is_workflow_level = 1 
                         AND wb.level - 1 = f.submission_status
                         AND ur.user_id = @logged_in_user_id) AS approve_as,
                        ROW_NUMBER() OVER (PARTITION BY f.id ORDER BY f.creation_datetime DESC) AS row_num
                    FROM file_upload f
                    JOIN reconciliation_approvals ra ON f.id = ra.file_upload_id
                    JOIN file_upload_batch fub ON f.batch_id = fub.id
                    JOIN users u ON fub.user_id = u.ID
                    JOIN bank_account ba ON f.bank_account_id = ba.id
                    JOIN bank b ON ba.bank_id = b.id
                    JOIN user_role ur ON u.ID = ur.user_id
                    JOIN role r ON ur.role_id = r.id
                    WHERE ra.approver_id IN
                    (SELECT DISTINCT(a.ID) 
                     FROM users a
                     JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                     WHERE b.parent_org_unit_tier_id IN 
                     (SELECT d.organisation_unit_tier_id FROM users d WHERE d.ID = @logged_in_user_id))
                    AND f.submission_status != 0 AND f.submission_status IN 
                     (SELECT DISTINCT(a.level) - 1 
                      FROM workflow_breakdown a
                      JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                      JOIN role c ON b.role_id = c.id
                      JOIN user_role d ON c.id = d.role_id
                      JOIN users e ON d.user_id = e.ID
                      WHERE a.is_responsibility_global = 1
                      AND e.ID = @logged_in_user_id)
                ),
                OrgBasedFiles AS (
                    -- Get files where responsibility is restricted to specific organizational units
                    SELECT 
                        ba.name AS bank_account, 
                        f.year, 
                        DATENAME(month, DATEADD(month, f.month, 0) - 1) AS month,
                        f.file_name, 
                        FORMAT(f.creation_datetime, 'yyyy-MM-dd HH:mm:ss') AS date_time,
                        (SELECT TOP 1 r.name 
                         FROM role r 
                         LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                         LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                         LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                         WHERE wb.is_workflow_level = 1 
                         AND wb.level - 1 = f.submission_status
                         AND ur.user_id = @logged_in_user_id) AS approve_as,
                        ROW_NUMBER() OVER (PARTITION BY f.id ORDER BY f.creation_datetime DESC) AS row_num
                        FROM file_upload f
                        JOIN reconciliation_approvals ra ON f.id = ra.file_upload_id
                        JOIN file_upload_batch fub ON f.batch_id = fub.id
                        JOIN users u ON fub.user_id = u.ID
                        JOIN bank_account ba ON f.bank_account_id = ba.id
                        JOIN bank b ON ba.bank_id = b.id
                        JOIN user_role ur ON u.ID = ur.user_id
                        JOIN role r ON ur.role_id = r.id
                        WHERE ra.approver_id IN
                        (SELECT DISTINCT(a.ID) 
                         FROM users a
                         JOIN organisation_unit b ON a.organisation_unit_id = b.id
                         WHERE b.parent_org_unit_id IN 
                         (SELECT d.organisation_unit_id FROM users d WHERE d.ID = @logged_in_user_id))
                        AND f.submission_status != 0 AND f.submission_status IN 
                         (SELECT DISTINCT(a.level) - 1 
                          FROM workflow_breakdown a
                          JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                          JOIN role c ON b.role_id = c.id
                          JOIN user_role d ON c.id = d.role_id
                          JOIN users e ON d.user_id = e.ID
                          WHERE a.is_responsibility_global = 0
                          AND e.ID = @logged_in_user_id)
                    )
                    
                    -- Combine results and order by bank_name, year, month
                    SELECT bank_account, year, month, file_name, date_time, approve_as
                    FROM (
                        SELECT * FROM GlobalFiles WHERE row_num = 1
                        UNION
                        SELECT * FROM OrgBasedFiles WHERE row_num = 1
                    ) AS UniqueResults
                    ORDER BY bank_account, year, month ASC;
            """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            reconciliations = [
                FileUpload(bank_account=row.bank_account, year=row.year, month=row.month,
                           file_name=row.file_name, date_time=row.date_time, approve_as=row.approve_as)
                for row in result
            ]

            return reconciliations
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_reconciliations_pending_approval_count(user_id):
        conn = get_db_connection()
        if conn is None:
            return 0  # Return 0 if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                DECLARE @logged_in_user_id INT = ?;

                WITH GlobalFiles AS (
                    SELECT DISTINCT(f.id)
                    FROM file_upload f
                    JOIN reconciliation_approvals ra ON f.id = ra.file_upload_id
                    JOIN file_upload_batch fub ON f.batch_id = fub.id
                    JOIN users u ON fub.user_id = u.ID
                    JOIN bank_account ba ON f.bank_account_id = ba.id
                    JOIN bank b ON ba.bank_id = b.id
                    JOIN user_role ur ON u.ID = ur.user_id
                    JOIN role r ON ur.role_id = r.id
                    WHERE ra.approver_id IN (
                        SELECT DISTINCT a.ID
                        FROM users a
                        JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                        WHERE b.parent_org_unit_tier_id IN (
                            SELECT d.organisation_unit_tier_id
                            FROM users d
                            WHERE d.ID = @logged_in_user_id
                        )
                    )
                    AND f.submission_status != 0
                    AND f.submission_status IN (
                        SELECT DISTINCT a.level - 1
                        FROM workflow_breakdown a
                        JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                        JOIN role c ON b.role_id = c.id
                        JOIN user_role d ON c.id = d.role_id
                        WHERE a.is_responsibility_global = 1
                        AND d.user_id = @logged_in_user_id
                    )
                ),
                OrgBasedFiles AS (
                    SELECT DISTINCT(f.id)
                    FROM file_upload f
                    JOIN reconciliation_approvals ra ON f.id = ra.file_upload_id
                    JOIN file_upload_batch fub ON f.batch_id = fub.id
                    JOIN users u ON fub.user_id = u.ID
                    JOIN bank_account ba ON f.bank_account_id = ba.id
                    JOIN bank b ON ba.bank_id = b.id
                    JOIN user_role ur ON u.ID = ur.user_id
                    JOIN role r ON ur.role_id = r.id
                    WHERE ra.approver_id IN (
                        SELECT DISTINCT a.ID
                        FROM users a
                        JOIN organisation_unit b ON a.organisation_unit_id = b.id
                        WHERE b.parent_org_unit_id IN (
                            SELECT d.organisation_unit_id
                            FROM users d
                            WHERE d.ID = @logged_in_user_id
                        )
                    )
                    AND f.submission_status != 0
                    AND f.submission_status IN (
                        SELECT DISTINCT a.level - 1
                        FROM workflow_breakdown a
                        JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                        JOIN role c ON b.role_id = c.id
                        JOIN user_role d ON c.id = d.role_id
                        WHERE a.is_responsibility_global = 0
                        AND d.user_id = @logged_in_user_id
                    )
                )

                SELECT 
                    (SELECT COUNT(*) FROM GlobalFiles) + 
                    (SELECT COUNT(*) FROM OrgBasedFiles) AS TotalPendingApprovals;
            """
            cursor.execute(query, [user_id])
            pending_approvals_count = cursor.fetchone()[0]
            return pending_approvals_count if pending_approvals_count is not None else 0
        except Exception as e:
            print("Database error:", e)
            return 0
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def check_for_already_existing_reconciliation(bank_account, year, month):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # Check if a record with the given bank_account, year, and month exists
            cursor.execute(
                "SELECT COUNT(*) FROM file_upload WHERE bank_account_id = ? AND year = ? AND month = ? AND "
                "removed_by_user_on_upload_page = 0",
                (bank_account, year, month)  # Parameters must be in a tuple
            )

            result = cursor.fetchone()  # Fetch the result, which is a tuple like (count,)
            return result[0] > 0  # Returns True if at least one record exists
        except Exception as e:
            print("Database error:", e)
            return None  # Return None to indicate an error occurred
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_submission_status_of_reconciliation(file_upload_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # Check if a record with the given bank_account, year, and month exists
            cursor.execute(
                "SELECT submission_status FROM file_upload WHERE id = ?", file_upload_id
            )
            result = cursor.fetchone()[0]
            return result
        except Exception as e:
            print("Database error:", e)
            return None  # Return None to indicate an error occurred
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_file_submission_status(bank_account_id, year, month, file_name):
        """
        Updates the submission_status of a file in the file_upload table.
        """
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # pick bank_account_id of bank_name in the uploadedFilesTable
            cursor.execute("SELECT id FROM bank_account WHERE name = ? ", bank_account_id)
            bank_account_id = cursor.fetchone()[0]  # Fetch last batch_id
            # pick value of month of name of month in the uploadedFilesTable
            # Mapping of month names to their corresponding integer values
            month_map = {
                "January": 1,
                "February": 2,
                "March": 3,
                "April": 4,
                "May": 5,
                "June": 6,
                "July": 7,
                "August": 8,
                "September": 9,
                "October": 10,
                "November": 11,
                "December": 12
            }

            # Convert the month name to an integer using the month_map
            month_int = month_map.get(month, None)  # Default to None if not found

            if month_int is None:
                raise ValueError(f"Invalid month name: {month}")

            query = """
                UPDATE file_upload
                SET submission_status = 1
                WHERE bank_account_id = ? AND year = ? AND month = ? AND file_name = ?
            """
            cursor.execute(query, (bank_account_id, year, month_int, file_name))
            conn.commit()
            return file_name
        except Exception as e:
            print(f"Error updating file submission status: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_file_approval_status(bank_account_id, year, month, file_name, action):
        """
        Updates the submission_status of a file in the file_upload table.
        """
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # pick bank_account_id of bank_name in the uploadedFilesTable
            cursor.execute("SELECT id FROM bank_account WHERE name = ?", (bank_account_id,))
            bank_account_id = cursor.fetchone()[0]  # Fetch last batch_id
            # pick value of month of name of month in the uploadedFilesTable
            # Mapping of month names to their corresponding integer values
            month_map = {
                "January": 1,
                "February": 2,
                "March": 3,
                "April": 4,
                "May": 5,
                "June": 6,
                "July": 7,
                "August": 8,
                "September": 9,
                "October": 10,
                "November": 11,
                "December": 12
            }

            # Convert the month name to an integer using the month_map
            month_int = month_map.get(month, None)  # Default to None if not found

            if month_int is None:
                raise ValueError(f"Invalid month name: {month}")

            if action == "reject":
                query = """
                    UPDATE file_upload
                    SET submission_status = 0
                    WHERE bank_account_id = ? AND year = ? AND month = ? AND file_name = ?;
                """

            else:
                query = """
                    UPDATE file_upload
                    SET submission_status = submission_status + 1
                    WHERE bank_account_id = ? AND year = ? AND month = ? AND file_name = ?
                """

            cursor.execute(query, (bank_account_id, year, month_int, file_name))
            conn.commit()
            return file_name
        except Exception as e:
            print(f"Error updating approval status of reconciliation record: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_file_approval_status_following_a_rejected_approval(file_upload_id):
        """
        Updates the submission_status of a file in the file_upload table.
        """
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            query = """
                UPDATE file_upload
                SET submission_status = 0
                WHERE id = ?
            """
            file_upload_id = cursor.execute(query, file_upload_id)
            conn.commit()
            return file_upload_id
        except Exception as e:
            print(f"Error updating status of file in file_upload table following a rejected request: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_next_approver_fname_email(user_id, max_submission_status):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                WITH ParentOrgUnits AS (
                    SELECT DISTINCT b.parent_org_unit_id 
                    FROM users a
                    JOIN organisation_unit b ON a.organisation_unit_id = b.id 
                    WHERE a.ID = ?
                ),
                ParentOrgUnitTiers AS (
                    SELECT DISTINCT b.parent_org_unit_tier_id 
                    FROM users a
                    JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id 
                    WHERE a.ID = ?
                ),
                GlobalApprovers AS (
                    SELECT DISTINCT u.Fname, u.Email
                    FROM users u
                    JOIN user_role ur ON u.id = ur.user_id
                    JOIN role r ON ur.role_id = r.id
                    JOIN role_workflow_breakdown rwb ON r.id = rwb.role_id
                    JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                    WHERE wb.is_workflow_level = 1
                    AND wb.level = ?
                    AND wb.is_responsibility_global = 1
                    AND u.ID IN (
                        SELECT DISTINCT a.ID
                        FROM users a
                        JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                        WHERE b.id IN (SELECT parent_org_unit_tier_id FROM ParentOrgUnitTiers)
                    )
                ),
                OrgBasedApprovers AS (
                    SELECT DISTINCT u.Fname, u.Email
                    FROM users u
                    JOIN user_role ur ON u.id = ur.user_id
                    JOIN role r ON ur.role_id = r.id
                    JOIN role_workflow_breakdown rwb ON r.id = rwb.role_id
                    JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                    WHERE wb.is_workflow_level = 1
                    AND wb.level = ?
                    AND wb.is_responsibility_global = 0
                    AND u.ID IN (
                        SELECT DISTINCT a.ID
                        FROM users a
                        JOIN organisation_unit b ON a.organisation_unit_id = b.id
                        WHERE b.id IN (SELECT parent_org_unit_id FROM ParentOrgUnits)
                    )
                )

                SELECT DISTINCT Fname, Email
                FROM (
                    SELECT Fname, Email FROM GlobalApprovers
                    UNION
                    SELECT Fname, Email FROM OrgBasedApprovers
                ) AS Approvers
                ORDER BY Fname ASC;
            """

            cursor.execute(query, (user_id, user_id, max_submission_status + 1, max_submission_status + 1))
            result = cursor.fetchall()

            # Return a list of dictionaries instead of trying to map to FileUpload
            return [{"Fname": row[0], "Email": row[1]} for row in result]

        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def initiators_pending_submission_of_reconciliations():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        WITH MonthList AS (
                            SELECT 
                                ba.id AS bank_account_id,
                                DATEFROMPARTS(YEAR(ba.creation_date), MONTH(ba.creation_date), 1) AS start_month
                            FROM 
                                bank_account ba
                        ), AllMonths AS (
                            SELECT 
                                ml.bank_account_id,
                                ml.start_month AS recon_month
                            FROM 
                                MonthList ml
                            UNION ALL
                            SELECT 
                                am.bank_account_id,
                                DATEADD(MONTH, 1, am.recon_month)
                            FROM 
                                AllMonths am
                            WHERE 
                                am.recon_month < DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)
                        )
                        SELECT DISTINCT
                            u.ID
                        FROM 
                            AllMonths am
                        LEFT JOIN 
                            file_upload f ON f.bank_account_id = am.bank_account_id 
                                           AND f.year = YEAR(am.recon_month)
                                           AND f.month = MONTH(am.recon_month)
                                           AND f.removed_by_user_on_upload_page = 0
                        INNER JOIN 
                            bank_account c ON am.bank_account_id = c.id
                        LEFT JOIN 
                            bank_account_responsible_user bru ON bru.bank_account_id = c.id
                        LEFT JOIN 
                            users u ON bru.user_id = u.ID
                        WHERE 
                            f.id IS NULL -- Means missing reconciliation
                            AND am.recon_month < DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)
                            AND u.ID IS NOT NULL
                        OPTION (MAXRECURSION 1000);
                  """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            return [row.ID for row in result]
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_user_fname_email(user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        DECLARE @UserID INT = ?;

                        SELECT fname, email FROM users WHERE ID = @UserID
                  """
            cursor.execute(query, (user_id,))
            result = cursor.fetchone()

            if result:
                return {"fname": result.fname, "email": result.email}
            else:
                return {}
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_user_ids():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT ID FROM users ORDER BY ID
                  """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            ids = [row[0] for row in result]

            return ids
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def pending_reconciliation_submission_details(user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        DECLARE @UserID INT = ?;
                        
                        WITH MonthList AS (
                            SELECT 
                                ba.id AS bank_account_id,
                                ba.name AS bank_account,
                                DATEFROMPARTS(YEAR(ba.creation_date), MONTH(ba.creation_date), 1) AS start_month
                            FROM 
                                bank_account ba
                        ), AllMonths AS (
                            SELECT 
                                ml.bank_account_id,
                                ml.bank_account,
                                ml.start_month AS recon_month
                            FROM 
                                MonthList ml
                        
                            UNION ALL
                        
                            SELECT 
                                am.bank_account_id,
                                am.bank_account,
                                DATEADD(MONTH, 1, am.recon_month)
                            FROM 
                                AllMonths am
                            WHERE 
                                am.recon_month < DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)
                        )
                        SELECT 
                            c.name AS bank_account,
                            YEAR(am.recon_month) AS year,
                            DATENAME(month, am.recon_month) AS month,
                            DATEDIFF(
                                DAY,
                                DATEADD(MONTH, 1, am.recon_month),  -- First day after recon month
                                GETDATE()
                            ) AS days_overdue
                        FROM 
                            AllMonths am
                        LEFT JOIN 
                            file_upload f ON f.bank_account_id = am.bank_account_id 
                                           AND f.year = YEAR(am.recon_month)
                                           AND f.month = MONTH(am.recon_month)
                                           AND f.removed_by_user_on_upload_page = 0
                        INNER JOIN 
                            bank_account c ON am.bank_account_id = c.id
                        LEFT JOIN 
                            bank_account_responsible_user bru ON bru.bank_account_id = c.id
                        LEFT JOIN 
                            users u ON bru.user_id = u.ID
                        WHERE 
                            f.id IS NULL -- Missing reconciliation
                            AND am.recon_month < DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)
                            AND u.ID = @UserID
                        GROUP BY 
                            c.name,
                            am.recon_month,
                            YEAR(am.recon_month),
                            DATENAME(month, am.recon_month)
                        ORDER BY 
                            c.name, year, 
                            MIN(MONTH(am.recon_month))
                        OPTION (MAXRECURSION 1000);
                  """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            reconciliations = [
                FileUpload(
                    bank_account=row.bank_account,
                    year=row.year,
                    month=row.month,
                    days_overdue=row.days_overdue
                )
                for row in result
            ]
            return reconciliations
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def pending_reconciliation_submission_details_for_approver(user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        DECLARE @logged_in_user_id INT = ?;
                        DECLARE @is_global_responsibility BIT = 0;
                        
                        WITH MonthList AS (
                            SELECT 
                                ba.id AS bank_account_id,
                                ba.name AS bank_account,
                                DATEFROMPARTS(YEAR(ba.creation_date), MONTH(ba.creation_date), 1) AS start_month
                            FROM 
                                bank_account ba
                        ), AllMonths AS (
                            SELECT 
                                ml.bank_account_id,
                                ml.bank_account,
                                ml.start_month AS recon_month
                            FROM 
                                MonthList ml
                            
                            UNION ALL
                            
                            SELECT 
                                am.bank_account_id,
                                am.bank_account,
                                DATEADD(MONTH, 1, am.recon_month)
                            FROM 
                                AllMonths am
                            WHERE 
                                am.recon_month < DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)
                        )
                        SELECT 
                            c.name AS bank_account,
                            YEAR(am.recon_month) AS year,
                            DATENAME(month, am.recon_month) AS month,
                            DATEDIFF(
                                DAY,
                                DATEADD(MONTH, 1, am.recon_month), -- Day after the end of the month
                                GETDATE()
                            ) AS days_overdue,
                            STRING_AGG(
                                LTRIM(RTRIM(
                                    COALESCE(u.Fname, '') + 
                                    CASE WHEN u.Mname IS NOT NULL AND u.Mname <> '' THEN ' ' + u.Mname ELSE '' END + 
                                    CASE WHEN u.Sname IS NOT NULL AND u.Sname <> '' THEN ' ' + u.Sname ELSE '' END
                                )),
                                ', '
                            ) AS responsible_users
                        FROM 
                            AllMonths am
                        LEFT JOIN 
                            file_upload f ON f.bank_account_id = am.bank_account_id 
                                           AND f.year = YEAR(am.recon_month)
                                           AND f.month = MONTH(am.recon_month)
                                           AND f.removed_by_user_on_upload_page = 0
                        INNER JOIN 
                            bank_account c ON am.bank_account_id = c.id
                        LEFT JOIN 
                            bank_account_responsible_user bru ON bru.bank_account_id = c.id
                        LEFT JOIN 
                            users u ON bru.user_id = u.ID
                        WHERE 
                            f.id IS NULL
                            AND am.recon_month < DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)
                            AND (
                                (@is_global_responsibility = 0 AND bru.user_id IN (
                                    SELECT DISTINCT a.ID 
                                    FROM users a
                                    JOIN organisation_unit b ON a.organisation_unit_id = b.id
                                    WHERE b.parent_org_unit_id IN (
                                        SELECT d.organisation_unit_id FROM users d WHERE d.ID = @logged_in_user_id
                                    )
                                ))
                                OR
                                (@is_global_responsibility = 1 AND bru.user_id IN (
                                    SELECT DISTINCT a.ID 
                                    FROM users a
                                    JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                                    WHERE b.parent_org_unit_tier_id IN (
                                        SELECT d.organisation_unit_tier_id FROM users d WHERE d.ID = @logged_in_user_id
                                    )
                                ))
                            )
                        GROUP BY 
                            c.name,
                            am.recon_month,
                            YEAR(am.recon_month),
                            DATENAME(month, am.recon_month) 
                        ORDER BY 
                            c.name, year, 
                            MIN(MONTH(am.recon_month))
                        OPTION (MAXRECURSION 1000);
                  """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            reconciliations = [
                FileUpload(
                    bank_account=row.bank_account,
                    year=row.year,
                    month=row.month,
                    responsible_users=row.responsible_users,
                    days_overdue=row.days_overdue
                )
                for row in result
            ]
            return reconciliations
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_next_approver_id(initiators_pending_submission_of_reconciliations):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Example list of user IDs
            logged_in_user_ids = initiators_pending_submission_of_reconciliations

            # Generate the comma-separated list for SQL
            user_ids_str = ', '.join(str(uid) for uid in logged_in_user_ids)

            query = f"""        
                    DECLARE @work_breakdown_level INT = 2;		
                    
                    WITH ParentOrgUnits AS (
                        SELECT DISTINCT b.parent_org_unit_id 
                        FROM users a
                        JOIN organisation_unit b ON a.organisation_unit_id = b.id 
                        WHERE a.ID IN ({user_ids_str})
                    ),
                    ParentOrgUnitTiers AS (
                        SELECT DISTINCT b.parent_org_unit_tier_id 
                        FROM users a
                        JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id 
                        WHERE a.ID IN ({user_ids_str})
                    ),
                    GlobalApprovers AS (
                        SELECT DISTINCT u.ID
                        FROM users u
                        JOIN user_role ur ON u.id = ur.user_id
                        JOIN role r ON ur.role_id = r.id
                        JOIN role_workflow_breakdown rwb ON r.id = rwb.role_id
                        JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                        WHERE wb.is_workflow_level = 1
                        AND wb.level = @work_breakdown_level
                        AND wb.is_responsibility_global = 1
                        AND u.ID IN (
                            SELECT DISTINCT a.ID
                            FROM users a
                            JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                            WHERE b.id IN (SELECT parent_org_unit_tier_id FROM ParentOrgUnitTiers)
                        )
                    ),
                    OrgBasedApprovers AS (
                        SELECT DISTINCT u.ID
                        FROM users u
                        JOIN user_role ur ON u.id = ur.user_id
                        JOIN role r ON ur.role_id = r.id
                        JOIN role_workflow_breakdown rwb ON r.id = rwb.role_id
                        JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                        WHERE wb.is_workflow_level = 1
                        AND wb.level = @work_breakdown_level
                        AND wb.is_responsibility_global = 0
                        AND u.ID IN (
                            SELECT DISTINCT a.ID
                            FROM users a
                            JOIN organisation_unit b ON a.organisation_unit_id = b.id
                            WHERE b.id IN (SELECT parent_org_unit_id FROM ParentOrgUnits)
                        )
                    )
                    
                    SELECT DISTINCT ID
                    FROM (
                        SELECT ID FROM GlobalApprovers
                        UNION
                        SELECT ID FROM OrgBasedApprovers
                    ) AS Approvers
                    ORDER BY ID ASC;
            """
            cursor.execute(query, )
            result = cursor.fetchall()

            return [row.ID for row in result]
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_id_of_file_upload_2(bank_account, year, month):
        # Convert month name to its corresponding number
        month_map = {
            "January": 1, "February": 2, "March": 3, "April": 4,
            "May": 5, "June": 6, "July": 7, "August": 8,
            "September": 9, "October": 10, "November": 11, "December": 12
        }
        # If month is a string, convert to integer
        if isinstance(month, str):
            month = month_map.get(month)
            if month is None:
                raise ValueError(f"Invalid month name: {month}")

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT fu.id, fu.file_name
            FROM file_upload fu
            LEFT OUTER JOIN bank_account ba ON fu.bank_account_id = ba.id
            WHERE ba.name = ? AND fu.year = ? AND fu.month = ? AND fu.submission_status = 0 
            AND fu.removed_by_user_on_upload_page = 0
        """, (bank_account, year, month))

        row = cursor.fetchone()
        conn.close()

        if row:
            return type('Obj', (object,), {"id": row[0], "file_name": row[1]})
        return None

    @staticmethod
    def update_file_name(file_id, new_filename):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE file_upload SET file_name = ? WHERE id = ?
        """, (new_filename, file_id))
        conn.commit()
        conn.close()


class FileDelete:
    def __init__(self, filename):
        self.filename = filename

    @staticmethod
    def remove_file_by_user_on_upload_page(file_name):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        # Check if file exists in the database
        cursor.execute("SELECT COUNT(*) FROM file_upload WHERE file_name = ?", (file_name,))
        file_exists = cursor.fetchone()[0]

        if file_exists:
            try:
                # Update `removed_by_user_on_upload_page` to 1
                cursor.execute(
                    "UPDATE file_upload SET removed_by_user_on_upload_page = 1 WHERE file_name = ?",
                    (file_name,)
                )
                conn.commit()
                return file_name
            except pyodbc.Error as e:
                print("Database update error:", e)
                conn.rollback()
                return None
            finally:
                conn.close()


class BankAccount:
    def __init__(self, id=None, name=None, bank_id=None, currency_id=None, strategic_business_unit_id=None, account=None, bank=None, currency=None, unit=None, creation_date=None, bank_account_name=None, bank_name=None, currency_name=None, org_unit_name=None):
        self.id = id
        self.name = name
        self.bank_id = bank_id
        self.currency_id = currency_id
        self.strategic_business_unit_id = strategic_business_unit_id
        self.account = account
        self.bank = bank
        self.currency = currency
        self.unit = unit
        self.creation_date = creation_date
        self.bank_account_name = bank_account_name
        self.bank_name = bank_name
        self.currency_name = currency_name
        self.org_unit_name = org_unit_name

    @staticmethod
    def get_bank_accounts_for_dropdown_menu(user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """SELECT ba.id, ba.name, ba.bank_id, ba.currency_id, ba.strategic_business_unit_id FROM 
            bank_account ba LEFT OUTER JOIN bank_account_responsible_user baru ON ba.id = baru.bank_account_id LEFT 
            OUTER JOIN users u ON baru.user_id = u.ID WHERE u.ID = ? ORDER BY ba.name"""
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            bank_accounts = [BankAccount(row.id, row.name, row.bank_id, row.currency_id, row.strategic_business_unit_id)
                             for row in result]
            return bank_accounts
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_bank_account_name_by_id(bank_account):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # check if User has a request pending submission
            cursor.execute("SELECT name FROM bank_account WHERE id = ? ", bank_account)

            bank_account_name = cursor.fetchone()[0]  # Fetch last batch_id
            return bank_account_name
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_bank_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT id, name FROM bank ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            bank_details = [
                Role(id=row.id, name=row.name)
                for row in result
            ]
            return bank_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def bank_name_exists(bankname):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM bank WHERE name = ?"
            cursor.execute(query, (bankname,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check username existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_bank(bank_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                INSERT INTO bank (name)
                VALUES (?)
            """
            cursor.execute(query, (bank_name,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new bank: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_bank_details(bank_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                SELECT id, name FROM bank WHERE name = ?
            """
            cursor.execute(query, (bank_name,))
            result = cursor.fetchall()

            bank_details = [
                BankAccount(id=row.id, name=row.name)
                for row in result
            ]
            return bank_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_bank(bank_id, bank_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE bank SET name = ? WHERE id = ?
            """
            cursor.execute(query, (bank_name, bank_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update bank: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_bank_account_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT ba.id, ba.name as account, b.name as bank, c.name as currency, ou.name as unit, 
                        CONVERT(date, ba.creation_date) AS creation_date
                        FROM bank_account ba 
                        LEFT OUTER JOIN bank b ON ba.bank_id = b.id
                        LEFT OUTER JOIN currency c ON ba.currency_id = c.id
                        LEFT OUTER JOIN organisation_unit ou ON ba.strategic_business_unit_id = ou.id
                        ORDER BY ba.name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            bank_details = [
                BankAccount(id=row.id, account=row.account, bank=row.bank, currency=row.currency, unit=row.unit, creation_date=row.creation_date)
                for row in result
            ]
            return bank_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def bank_account_name_exists(bank_account_name):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM bank_account WHERE name = ?"
            cursor.execute(query, (bank_account_name,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check bank account existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_bank_account(bankAccountName, bank_id, currency_id, org_unit_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                        INSERT INTO bank_account (name, bank_id, currency_id, strategic_business_unit_id, creation_date)
                        VALUES (?, ?, ?, ?, GETDATE())
                    """
            cursor.execute(query, (bankAccountName, bank_id, currency_id, org_unit_id))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new bank: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_bank_account_details(bank_account_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()
        try:
            query = """
                SELECT ba.id, ba.name AS bank_account_name, b.id AS bank_id,
                       c.id AS currency_id, ou.id AS org_unit_id, ba.creation_date
                FROM bank_account ba
                LEFT OUTER JOIN bank b ON ba.bank_id = b.id
                LEFT OUTER JOIN currency c ON ba.currency_id = c.id
                LEFT OUTER JOIN organisation_unit ou ON ba.strategic_business_unit_id = ou.id
                WHERE ba.name = ?
            """
            cursor.execute(query, (bank_account_name,))
            result = cursor.fetchall()

            bank_account_details = [
                {
                    "id": row.id,
                    "bankaccountname": row.bank_account_name,
                    "bank": row.bank_id,
                    "currency": row.currency_id,
                    "org_unit": row.org_unit_id,
                    "creation_date": row.creation_date
                }
                for row in result
            ]

            return bank_account_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_bank_account(bank_acc_id, bank_id, currency_id, org_unit_id, creation_date):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE bank_account
                SET bank_id = ?, currency_id = ?, strategic_business_unit_id = ?, creation_date = ? 
                WHERE id = ?
            """
            cursor.execute(query, (bank_id, currency_id, org_unit_id, creation_date, bank_acc_id,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update bank account: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class Role:
    def __init__(self, id=None, name=None):
        self.id = id
        self.name = name

    @staticmethod
    def get_all_role_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT id, name FROM role ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            role_details = [
                Role(id=row.id, name=row.name)
                for row in result
            ]
            return role_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def role_name_exists(rolename):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM role WHERE name = ?"
            cursor.execute(query, (rolename,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check username existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_role(role_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                INSERT INTO role (name)
                VALUES (?)
            """
            cursor.execute(query, (role_name,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new role: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_role(role_id, role_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE role SET name = ? WHERE id = ?
            """
            cursor.execute(query, (role_name, role_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update user: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_roles():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                SELECT id, name FROM role ORDER BY name
            """
            cursor.execute(query, )
            result = cursor.fetchall()

            usernames = [
                Role(id=row.id, name=row.name)
                for row in result
            ]
            return usernames
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_role_details(role_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                SELECT id, name FROM role WHERE name = ?
            """
            cursor.execute(query, (role_name,))
            result = cursor.fetchall()

            usernames = [
                Role(id=row.id, name=row.name)
                for row in result
            ]
            return usernames
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()


class Workflow:
    def __init__(self, id=None, name=None, role_id=None, role_name=None, workflow_breakdown_id=None,
                 workflow_breakdown_name=None, workflow_id=None, level=None, is_responsibility_global=None,
                 menu_item_id=None, is_workflow_level=None):
        self.id = id
        self.name = name
        self.role_id = role_id
        self.role_name = role_name
        self.workflow_breakdown_id = workflow_breakdown_id
        self.workflow_breakdown_name = workflow_breakdown_name
        self.workflow_id = workflow_id
        self.level = level
        self.is_responsibility_global = is_responsibility_global
        self.menu_item_id = menu_item_id
        self.is_workflow_level = is_workflow_level

    @staticmethod
    def get_all_workflow_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT id, name FROM workflow ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            workflow_details = [
                Workflow(id=row.id, name=row.name)
                for row in result
            ]
            return workflow_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def workflow_name_exists(workflowName):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM workflow WHERE name = ?"
            cursor.execute(query, (workflowName,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check workflow name existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_workflow(workflow_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                INSERT INTO workflow (name)
                VALUES (?)
            """
            cursor.execute(query, (workflow_name,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new workflow: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_workflow(workflow_id, workflow_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE workflow SET name = ? WHERE id = ?
            """
            cursor.execute(query, (workflow_name, workflow_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update workflow: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_role_workflow_breakdown_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT rwb.id, rwb.role_id, r.name AS role_name, rwb.workflow_breakdown_id, 
                        wb.name AS workflow_breakdown_name
                        FROM role_workflow_breakdown rwb
                        LEFT OUTER JOIN role r ON rwb.role_id = r.id
                        LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                        ORDER BY rwb.role_id, r.name, rwb.workflow_breakdown_id, wb.name
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            workflow_details = [
                Workflow(id=row.id, role_id=row.role_id, role_name=row.role_name,
                         workflow_breakdown_id=row.workflow_breakdown_id,
                         workflow_breakdown_name=row.workflow_breakdown_name)
                for row in result
            ]
            return workflow_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_workflow_breakdown_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT id, workflow_id, level, name, is_responsibility_global, menu_item_id, is_workflow_level 
                        FROM workflow_breakdown
                        ORDER BY id, workflow_id, level, name
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            workflow_breakdown_details = [
                Workflow(id=row.id, workflow_id=row.workflow_id, level=row.level,
                         name=row.name, is_responsibility_global=row.is_responsibility_global,
                         menu_item_id=row.menu_item_id, is_workflow_level=row.is_workflow_level)
                for row in result
            ]
            return workflow_breakdown_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def check_role_workflow_breakdown_exists(role_id, workflow_breakdown_id):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM role_workflow_breakdown WHERE role_id = ? AND workflow_breakdown_id = ?"
            cursor.execute(query, (role_id, workflow_breakdown_id,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check role-workflow-breakdown existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_role_workflow_breakdown(role_id, workflow_breakdown_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                INSERT INTO role_workflow_breakdown (role_id, workflow_breakdown_id)
                VALUES (?, ?)
            """
            cursor.execute(query, (role_id, workflow_breakdown_id,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new breakdown: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_role_workflow_breakdown(role_workflow_breakdown_id, role_id, workflow_breakdown_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE role_workflow_breakdown SET role_id = ?, workflow_breakdown_id = ? WHERE id = ?
            """
            cursor.execute(query, (role_id, workflow_breakdown_id, role_workflow_breakdown_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update role-workflow-breakdown: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class WorkflowBreakdown:
    def __init__(self, id=None, workflow_id=None, level=None, name=None, is_responsibility_global=None, menu_item=None,
                 role_name=None, workflow_name=None, menu_item_id=None, is_workflow_level=None):
        self.id = id
        self.workflow_id = workflow_id
        self.level = level
        self.name = name
        self.is_responsibility_global = is_responsibility_global
        self.menu_item = menu_item
        self.role_name = role_name
        self.workflow_name = workflow_name
        self.menu_item_id = menu_item_id
        self.is_workflow_level = is_workflow_level

    @staticmethod
    def get_workflow_breakdown_for_reconciliation_approval(workflow_id, is_workflow_level=True):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Get workflow breakdown
            query = """SELECT wb.id, wb.workflow_id, wb.level, wb.name, 
                        wb.is_responsibility_global, wb.menu_item_id, r.name AS role_name 
                        FROM workflow_breakdown wb
                        JOIN role_workflow_breakdown rwb ON wb.id = rwb.workflow_breakdown_id
                        JOIN role r ON rwb.role_id = r.id
                        WHERE wb.workflow_id = ? AND wb.is_workflow_level = ?
                        ORDER BY wb.level ASC
                    """
            cursor.execute(query, (workflow_id, is_workflow_level))
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            workflows = [WorkflowBreakdown(row[0], row[1], row[2], row[3], row[4], row[5], row[6]) for row in result]

            return workflows
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_workflow_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT id, name FROM workflow ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            workflow_details = [
                Workflow(id=row.id, name=row.name)
                for row in result
            ]
            return workflow_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_every_workflow_breakdown_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT 
                            wb.id,
                            wb.name,
                            wb.workflow_id,
                            wf.name AS workflow_name,
                            wb.level,
                            CASE 
                                WHEN wb.is_responsibility_global = 1 THEN 'Yes' 
                                ELSE 'No' 
                            END AS is_responsibility_global,
                            wb.menu_item_id,
                            CASE 
                                WHEN wb.is_workflow_level = 1 THEN 'Yes' 
                                ELSE 'No' 
                            END AS is_workflow_level
                        FROM 
                            workflow_breakdown wb
                        LEFT OUTER JOIN 
                            workflow wf ON wb.workflow_id = wf.id;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            workflow_breakdown_details = [
                WorkflowBreakdown(id=row.id, name=row.name, workflow_id=row.workflow_id,
                                  workflow_name=row.workflow_name, level=row.level,
                                  is_responsibility_global=row.is_responsibility_global, menu_item_id=row.menu_item_id,
                                  is_workflow_level=row.is_workflow_level)
                for row in result
            ]
            return workflow_breakdown_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def workflow_breakdown_exists(workflowBreakdownName, workflow_id, level_id, item_menu_id, is_responsibility_global,
                                  is_workflow_level):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = ("SELECT COUNT(*) FROM workflow_breakdown WHERE workflow_id = ? AND level = ? AND name = ? AND "
                     "is_responsibility_global = ? AND menu_item_id = ? AND is_workflow_level = ?")
            cursor.execute(query, (workflow_id, level_id, workflowBreakdownName, is_responsibility_global,
                                   item_menu_id, is_workflow_level, ))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check workflow name existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_workflow_breakdown(workflowBreakdownName, workflow_id, level_id, item_menu_id, is_responsibility_global, is_workflow_level):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                INSERT INTO workflow_breakdown (workflow_id, level, name, is_responsibility_global, menu_item_id, is_workflow_level)
                VALUES (?, ?, ?, ?, ?, ?)
            """
            cursor.execute(query, (workflow_id, level_id, workflowBreakdownName, is_responsibility_global, item_menu_id, is_workflow_level))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new workflow breakdown: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_workflow(workflow_id, workflow_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE workflow SET name = ? WHERE id = ?
            """
            cursor.execute(query, (workflow_name, workflow_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update workflow: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_role_workflow_breakdown_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT rwb.id, rwb.role_id, r.name AS role_name, rwb.workflow_breakdown_id, 
                        wb.name AS workflow_breakdown_name
                        FROM role_workflow_breakdown rwb
                        LEFT OUTER JOIN role r ON rwb.role_id = r.id
                        LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                        ORDER BY rwb.role_id, r.name, rwb.workflow_breakdown_id, wb.name
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            workflow_details = [
                Workflow(id=row.id, role_id=row.role_id, role_name=row.role_name,
                         workflow_breakdown_id=row.workflow_breakdown_id,
                         workflow_breakdown_name=row.workflow_breakdown_name)
                for row in result
            ]
            return workflow_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_workflow_breakdown(workflowBreakdownIdEdit, workflowBreakdownNameEdit, workflowEdit, levelEdit,
                                  item_menu_id_edit, is_responsibility_global_edit, is_workflow_level_edit):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """UPDATE workflow_breakdown SET workflow_id = ?, level = ?, name = ?, is_responsibility_global = 
            ?, menu_item_id = ?, is_workflow_level = ? WHERE id = ?"""
            cursor.execute(query, (workflowEdit, levelEdit, workflowBreakdownNameEdit, is_responsibility_global_edit,
                                   item_menu_id_edit, is_workflow_level_edit, workflowBreakdownIdEdit))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update workflow breakdown: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class UserRole:
    def __init__(self, id=None, user_id=None, user_name=None, username=None, role_id=None, role_name=None, start_datetime=None, expiry_datetime=None):
        self.id = id
        self.user_id = user_id
        self.username = username
        self.user_name = user_name
        self.role_id = role_id
        self.role_name = role_name
        self.start_datetime = start_datetime
        self.expiry_datetime = expiry_datetime

    @staticmethod
    def get_all_user_roles_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT ur.id, ur.user_id, u.username,
                        LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS user_name, 
                        ur.role_id, r.name as role_name, 
                        CAST(ur.start_datetime AS DATE) AS start_datetime, 
                        CAST(ur.expiry_datetime AS DATE) AS expiry_datetime 
                        FROM user_role ur LEFT OUTER JOIN users u ON ur.user_id = u.ID 
                        LEFT OUTER JOIN role r ON ur.role_id = r.id 
                        ORDER BY u.Fname, u.Mname, u.Sname;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            user_role_details = [
                UserRole(id=row.id, user_id=row.user_id, username=row.username, user_name=row.user_name, role_id=row.role_id, role_name=row.role_name, start_datetime=row.start_datetime, expiry_datetime=row.expiry_datetime)
                for row in result
            ]
            return user_role_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def user_role_exists(user_id, role_id):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM user_role WHERE user_id = ? AND role_id = ?"
            cursor.execute(query, (user_id, role_id,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check user-role existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_user_role(user_id, role_id, start_date, end_date):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                INSERT INTO user_role (user_id, role_id, start_datetime, expiry_datetime)
                VALUES (?, ?, ?, ?)
            """
            cursor.execute(query, (user_id, role_id, start_date, end_date))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new user-role: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_user_role_id(user_name, role_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT ur.id FROM user_role ur  LEFT OUTER JOIN users u ON ur.user_id = u.ID 
                        LEFT OUTER JOIN role r ON ur.role_id = r.id WHERE u.Username = ? AND r.name = ?
                    """
            cursor.execute(query, (user_name, role_name,))
            result = cursor.fetchall()

            user_role_id_details = [
                {
                    "id": row.id
                }
                for row in result
            ]
            return user_role_id_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_user_role(user_role_id, start_date, expiry_date):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE user_role SET start_datetime = ?, expiry_datetime = ? WHERE id = ?
            """
            cursor.execute(query, (start_date, expiry_date, user_role_id))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update user: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class ReconciliationApprovals:
    def __init__(self, id, file_upload_id, decision, approver_id, approver, level, comment, date_time):
        self.id = id
        self.file_upload_id = file_upload_id
        self.decision = decision
        self.approver_id = approver_id
        self.approver = approver
        self.level = level
        self.comment = comment
        self.date_time = date_time

    @staticmethod
    def insert_into_reconciliation_approvals(file_upload_id, decision, approver_id, level, comment):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        now = datetime.now()

        try:
            cursor.execute("SELECT COALESCE(MAX(id), 0) FROM reconciliation_approvals")
            last_reconciliation_approvals_id = cursor.fetchone()[0]  # Fetch last batch_id

            # Set new batch_id
            last_reconciliation_approvals_id = (last_reconciliation_approvals_id + 1) \
                if last_reconciliation_approvals_id else 1

            cursor.execute(
                "INSERT INTO reconciliation_approvals (id, file_upload_id, decision, approver_id, level, comment, "
                "date_time)"
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (last_reconciliation_approvals_id, file_upload_id, decision, approver_id, level, comment, now),
            )
            conn.commit()
            return last_reconciliation_approvals_id
        except pyodbc.Error as e:
            print("Database insert error:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def get_latest_reconciliation_approval_level(file_upload_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # check if User has a request pending submission
            cursor.execute("SELECT TOP 1 COALESCE(level, 0) FROM reconciliation_approvals WHERE file_upload_id = ? "
                           "ORDER BY date_time DESC;", file_upload_id)

            latest_approval_level = cursor.fetchone()[0]  # Fetch last batch_id
            return latest_approval_level
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_reconciliation_approval_levels_of_given_file(file_upload_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Get the latest approval level for the given file
            query = """
                        SELECT ra.level, CASE WHEN ra.decision = 1 
                        THEN 'Submitted' WHEN ra.decision = 2 THEN 'Approved' WHEN ra.decision = 3 THEN 'Rejected' 
                        ELSE 'Pending' END AS decision,
                        CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) AS approver, ra.date_time, ra.comment 
                        FROM reconciliation_approvals ra
                        LEFT OUTER JOIN users u ON ra.approver_id = u.ID
                        WHERE ra.file_upload_id = ? ORDER BY ra.date_time
                    """
            cursor.execute(query, (file_upload_id,))  # Pass the parameter twice
            result = cursor.fetchall()  # Fetch results properly

            return result if result else []
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()


class Audit:
    def __init__(self, id=None, user_id=None, name=None, action=None, details=None, date_time=None, ip_address=None,
                 username=None):
        self.id = id
        self.user_id = user_id
        self.name = name
        self.action = action
        self.details = details
        self.date_time = date_time
        self.ip_address = ip_address
        self.username = username

    @staticmethod
    def log_audit_trail(user_id, action, details="", ip_address=None):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO audit_trail (user_id, action, details, timestamp, ip_address)
                VALUES (?, ?, ?, ?, ?)
            """, (
                user_id,
                action,
                details,
                datetime.now(),
                ip_address
            ))
            conn.commit()
            return action
        except Exception as e:
            print(f"Error while updating audit trail: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_audit_trail_records():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT at.id, at.user_id, u.Username AS username, 
                        LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name, 
                        at.action, at.details, at.timestamp as date_time, at.ip_address 
                        FROM audit_trail at
                        LEFT OUTER JOIN users u ON at.user_id = u.ID
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            audit_trail_records = [
                Audit(id=row.id, user_id=row.user_id, username=row.username, name=row.name, action=row.action,
                      details=row.details, date_time=row.date_time, ip_address=row.ip_address)
                for row in result
            ]
            return audit_trail_records
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()


class Currency:
    def __init__(self, id=None, name=None, code=None):
        self.id = id
        self.name = name
        self.code = code

    @staticmethod
    def get_all_currency_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT id, name, code FROM currency ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            currency_details = [
                Currency(id=row.id, name=row.name, code=row.code)
                for row in result
            ]
            return currency_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_currency_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT id, name, code FROM currency ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            currency_details = [
                Currency(id=row.id, name=row.name, code=row.code)
                for row in result
            ]
            return currency_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def currency_name_exists(currencyname):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM currency WHERE name = ?"
            cursor.execute(query, (currencyname,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check name of currency existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_currency(currency_name, currency_code):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                INSERT INTO currency (name, code)
                VALUES (?, ?)
            """
            cursor.execute(query, (currency_name, currency_code,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new role: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_currency_details(currency_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                SELECT id, name, code FROM currency WHERE name = ?
            """
            cursor.execute(query, (currency_name,))
            result = cursor.fetchall()

            currencies = [
                Currency(id=row.id, name=row.name, code=row.code)
                for row in result
            ]
            return currencies
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_currency(currency_id, currency_name, currency_code):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE currency SET name = ?, code = ? WHERE id = ?
            """
            cursor.execute(query, (currency_name, currency_code, currency_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update user: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class BankAccountResponsibleUser:
    def __init__(self, id=None, bank_account_id=None, user_id=None, bank_account_name=None, username=None, name=None, is_active=None, status=None):
        self.id = id
        self.bank_account_id = bank_account_id
        self.user_id = user_id
        self.bank_account_name = bank_account_name
        self.username = username
        self.name = name
        self.is_active = is_active
        self.status = status

    @staticmethod
    def get_all_bank_responsible_person_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT baru.id, ba.name AS bank_account_name, u.Username AS username, 
                        LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name,
                        CASE 
                            WHEN baru.is_active = 1 THEN 'Active' 
                            ELSE 'Disabled' 
                        END AS status
                        FROM bank_account_responsible_user baru
                        LEFT OUTER JOIN bank_account ba ON baru.bank_account_id = ba.id
                        LEFT OUTER JOIN users u ON baru.user_id = u.ID
                        WHERE ba.name is not null
                        ORDER BY ba.name, u.Username;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            responsible_user_details = [
                BankAccountResponsibleUser(id=row.id, bank_account_name=row.bank_account_name, username=row.username, name=row.name, status=row.status)
                for row in result
            ]
            return responsible_user_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def bank_account_responsibility_exists(bankAccId, userId):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM bank_account_responsible_user WHERE bank_account_id = ? AND user_id = ?"
            cursor.execute(query, (bankAccId, userId,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check user-role existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_bank_account_responsibility(bank_acc_id, user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                INSERT INTO bank_account_responsible_user (bank_account_id, user_id)
                VALUES (?, ?)
            """
            cursor.execute(query, (bank_acc_id, user_id))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new user-role: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_bank_account_responsibility_details(bank_account_name, username):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                SELECT ba.id, ba.id AS bank_account_id, 
                u.ID AS user_id, baru.is_active
                FROM bank_account_responsible_user baru
                LEFT OUTER JOIN bank_account ba ON baru.bank_account_id = ba.id
                LEFT OUTER JOIN users u ON baru.user_id = u.ID
                WHERE ba.name is not null AND ba.name = ? AND u.Username = ?
            """
            cursor.execute(query, (bank_account_name, username, ))
            result = cursor.fetchall()

            responsibilities = [
                BankAccountResponsibleUser(id=row.id, bank_account_id=row.bank_account_id, user_id=row.user_id, is_active=row.is_active)
                for row in result
            ]
            return responsibilities
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_bank_account_responsibility(responsibility_id, bank_acc_id, user_id, is_active):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE bank_account_responsible_user SET bank_account_id = ?, user_id = ?, is_active = ? WHERE id = ?
            """
            cursor.execute(query, (bank_acc_id, user_id, is_active, responsibility_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update user: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class OrganisationUnitTier:
    def __init__(self, id=None, name=None, parent_org_unit_tier_name=None, parent_org_unit_tier_id=None):
        self.id = id
        self.name = name
        self.parent_org_unit_tier_name = parent_org_unit_tier_name
        self.parent_org_unit_tier_id = parent_org_unit_tier_id

    @staticmethod
    def get_all_org_unit_tier_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT out.id, out.name, 
                        (SELECT name FROM organisation_unit_tier WHERE id = out.parent_org_unit_tier_id) AS parent_org_unit_tier_name,
                        parent_org_unit_tier_id 
                        FROM organisation_unit_tier out ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            unit_tier_details = [
                OrganisationUnitTier(id=row.id, name=row.name, parent_org_unit_tier_name=row.parent_org_unit_tier_name,
                                     parent_org_unit_tier_id=row.parent_org_unit_tier_id)
                for row in result
            ]
            return unit_tier_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def org_unit_name_exists(unit_name):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM organisation_unit WHERE name = ?"
            cursor.execute(query, (unit_name,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check name of Organisation Unit Name existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_org_unit_tier(unit_tier_name, parent_unit_tier):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                INSERT INTO organisation_unit_tier (name, parent_org_unit_tier_id)
                VALUES (?, ?)
            """
            cursor.execute(query, (unit_tier_name, parent_unit_tier,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new role: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_org_unit_tier(org_unit_tier_id, org_unit_tier_name, parent_org_unit_tier_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE organisation_unit_tier SET name = ?, parent_org_unit_tier_id = ? WHERE id = ?
            """
            cursor.execute(query, (org_unit_tier_name, parent_org_unit_tier_id, org_unit_tier_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update Organisation Unit Tier: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def org_unit_tier_exists(org_unit_tier_name, parent_org_unit_tier_id):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM organisation_unit_tier WHERE name = ? AND parent_org_unit_tier_id = ?"
            cursor.execute(query, (org_unit_tier_name, parent_org_unit_tier_id,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check org_unit_tier existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class OrganisationUnit:
    def __init__(self, id=None, name=None, parent_org_unit_id=None, parent_org_unit_name=None, org_unit_tier_name=None, org_unit_tier_id=None):
        self.id = id
        self.name = name
        self.parent_org_unit_id = parent_org_unit_id
        self.parent_org_unit_name = parent_org_unit_name
        self.org_unit_tier_name = org_unit_tier_name
        self.org_unit_tier_id = org_unit_tier_id

    @staticmethod
    def get_all_org_unit_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT ou.id, ou.name, ou.parent_org_unit_id, 
                        (SELECT name FROM organisation_unit WHERE id = ou.parent_org_unit_id) AS parent_org_unit_name
                        ,out.id AS org_unit_tier_id, out.name AS org_unit_tier_name 
                        FROM organisation_unit ou 
                        LEFT OUTER JOIN organisation_unit_tier out ON ou.org_unit_tier_id = out.id
                        ORDER BY ou.name
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            unit_details = [
                OrganisationUnit(id=row.id, name=row.name, parent_org_unit_id=row.parent_org_unit_id,
                                 parent_org_unit_name=row.parent_org_unit_name, org_unit_tier_id=row.org_unit_tier_id,
                                 org_unit_tier_name=row.org_unit_tier_name)
                for row in result
            ]
            return unit_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def org_unit_name_exists(unit_name):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM organisation_unit WHERE name = ?"
            cursor.execute(query, (unit_name,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check name of currency existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_org_unit(unit_name, parent_unit, unit_tier):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                INSERT INTO organisation_unit (name, org_unit_tier_id, parent_org_unit_id)
                VALUES (?, ?, ?)
            """
            cursor.execute(query, (unit_name, unit_tier, parent_unit,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new organisation unit: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def check_unit_exists(org_unit_name, parent_unit_id, org_unit_tier_id):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = ("SELECT COUNT(*) FROM organisation_unit WHERE name = ? AND org_unit_tier_id = ? AND "
                     "parent_org_unit_id = ?")
            cursor.execute(query, (org_unit_name, org_unit_tier_id, parent_unit_id, ))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check Organisation Unit existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_org_unit(org_unit_id, org_unit_name, parent_unit_id, org_unit_tier_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE organisation_unit SET name = ?, org_unit_tier_id = ?, parent_org_unit_id = ? WHERE id = ?
            """
            cursor.execute(query, (org_unit_name, org_unit_tier_id, parent_unit_id, org_unit_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update Organisation Unit: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class MenuItem:
    def __init__(self, id=None, name=None):
        self.id = id
        self.name = name

    @staticmethod
    def get_all_menu_item_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT id, name FROM menu_item ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            menu_item_details = [
                MenuItem(id=row.id, name=row.name)
                for row in result
            ]
            return menu_item_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def menu_item_name_exists(menuItemName):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM menu_item WHERE name = ?"
            cursor.execute(query, (menuItemName,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check item menu name existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_menu_item(menuItemName):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                INSERT INTO menu_item (name)
                VALUES (?)
            """
            cursor.execute(query, (menuItemName,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new menu item: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_menu_item(edit_menu_item_id, menu_item_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE menu_item SET name = ? WHERE id = ?
            """
            cursor.execute(query, (menu_item_name, edit_menu_item_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update menu item: ", e)
            return False
        finally:
            cursor.close()
            conn.close()
