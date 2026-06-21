import pyodbc
from sqlalchemy import null

from ActivityTracker import app, login_manager
from flask_login import UserMixin
from flask_bcrypt import Bcrypt
from datetime import datetime
from ActivityTracker.database import get_db_connection
from ActivityTracker import mail  # Import mail from __init__.py
from flask_mail import Message
from collections import defaultdict

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
            return []

        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT r.name FROM role r INNER JOIN user_role ur ON r.id = ur.role_id WHERE ur.user_id = ?",
                (self.id,)
            )
            return [row[0] for row in cursor.fetchall()]
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
            return None

        cursor = conn.cursor()
        cursor.execute(
            "SELECT ID, Username, Fname, Mname, Sname, Password, Email, is_active FROM users WHERE Username = ?",
            (username,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            return User(*row)
        return None

    @staticmethod
    def load_user(self, username):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()
        try:
            cursor.execute(
                "SELECT ID, Username, Fname, Mname, Sname, Password, Email FROM users WHERE Username = ?",
                (username,)
            )
            row = cursor.fetchone()
            if row:
                return User(row.id, row.username, row.fname, row.mname, row.sname, row.password, row.email)
            return None
        except Exception as e:
            print("Database error:", e)
            return None
        finally:
            cursor.close()
            conn.close()

    def get_id(self):
        return self.username

    @staticmethod
    def create_user_from_ldap(username, fname, sname, email):
        conn = get_db_connection()
        if conn is None:
            print("Could not connect to DB for LDAP user creation")
            return None

        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (Username, Fname, Mname, Sname, Password, Email, organisation_unit_id, organisation_unit_tier_id, is_active)
                VALUES (?, ?, '', ?, '', ?, 0, 0, 1)
            """, (username, fname, sname, email))
            conn.commit()
            print(f"User {username} created successfully from LDAP")
        except Exception as e:
            print(f"Error inserting LDAP user {username}: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def hash_password(password):
        return bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        if not self.password_hash:
            # No local password hash set
            return False
        try:
            return bcrypt.check_password_hash(self.password_hash, password)
        except ValueError as e:
            current_app.logger.warning(f"Invalid password hash for user '{self.username}': {e}")
            return False

    def has_permission(self, work_flow_breakdown_name):
        return any(
            work_flow_breakdown_name in [wfb.name for r in self.roles for wfb in r.workflows]
        )


class UserSummary:
    def __init__(self, id=None, username=None, name=None, email_address=None, email=None,
                 organisation_unit_tier_name=None, organisation_unit_name=None, status=None, fname=None, mname=None,
                 sname=None, password=None, is_active=None):
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
                UserSummary(username=row.username, name=row.name, email_address=row.email_address,
                            organisation_unit_tier_name=row.organisation_unit_tier_name,
                            organisation_unit_name=row.organisation_unit_name, status=row.status)
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
    def get_user_tagged_project_id(user_name, project_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT TOP 1
                            utp.id
                        FROM user_tagged_project AS utp
                            INNER JOIN users AS u
                                ON utp.user_id = u.ID
                            INNER JOIN mst_project AS mp
                                ON utp.project_id = mp.id
                        WHERE
                            u.Username = ?
                            AND mp.project_name = ?;
                    """
            cursor.execute(query, (user_name, project_name,))
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
    def insert_new_user_tagged_project(user_id, project_id, start_date, end_date):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                INSERT INTO user_tagged_project (user_id, project_id, start_datetime, expiry_datetime)
                VALUES (?, ?, ?, ?)
            """
            cursor.execute(query, (user_id, project_id, start_date, end_date))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new user-tagged-project: ", e)
            return False
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
            cursor.execute(query,
                           (username, fname, mname, sname, password_hash, email, org_unit_id, org_unit_tier_id, 1))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new user: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_user_tagged_project(user_tagged_project_id, start_date, expiry_date):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE user_tagged_project SET start_datetime = ?, expiry_datetime = ? WHERE id = ?
            """
            cursor.execute(query, (start_date, expiry_date, user_tagged_project_id))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update user: ", e)
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

    @staticmethod
    def get_all_usersnames():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                SELECT id, username, LTRIM(RTRIM(COALESCE(Fname + ' ' + Mname + ' ' + Sname, ''))) AS name 
                FROM users ORDER BY Fname, Mname, Sname;     
            """
            cursor.execute(query, )
            result = cursor.fetchall()

            usernames = [
                UserSummary(id=row.id, username=row.username, name=row.name)
                for row in result
            ]
            return usernames
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()


class ProjectKPI:
    def __init__(self, id=None, username=None, name=None, email_address=None, email=None,
                 organisation_unit_tier_name=None, organisation_unit_name=None, status=None, fname=None, mname=None,
                 sname=None, password=None, is_active=None, requester=None, project_kpi_setup_id=None,
                 project_code=None, project_name=None, creation_date=None, approve_as=None, process_name=None):
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
        self.requester = requester
        self.project_kpi_setup_id = project_kpi_setup_id
        self.project_code = project_code
        self.project_name = project_name
        self.creation_date = creation_date
        self.approve_as = approve_as
        self.process_name = process_name

    @staticmethod
    def get_available_credit_points_by_project_id_and_key_process_id(
            project_id,
            key_process_id,
            activity_id
    ):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                        DECLARE @project_id INT = ?;
                        DECLARE @key_process_id INT = ?;
                        DECLARE @activity_id INT = ?;
                        
                        SELECT
                            ISNULL(SUM(kpsd.credit_points), 0)
                            -
                            ISNULL(
                                (
                                    SELECT SUM(a.credit_points)
                                    FROM trn_activity_breakdown a
                                    INNER JOIN trn_activity_request b
                                        ON a.activity_id = b.id
                                    WHERE b.project_id = @project_id
                                      AND a.key_process_id = @key_process_id
                                ),
                                0
                            )
                            +
                            ISNULL(
                                (
                                    SELECT SUM(a.credit_points)
                                    FROM trn_activity_breakdown a
                                    INNER JOIN trn_activity_request b
                                        ON a.activity_id = b.id
                                    WHERE b.id = @activity_id
                                      AND a.key_process_id = @key_process_id
                                ),
                                0
                            ) AS available_credit_points
                        FROM trn_project_kpi_setup_details kpsd
                        INNER JOIN trn_project_kpi_setup kps
                            ON kpsd.project_kpi_setup_id = kps.id
                        WHERE kps.project_id = @project_id
                          AND kpsd.key_process_id = @key_process_id;
            """

            cursor.execute(query, (project_id, key_process_id, activity_id))

            row = cursor.fetchone()

            return row.available_credit_points if row else 0

        except Exception as e:
            print(f"Database error: {e}")
            return None

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_key_processes_by_project_id(project_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch tasks associated with the Key Process
            query = """
                        SELECT
                            kp.id,
                            kp.name AS process_name
                        FROM mst_key_process AS kp
                        INNER JOIN trn_project_kpi_setup_details AS kpsd
                            ON kp.id = kpsd.key_process_id
                        INNER JOIN trn_project_kpi_setup AS kps
                            ON kpsd.project_kpi_setup_id = kps.id
                        INNER JOIN mst_project AS p
                            ON kps.project_id = p.id
                        WHERE p.id = ?
                        ORDER BY kp.name ASC;
            """
            cursor.execute(query, (project_id,))
            result = cursor.fetchall()

            key_processes = [
                ProjectKPI(id=row.id, process_name=row.process_name)
                for row in result
            ]
            return key_processes
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_saved_project_kpi_request_details_3(kpi_request_setup_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT
                            a.id,
                            c.project_code,
                            c.project_name
                        FROM trn_project_kpi_setup_approvals AS a
                        LEFT JOIN trn_project_kpi_setup AS b
                            ON a.project_kpi_setup_id = b.id
                        LEFT JOIN mst_project AS c
                            ON b.project_id = c.id
                        WHERE a.project_kpi_setup_id = ?;
                    """
            cursor.execute(query, (kpi_request_setup_id,))
            result = cursor.fetchall()

            activity_request_details = [
                ProjectKPI(id=row.id, project_code=row.project_code, project_name=row.project_name)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_status_of_project_kpi_request(kpi_request_setup_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # Check if a record with the given bank_account, year, and month exists
            cursor.execute(
                "SELECT status FROM trn_project_kpi_setup WHERE id = ?", kpi_request_setup_id
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
    def get_project_kpi_request_initiator_user_id(kpi_request_setup_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # check if User has a request pending submission
            cursor.execute("SELECT created_by FROM trn_project_kpi_setup WHERE id = ?", kpi_request_setup_id)

            id_of_initiator = cursor.fetchone()[0]  # Fetch last batch_id

            return id_of_initiator
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_latest_project_kpi_request_approval_level(kpi_request_setup_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            cursor.execute("SELECT TOP 1 COALESCE(level, 0) FROM trn_project_kpi_setup_approvals "
                           "WHERE project_kpi_setup_id = ? ORDER BY date_time DESC;", kpi_request_setup_id)

            latest_approval_level = cursor.fetchone()[0]
            return latest_approval_level
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_project_kpi_setup_details(kpi_request_setup_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()
        try:
            query = """
                        SELECT
                            a.id,
                            b.name AS process_name,
                            a.credit_points,
                            CONVERT(varchar, a.creation_date, 23) AS creation_date
                        FROM trn_project_kpi_setup_details a
                        LEFT OUTER JOIN mst_key_process b
                            ON a.key_process_id = b.id
                        WHERE a.project_kpi_setup_id = ?
                        ORDER BY a.id;
            """
            cursor.execute(query, (kpi_request_setup_id,))
            columns = [col[0] for col in cursor.description]
            result = cursor.fetchall()
            return [dict(zip(columns, row)) for row in result]

        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_workflow_breakdown_for_kpi_setup_approval(workflow_id, is_workflow_level):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Get workflow breakdown
            query = """
                        SELECT
                            wb.id,
                            wb.workflow_id,
                            wb.level,
                            wb.name,
                            wb.is_responsibility_global,
                            wb.menu_item_id,
                            r.name AS role_name
                        FROM workflow_breakdown wb
                        JOIN role_workflow_breakdown rwb
                            ON wb.id = rwb.workflow_breakdown_id
                        JOIN role r
                            ON rwb.role_id = r.id
                        WHERE wb.workflow_id = ?
                          AND wb.is_workflow_level = ?
                        ORDER BY wb.level ASC;
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
    def get_project_kpi_setup_request_approval_levels(kpi_request_setup_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT
                            tpksa.level,
                            CASE tpksa.decision
                                WHEN 1 THEN 'Submitted'
                                WHEN 2 THEN 'Approved'
                                WHEN 3 THEN 'Rejected'
                                ELSE 'Pending'
                            END AS decision,
                            LTRIM(RTRIM(CONCAT(
                                ISNULL(u.Fname, ''),
                                ' ',
                                ISNULL(u.Mname, ''),
                                ' ',
                                ISNULL(u.Sname, '')
                            ))) AS approver,
                            tpksa.date_time,
                            ISNULL(tpksa.comment, '') AS comment
                        FROM trn_project_kpi_setup_approvals tpksa
                        LEFT JOIN users u
                            ON tpksa.approver_id = u.ID
                        WHERE tpksa.project_kpi_setup_id = ?
                        ORDER BY tpksa.date_time ASC;
                   """
            cursor.execute(query, (kpi_request_setup_id,))  # Pass the parameter twice
            result = cursor.fetchall()  # Fetch results properly

            return result if result else []
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_project_kpi_requests_pending_approval(user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                       DECLARE @logged_in_user_id INT = ?; -- Set logged-in user's ID

                        ;WITH GlobalFiles AS (
                            -- Get files where responsibility is global
                            SELECT 
                                tpksa.project_kpi_setup_id,
                                LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name,
                                pro.project_code, 
                                pro.project_name,
                                tpks.creation_date,
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tpks.status + 1
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tpks.id ORDER BY tpks.creation_date DESC) AS row_num
                            FROM trn_project_kpi_setup tpks
                            JOIN trn_project_kpi_setup_approvals tpksa ON tpks.id = tpksa.project_kpi_setup_id
                            JOIN mst_project pro ON tpks.project_id = pro.id
                            JOIN users u ON tpks.created_by = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tpksa.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                                    WHERE b.parent_org_unit_tier_id IN (
                                        SELECT d.organisation_unit_tier_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tpks.status != 0 
                                AND tpks.status + 1 IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 1
                                        AND e.ID = @logged_in_user_id
                                )
                        ),
                        OrgBasedFiles AS (
                            -- Get files where responsibility is restricted to specific organizational units
                            SELECT 
                                tpksa.project_kpi_setup_id,
                                LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name,
                                pro.project_code, 
                                pro.project_name, 
                                tpks.creation_date,
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tpks.status + 1
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tpks.id ORDER BY tpks.creation_date DESC) AS row_num
                            FROM trn_project_kpi_setup tpks
                            JOIN trn_project_kpi_setup_approvals tpksa ON tpks.id = tpksa.project_kpi_setup_id
                            JOIN mst_project pro ON tpks.project_id = pro.id
                            JOIN users u ON tpks.created_by = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tpksa.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit b ON a.organisation_unit_id = b.id
                                    WHERE b.parent_org_unit_id IN (
                                        SELECT d.organisation_unit_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tpks.status != 0 
                                AND tpks.status + 1 IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 0
                                        AND e.ID = @logged_in_user_id
                                )
                        )
                        -- name, project_kpi_setup_id, project_code, project_name, creation_date, approve_as
                        SELECT 
                            name, project_kpi_setup_id, project_code, project_name, creation_date, approve_as
                        FROM (
                            SELECT * FROM GlobalFiles WHERE row_num = 1
                            UNION
                            SELECT * FROM OrgBasedFiles WHERE row_num = 1
                        ) AS UniqueResults
                        WHERE approve_as IS NOT NULL
                        ORDER BY project_code, creation_date ASC;
            """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            activity_requests = [
                ProjectKPI(requester=row.name, project_kpi_setup_id=row.project_kpi_setup_id,
                           project_code=row.project_code, project_name=row.project_name,
                           creation_date=row.creation_date, approve_as=row.approve_as)
                for row in result
            ]
            return activity_requests
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_current_project_kpi_setup_id(user_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # check if User has a request pending submission
            cursor.execute("SELECT COALESCE(MAX(id), 0) FROM trn_project_kpi_setup WHERE status = 0 "
                           "AND created_by = ? ", user_id)

            project_kpi_setup_id = cursor.fetchone()[0]  # Fetch last project_kpi_setup_id
            return project_kpi_setup_id
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_current_project_kpi_setup_detail_id(current_project_kpi_setup_id, key_process_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # check if User has a request pending submission
            cursor.execute("SELECT id FROM trn_project_kpi_setup_details "
                           "WHERE project_kpi_setup_id = ? AND key_process_id = ? ",
                           current_project_kpi_setup_id, key_process_id,)

            project_kpi_setup_id = cursor.fetchone()[0]  # Fetch last project_kpi_setup_id
            return project_kpi_setup_id
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_saved_project_kpi_setup_details(project_kpi_setup_id):

        if not project_kpi_setup_id:
            return []

        conn = get_db_connection()

        if conn is None:
            return []

        cursor = conn.cursor()

        try:
            query = """
                        SELECT
                            kpi.id,
                            detail.id AS kpi_detail_id,
                            kpi.project_id,
                            project.project_code,
                            project.project_name,
                            process.name AS key_process_name,
                            detail.credit_points,
                            'Pending Submission' AS status
                        FROM trn_project_kpi_setup AS kpi
                        INNER JOIN trn_project_kpi_setup_details AS detail
                            ON kpi.id = detail.project_kpi_setup_id
                        LEFT JOIN mst_project AS project
                            ON kpi.project_id = project.id
                        LEFT JOIN mst_key_process AS process
                            ON detail.key_process_id = process.id
                        WHERE kpi.id = ?
                        ORDER BY process.name;
            """

            cursor.execute(query, (project_kpi_setup_id,))
            return cursor.fetchall()

        except Exception as e:
            print(f"Database error while retrieving KPI setup details: {e}")
            return []

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_saved_project_kpi_setup_details_2(kpi_detail_id):

        conn = get_db_connection()

        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                SELECT
                    a.id,
                    a.project_kpi_setup_id,
                    b.project_id,
                    a.key_process_id,
                    a.credit_points
                FROM trn_project_kpi_setup_details a
                INNER JOIN trn_project_kpi_setup b ON a.project_kpi_setup_id = b.id
                WHERE a.id = ?
            """

            cursor.execute(query, (kpi_detail_id,))

            row = cursor.fetchone()

            if not row:
                return None

            return {
                "id": row.id,
                "project_kpi_setup_id": row.project_kpi_setup_id,
                "project_id": row.project_id,
                "key_process_id": row.key_process_id,
                "credit_points": row.credit_points
            }

        except Exception as e:
            print(f"Database error: {e}")
            return None

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def project_kpi_setup_pending_approval_count(user_id):
        conn = get_db_connection()
        if conn is None:
            return 0  # Return 0 if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                       DECLARE @logged_in_user_id INT = ?; -- Set logged-in user's ID
                        
                        ;WITH GlobalFiles AS (
                            -- Get files where responsibility is global
                            SELECT 
                                LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name,
                                pro.project_code, 
                                pro.project_name,
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tpks.status + 1
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tpks.id ORDER BY tpks.creation_date DESC) AS row_num
                            FROM trn_project_kpi_setup tpks
                            JOIN trn_project_kpi_setup_approvals tpksa ON tpks.id = tpksa.project_kpi_setup_id
                            JOIN mst_project pro ON tpks.project_id = pro.id
                            JOIN users u ON tpks.created_by = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tpksa.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                                    WHERE b.parent_org_unit_tier_id IN (
                                        SELECT d.organisation_unit_tier_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tpks.status != 0 
                                AND tpks.status + 1 IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 1
                                        AND e.ID = @logged_in_user_id
                                )
                        ),
                        OrgBasedFiles AS (
                            -- Get files where responsibility is restricted to specific organizational units
                            SELECT 
                                LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name,
                                pro.project_code, 
                                pro.project_name, 
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tpks.status + 1
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tpks.id ORDER BY tpks.creation_date DESC) AS row_num
                            FROM trn_project_kpi_setup tpks
                            JOIN trn_project_kpi_setup_approvals tpksa ON tpks.id = tpksa.project_kpi_setup_id
                            JOIN mst_project pro ON tpks.project_id = pro.id
                            JOIN users u ON tpks.created_by = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tpksa.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit b ON a.organisation_unit_id = b.id
                                    WHERE b.parent_org_unit_id IN (
                                        SELECT d.organisation_unit_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tpks.status != 0 
                                AND tpks.status + 1 IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 0
                                        AND e.ID = @logged_in_user_id
                                )
                        )

                        SELECT 
                            COUNT(*) AS TotalPendingApprovals
                        FROM (
                            SELECT * FROM GlobalFiles WHERE row_num = 1
                            UNION
                            SELECT * FROM OrgBasedFiles WHERE row_num = 1
                        ) AS UniqueResults
                        WHERE approve_as IS NOT NULL;
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
    def get_pending_project_kpi_submissions_count(status, user_id):
        conn = get_db_connection()
        if conn is None:
            return 0  # Return 0 if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT 
                            COUNT(*)
                        FROM 
                            trn_project_kpi_setup a
                        INNER JOIN 
                            trn_project_kpi_setup_details b ON a.id = b.project_kpi_setup_id
                        WHERE a.status = ? AND a.created_by = ?
            """
            cursor.execute(query, [status, user_id])
            pending_submissions_count = cursor.fetchone()[0]
            return pending_submissions_count if pending_submissions_count is not None else 0
        except Exception as e:
            print("Database error:", e)
            return 0
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_project_kpi_setup_details(current_project_kpi_setup_detail_id, credit_points):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                UPDATE 
                    trn_project_kpi_setup_details
                SET 
                    credit_points = ?,
                    creation_date = GETDATE()
                WHERE 
                    id = ?;
            """
            cursor.execute(query, (credit_points, current_project_kpi_setup_detail_id,))
            conn.commit()

            return current_project_kpi_setup_detail_id
        except Exception as e:
            print(f"Error updating batch submission status: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_project_kpi_setup(project_id, current_project_kpi_setup_detail_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                UPDATE 
                    trn_project_kpi_setup
                SET 
                    project_id = ?                    
                WHERE 
                    id = ?;
            """
            cursor.execute(query, (project_id, current_project_kpi_setup_detail_id,))
            conn.commit()

            return current_project_kpi_setup_detail_id
        except Exception as e:
            print(f"Error updating batch submission status: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_project_kpi_request_approval_status(kpi_request_setup_id, action, workflow_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            if action == "reject":
                query = """
                    UPDATE trn_project_kpi_setup
                    SET status = 0
                    WHERE id = ?;
                """
                cursor.execute(query, (kpi_request_setup_id,))

            else:
                query = """                    
                    UPDATE trn_project_kpi_setup
                    SET 
                        status = status + 1
                    WHERE id = ?;
                """
                cursor.execute(query, (kpi_request_setup_id,))

            conn.commit()
            return True
        except Exception as e:
            print(f"Error updating approval status of trn_project_kpi_setup record: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_project_kpi_setup_status(focused_project_kpi_id):
        conn = get_db_connection()

        if conn is None:
            return False

        cursor = conn.cursor()

        try:
            query = """
                UPDATE trn_project_kpi_setup
                SET status = 1
                WHERE id = ?;
            """

            cursor.execute(query, (focused_project_kpi_id,))
            conn.commit()

            return cursor.rowcount > 0

        except Exception as e:
            print(f"Error updating status in trn_project_kpi_setup: {e}")
            return False

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def has_ongoing_project_kpi_setup(user_id):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM trn_project_kpi_setup WHERE status = 0 AND created_by = ?"
            cursor.execute(query, (user_id,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check for existing ongoing project kpi setup: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def has_ongoing_project_kpi_setup_detail(project_kpi_setup_id, key_process_id):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = ("SELECT COUNT(*) FROM trn_project_kpi_setup_details WHERE project_kpi_setup_id = ? "
                     "AND key_process_id = ?")
            cursor.execute(query, (project_kpi_setup_id, key_process_id,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check for existing ongoing project kpi setup: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_project_kpi_setup(
            project_id,
            user_id):

        conn = get_db_connection()

        if conn is None:
            return False

        cursor = conn.cursor()

        try:

            query = """
                INSERT INTO trn_project_kpi_setup
                (
                    project_id,
                    created_by,
                    creation_date
                )
                VALUES
                (
                    ?, ?, GETDATE()
                )
            """

            cursor.execute(
                query,
                (
                    project_id,
                    user_id
                )
            )

            conn.commit()

            return True

        except Exception as e:
            print(f"Database error: {e}")
            return False

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_project_kpi_request_approval_status_following_a_rejected_approval(kpi_request_setup_id):

        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            query = """
                UPDATE 
                    trn_project_kpi_setup
                SET 
                    status = 0
                WHERE 
                    id = ?
            """
            file_upload_id = cursor.execute(query, kpi_request_setup_id)
            conn.commit()
            return kpi_request_setup_id
        except Exception as e:
            print(f"Error updating status of trn_project_kpi_setup following a rejected request: {e}")

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_project_kpi_setup_details(
            project_kpi_setup_id,
            key_process_id,
            credit_points):

        conn = get_db_connection()

        if conn is None:
            return False

        cursor = conn.cursor()

        try:

            query = """
                INSERT INTO trn_project_kpi_setup_details
                (
                    project_kpi_setup_id,
                    key_process_id,
                    credit_points,
                    creation_date
                )
                VALUES
                (
                    ?, ?, ?, GETDATE()
                )
            """

            cursor.execute(
                query,
                (
                    project_kpi_setup_id,
                    key_process_id,
                    credit_points
                )
            )

            conn.commit()

            return True

        except Exception as e:
            print(f"Database error: {e}")
            return False

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_into_trn_project_kpi_setup_approvals(
            focused_project_kpi_id,
            decision,
            user_id,
            level,
            comment):

        conn = get_db_connection()

        if conn is None:
            return False

        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                INSERT INTO trn_project_kpi_setup_approvals
                    (project_kpi_setup_id, decision, approver_id, level, comment, date_time)
                VALUES
                    (?, ?, ?, ?, ?, ?)
                """,
                (
                    focused_project_kpi_id,
                    decision,
                    user_id,
                    level,
                    comment,
                    datetime.now()
                )
            )

            conn.commit()
            return True

        except pyodbc.Error as e:
            print(f"Database insert error: {e}")
            conn.rollback()
            return False

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_kpi_detail(kpi_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                DELETE 
                FROM 
                    trn_project_kpi_setup_details                
                WHERE id = ?
            """
            cursor.execute(query, kpi_id)
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to delete from trn_project_kpi_setup_details: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class EmailHelper(UserMixin):
    def __init__(self):
        self.id = id

    @staticmethod
    def send_submitted_activity_request_email(current_fname, next_approver_email, next_approver_fname, details):
        subject = "Activity Request Submitted for Approval"

        # Email body with Poppins font and inline styles
        body = f"""
        <html>
        <head>
            <link href="https:get_reconciliations_pending_approval_report/fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Poppins', sans-serif; margin: 20px; color: #333;">
            <p style="font-size: 14px;">Dear {next_approver_fname},</p>
            <p style="font-size: 14px;">{current_fname} has submitted the following activity request for your approval.</p>

            <p style="font-size: 14px; font-weight: bold; margin-top: 25px;">Activity Request:</p>

            <table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center; padding: 8px;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Project Code</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Project Name</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Subject</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, detail in enumerate(details, start=1):
            body += f"""
                    <tr>
                        <td style="border: 1px solid #ddd; text-align: center; padding: 8px;">{index}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.get('project_code')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.get('project_name')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.get('subject')}</td>
                    </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 25px; margin-bottom: 25px;">
                🔗 <a href="http://127.0.0.1:5000/approve-activity-requests" 
                style="color: #4270a8; text-decoration: none; font-weight: 600;">Click here to review and approve</a>
            </p>

            <p style="font-size: 14px;">Your timely action is appreciated.</p>

            <p style="font-size: 14px;">
                <strong>Best Regards,</strong><br>
                Land Acquisition Activity Tracker<br>              
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
        subject = "Activity Request Approval"

        # Email body with Poppins font and inline styles
        body = f"""
        <html>
        <head>
            <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Poppins', sans-serif; margin: 20px; color: #333;">
            <p style="font-size: 14px;">Dear {next_approver_fname},</p>
            <p style="font-size: 14px;">Please be notified that the following activity requests have been forwarded to you for approval:</p>

            <table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center; padding: 8px;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Project Code</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Project Name</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Subject</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, file in enumerate(files, start=1):
            body += f"""
                    <tr>
                        <td style="border: 1px solid #ddd; text-align: center; padding: 8px;">{index}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('project_code')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('project_name')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('subject')}</td>
                    </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 25px; margin-bottom: 25px;">
                🔗 <a href="https://brt.uetcl.com/approve-reconciliations" 
                style="color: #4270a8; text-decoration: none; font-weight: 600;">Click here to review and approve</a>
            </p>

            <p style="font-size: 14px;">Your timely action is appreciated.</p>

            <p style="font-size: 14px;">
                <strong>Best Regards,</strong><br>
                Land Acquisition Activity Tracker<br>                
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
        subject = "Activity Request(s) " + action_for_email_subject

        # Email body with Poppins font and inline styles
        body = f"""
        <html>
        <head>
            <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Poppins', sans-serif; margin: 20px; color: #333;">
            <p style="font-size: 14px;">Dear {initiator_approver_fname},</p>
            <p style="font-size: 14px;">The following activity requests(s) that you submitted have been {action} by {current_fname}.</p>

            <table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center; padding: 8px;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Project Code</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Project Name</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Subject</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, file in enumerate(files, start=1):
            body += f"""
                    <tr>
                        <td style="border: 1px solid #ddd; text-align: center; padding: 8px;">{index}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('project_code', '')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('project_name', '')}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{file.get('subject', '')}</td>
                    </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 25px; margin-bottom: 25px;">
                🔗 <a href="https://brt.uetcl.com/submitted-reconciliations" 
                style="color: #4270a8; text-decoration: none; font-weight: 600;">Click here to view the approved reconciliations</a>
            </p>

            <p style="font-size: 14px;">
                <strong>Best Regards,</strong><br>
                Land Acquisition Activity Tracker<br>                
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
    def email_reminder_to_initiator_activity_requests_pending_submission(current_fname, initiator_approver_email,
                                                                       details):
        subject = "Activity Requests Pending Submission"

        # Start building HTML body with inline styles only
        body = f"""
        <html>
        <body style="margin: 0; padding: 20px; font-family: Arial, sans-serif; font-size: 14px; color: #333;">
            <p>Dear {current_fname},</p>
            <p>The following activity requests are pending your submission:</p>

            <table border="1" cellpadding="6" cellspacing="0" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left;">Project Code</th>
                        <th style="border: 1px solid #ddd; text-align: left;">Project Name</th>
                        <th style="border: 1px solid #ddd; text-align: left;">Subject</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, detail in enumerate(details, start=1):
            body += f"""
                <tr>
                    <td style="border: 1px solid #ddd; text-align: center;">{index}</td>
                    <td style="border: 1px solid #ddd;">{detail.project_code}</td>
                    <td style="border: 1px solid #ddd;">{detail.project_name}</td>
                    <td style="border: 1px solid #ddd;">{detail.subject}</td>
                </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 20px;">
                🔗 <a href="https://brt.uetcl.com/submit-reconciliations" 
                style="color: #1a73e8; text-decoration: none;">Click here to submit</a>
            </p>

            <p>Your timely action is appreciated.</p>

            <p>
                <strong>Best Regards,</strong><br>
                Land Acquisition Activity Tracker<br>
            </p>
        </body>
        </html>
        """

        try:
            msg = Message(subject, recipients=[initiator_approver_email])
            msg.html = body
            mail.send(msg)
            print(f"Email reminder sent to Initiator: {initiator_approver_email}")
        except Exception as e:
            print(f"Error sending email: {e}")

    @staticmethod
    def email_reminder_to_approve_submitted_activity_requests(approver_fname, approver_email, details):
        subject = "Activity Request(s) Pending Approval"

        # Email body with Poppins font and inline styles
        body = f"""
        <html>
        <head>
            <link href="https:get_reconciliations_pending_submission/fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Poppins', sans-serif; margin: 20px; color: #333;">
            <p style="font-size: 14px;">Dear {approver_fname},</p>
            <p style="font-size: 14px;">The following activity request(s) are pending your approval.</p>

            <p style="font-size: 14px; font-weight: bold; margin-top: 25px;">Activity Request(s) Pending Approval:</p>

            <table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center; padding: 8px;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Requester</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Project Code</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Project Name</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Subject</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Approve As</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, detail in enumerate(details, start=1):
            body += f"""
                    <tr>
                        <td style="border: 1px solid #ddd; text-align: center; padding: 8px;">{index}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.name}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.project_code}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.project_name}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.subject}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.approve_as}</td>
                    </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 25px; margin-bottom: 25px;">
                🔗 <a href="https://brt.uetcl.com/approve-reconciliations" 
                style="color: #4270a8; text-decoration: none; font-weight: 600;">Click here to review and approve activity request(s)</a>
            </p>

            <p style="font-size: 14px;">Your timely action is appreciated.</p>

            <p style="font-size: 14px;">
                <strong>Best Regards,</strong><br>
                Land Acquisition Activity Tracker<br>                
            </p>
        </body>
        </html>
        """

        try:
            msg = Message(subject, recipients=[approver_email])
            msg.html = body  # Set HTML content
            mail.send(msg)
            print(f"Email reminder about Pending Activity Requests(s) Approval sent to Approver, {approver_email}")
        except Exception as e:
            print(f"Error sending email: {e}")

    @staticmethod
    def email_reminder_to_approve_submitted_completed_wip_activity_requests(approver_fname, approver_email, details):
        subject = "Completed WIP Activity Request(s) Pending Approval"

        # Email body with Poppins font and inline styles
        body = f"""
        <html>
        <head>
            <link href="https:get_reconciliations_pending_submission/fonts.googleapis.com/css2?family=Poppins:wght@300;400;600&display=swap" rel="stylesheet">
        </head>
        <body style="font-family: 'Poppins', sans-serif; margin: 20px; color: #333;">
            <p style="font-size: 14px;">Dear {approver_fname},</p>
            <p style="font-size: 14px;">The following completed wip activity request(s) are pending your approval.</p>

            <p style="font-size: 14px; font-weight: bold; margin-top: 25px;">Completed WIP Activity Request(s) Pending Approval:</p>

            <table border="1" cellspacing="0" cellpadding="8" style="border-collapse: collapse; width: 100%; font-size: 14px;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th style="border: 1px solid #ddd; text-align: center; padding: 8px;">#</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Requester</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Project Code</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Project Name</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Subject</th>
                        <th style="border: 1px solid #ddd; text-align: left; padding: 8px;">Approve As</th>
                    </tr>
                </thead>
                <tbody>
        """

        for index, detail in enumerate(details, start=1):
            body += f"""
                    <tr>
                        <td style="border: 1px solid #ddd; text-align: center; padding: 8px;">{index}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.name}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.project_code}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.project_name}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.subject}</td>
                        <td style="border: 1px solid #ddd; padding: 8px;">{detail.approve_as}</td>
                    </tr>
            """

        body += """
                </tbody>
            </table>

            <p style="margin-top: 25px; margin-bottom: 25px;">
                🔗 <a href="https://brt.uetcl.com/approve-reconciliations" 
                style="color: #4270a8; text-decoration: none; font-weight: 600;">Click here to review and approve completed WIP activity request(s)</a>
            </p>

            <p style="font-size: 14px;">Your timely action is appreciated.</p>

            <p style="font-size: 14px;">
                <strong>Best Regards,</strong><br>
                Land Acquisition Activity Tracker<br>                
            </p>
        </body>
        </html>
        """

        try:
            msg = Message(subject, recipients=[approver_email])
            msg.html = body  # Set HTML content
            mail.send(msg)
            print(f"Email reminder about Pending Activity Requests(s) Approval sent to Approver, {approver_email}")
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
                        SELECT 
                            b.name AS bank_account_id, 
                            a.[year], 
                            DATENAME(month, DATEADD(month, a.[month], 0) - 1) AS [month], 
                            a.file_name, 
                            a.batch_id,
                            CASE 
                                WHEN ra.decision = 3 THEN 'Rejected'
                                ELSE 'Pending Submission'
                            END AS submission_status 
                        FROM file_upload a 
                        LEFT OUTER JOIN bank_account b ON a.bank_account_id = b.id
                        LEFT OUTER JOIN file_upload_batch c ON c.id = a.batch_id
                        LEFT OUTER JOIN users d ON d.id = c.user_id
                        LEFT OUTER JOIN (
                            SELECT ra1.file_upload_id, ra1.decision
                            FROM trn_activity_request_approvals ra1
                            WHERE ra1.date_time = (
                                SELECT MAX(ra2.date_time)
                                FROM trn_activity_request_approvals ra2
                                WHERE ra2.file_upload_id = ra1.file_upload_id
                            )
                        ) ra ON ra.file_upload_id = a.id
                        WHERE c.user_id = ? 
                          AND a.submission_status = 0 
                          AND a.removed_by_user_on_upload_page = 0
                        ORDER BY b.name;
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
                            FROM trn_activity_request_approvals ra
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
                        DECLARE @workflow_id INT = 1;-- workflow_id from workflow table
                        DECLARE @is_workflow_level INT = 1;
                        
                        SELECT c.NAME AS bank_account
                            ,b.year
                            ,(
                                SELECT DateName(month, DateAdd(month, b.month, 0) - 1)
                                ) AS month
                            ,b.file_name
                            ,FORMAT(b.creation_datetime, 'yyyy-MM-dd HH:mm:ss') AS date_time
                            ,(
                                SELECT r.NAME
                                FROM ROLE r
                                LEFT JOIN role_workflow_breakdown rwb ON r.id = rwb.role_id
                                LEFT JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                WHERE wb.workflow_id = @workflow_id
                                    AND wb.is_workflow_level = @is_workflow_level
                                    AND wb.LEVEL = b.submission_status + 1
                                ) AS next_approver
                        FROM file_upload_batch a
                        LEFT JOIN file_upload b ON a.id = b.batch_id
                        LEFT JOIN bank_account c ON b.bank_account_id = c.id
                        WHERE b.submission_status != 0
                            AND b.submission_status < (
                                SELECT COALESCE(MAX(LEVEL), 0)
                                FROM workflow wf
                                LEFT JOIN workflow_breakdown wb ON wf.id = wb.workflow_id
                                WHERE wf.id = @workflow_id
                                )
                            AND b.removed_by_user_on_upload_page = 0
                        ORDER BY c.NAME
                            ,b.year
                            ,b.month ASC;

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
            # Fetch rejected reconciliations
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
                        FROM trn_activity_request_approvals ra
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
                FileUpload(id=row.id, bank_account=row.bank_account, year=row.year, month=row.month,
                           file_name=row.file_name,
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
                        'Unknown' END + ' ' + r.name FROM trn_activity_request_approvals ra LEFT JOIN workflow_breakdown wb 
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
    def get_reconciliations_pending_submission_by_user(user_id):
        conn = get_db_connection()
        if conn is None:
            return 0  # Return 0 if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT COUNT(*) AS TotalReconciliationsPendingSubmission FROM file_upload fu
                        LEFT OUTER JOIN file_upload_batch fub ON fu.batch_id = fub.id
                        WHERE fu.submission_status = 0 AND fub.user_id = ?
            """
            cursor.execute(query, [user_id])
            pending_submissions_count = cursor.fetchone()[0]
            return pending_submissions_count if pending_submissions_count is not None else 0
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
                    AND ur.start_datetime <= GETDATE() 
                    AND ur.expiry_datetime >= GETDATE()
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
                    AND ur.start_datetime <= GETDATE() 
                    AND ur.expiry_datetime >= GETDATE()
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
    def __init__(self, id=None, name=None, bank_id=None, currency_id=None, strategic_business_unit_id=None,
                 account=None, bank=None, currency=None, unit=None, creation_date=None, bank_account_name=None,
                 bank_name=None, currency_name=None, org_unit_name=None):
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
            query = """
                        SELECT ba.id, ba.name, ba.bank_id, ba.currency_id, ba.strategic_business_unit_id 
                        FROM bank_account ba 
                        LEFT OUTER JOIN bank_account_responsible_user baru ON ba.id = baru.bank_account_id 
                        LEFT OUTER JOIN users u ON baru.user_id = u.ID 
                        WHERE baru.is_active = 1 AND u.ID = ?
                        ORDER BY ba.name
                    """
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


class TeamMemberRole:
    def __init__(self, id=None, name=None, bank_id=None, currency_id=None, strategic_business_unit_id=None,
                 account=None, bank=None, currency=None, unit=None, creation_date=None, bank_account_name=None,
                 bank_name=None, currency_name=None, org_unit_name=None):
        self.id = id
        self.name = name

    @staticmethod
    def get_all_team_member_roles():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT id, name FROM team_member_role ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            team_member_roles = [
                Role(id=row.id, name=row.name)
                for row in result
            ]
            return team_member_roles
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_team_member_role_details(team_member_role_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                SELECT id, name FROM team_member_role WHERE name = ?
            """
            cursor.execute(query, (team_member_role_name,))
            result = cursor.fetchall()

            team_member_role_details = [
                BankAccount(id=row.id, name=row.name)
                for row in result
            ]
            return team_member_role_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def team_member_role_name_exists(team_member_role_name):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM team_member_role WHERE name = ?"
            cursor.execute(query, (team_member_role_name,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check username existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_team_member_role(team_member_role_id, team_member_role_name_2):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE team_member_role SET name = ? WHERE id = ?
            """
            cursor.execute(query, (team_member_role_name_2, team_member_role_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update bank: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_team_member_role(name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                INSERT INTO team_member_role (name)
                VALUES (?)
            """
            cursor.execute(query, (name,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new team_member_role: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class KeyProcess:
    def __init__(self, id=None, name=None, bank_id=None, currency_id=None, strategic_business_unit_id=None,
                 account=None, bank=None, currency=None, unit=None, creation_date=None, bank_account_name=None,
                 bank_name=None, currency_name=None, org_unit_name=None):
        self.id = id
        self.name = name

    @staticmethod
    def get_all_key_processes():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT id, name FROM mst_key_process ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            key_process = [
                Role(id=row.id, name=row.name)
                for row in result
            ]
            return key_process
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_key_process_details(key_process_name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                SELECT id, name FROM mst_key_process WHERE name = ?
            """
            cursor.execute(query, (key_process_name,))
            result = cursor.fetchall()

            team_member_role_details = [
                BankAccount(id=row.id, name=row.name)
                for row in result
            ]
            return team_member_role_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def key_process_name_exists(key_process_name):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM mst_key_process WHERE name = ?"
            cursor.execute(query, (key_process_name,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check key process existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_key_process(team_member_role_id, team_member_role_name_2):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                UPDATE mst_key_process SET name = ? WHERE id = ?
            """
            cursor.execute(query, (team_member_role_name_2, team_member_role_id, ))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update bank: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_key_process(name):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                INSERT INTO mst_key_process (name)
                VALUES (?)
            """
            cursor.execute(query, (name,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to insert a new key process: ", e)
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
            cursor.execute(query, (role_name, role_id,))
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
            cursor.execute(query, (workflow_name, workflow_id,))
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
            cursor.execute(query, (role_id, workflow_breakdown_id, role_workflow_breakdown_id,))
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
    def get_workflow_breakdown_for_reconciliation_approval(workflow_id, is_workflow_level):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Get workflow breakdown
            query = """
                        SELECT wb.id, wb.workflow_id, wb.level, wb.name, 
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
                                   item_menu_id, is_workflow_level,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check workflow name existence: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_new_workflow_breakdown(workflowBreakdownName, workflow_id, level_id, item_menu_id,
                                      is_responsibility_global, is_workflow_level):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                INSERT INTO workflow_breakdown (workflow_id, level, name, is_responsibility_global, menu_item_id, is_workflow_level)
                VALUES (?, ?, ?, ?, ?, ?)
            """
            cursor.execute(query, (
            workflow_id, level_id, workflowBreakdownName, is_responsibility_global, item_menu_id, is_workflow_level))
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
            cursor.execute(query, (workflow_name, workflow_id,))
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
    def __init__(self, id=None, user_id=None, user_name=None, username=None, role_id=None, role_name=None,
                 project_id=None, project_code=None, project_name=None, start_datetime=None, expiry_datetime=None):
        self.id = id
        self.user_id = user_id
        self.username = username
        self.user_name = user_name
        self.role_id = role_id
        self.role_name = role_name
        self.project_id = project_id
        self.project_code = project_code
        self.project_name = project_name
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
                UserRole(id=row.id, user_id=row.user_id, username=row.username, user_name=row.user_name,
                         role_id=row.role_id, role_name=row.role_name, start_datetime=row.start_datetime,
                         expiry_datetime=row.expiry_datetime)
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
    def user_tagged_project_exists(user_id, project_id):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM user_tagged_project WHERE user_id = ? AND project_id = ?"
            cursor.execute(query, (user_id, project_id,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to check user-tagged-project existence: ", e)
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
    def get_all_user_tagged_project_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:

            query = """
                        SELECT
                            utp.id,
                            utp.user_id,
                            u.username,
                            LTRIM(RTRIM(
                                CONCAT(
                                    ISNULL(u.Fname, ''),
                                    ' ',
                                    ISNULL(u.Mname, ''),
                                    ' ',
                                    ISNULL(u.Sname, '')
                                )
                            )) AS user_name,
                            mp.id AS project_id,
                            mp.project_code,
                            mp.project_name,
                            CAST(utp.start_datetime AS DATE) AS start_datetime,
                            CAST(utp.expiry_datetime AS DATE) AS expiry_datetime
                        FROM user_tagged_project utp
                        LEFT JOIN users u
                            ON utp.user_id = u.ID
                        LEFT JOIN mst_project mp
                            ON utp.project_id = mp.id
                        ORDER BY
                            u.Fname,
                            u.Mname,
                            u.Sname;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            user_role_details = [
                UserRole(id=row.id, user_id=row.user_id, username=row.username, user_name=row.user_name,
                         project_id=row.project_id, project_code=row.project_code, project_name=row.project_name,
                         start_datetime=row.start_datetime, expiry_datetime=row.expiry_datetime)
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
            cursor.execute("SELECT COALESCE(MAX(id), 0) FROM trn_activity_request_approvals")
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
            cursor.execute("SELECT TOP 1 COALESCE(level, 0) FROM trn_activity_request_approvals WHERE file_upload_id = ? "
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
                        FROM trn_activity_request_approvals ra
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
                        ORDER BY at.timestamp DESC;
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
            cursor.execute(query, (currency_name, currency_code, currency_id,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update user: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class BankAccountResponsibleUser:
    def __init__(self, id=None, bank_account_id=None, user_id=None, bank_account_name=None, username=None, name=None,
                 is_active=None, status=None):
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
                BankAccountResponsibleUser(id=row.id, bank_account_name=row.bank_account_name, username=row.username,
                                           name=row.name, status=row.status)
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
                SELECT baru.id, ba.id AS bank_account_id, 
                u.ID AS user_id, baru.is_active
                FROM bank_account_responsible_user baru
                LEFT OUTER JOIN bank_account ba ON baru.bank_account_id = ba.id
                LEFT OUTER JOIN users u ON baru.user_id = u.ID
                WHERE ba.name is not null AND ba.name = ? AND u.Username = ?
            """
            cursor.execute(query, (bank_account_name, username,))
            result = cursor.fetchall()

            responsibilities = [
                BankAccountResponsibleUser(id=row.id, bank_account_id=row.bank_account_id, user_id=row.user_id,
                                           is_active=row.is_active)
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
                UPDATE bank_account_responsible_user SET is_active = ? WHERE id = ?
            """
            cursor.execute(query, (is_active, responsibility_id,))
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
            cursor.execute(query, (org_unit_tier_name, parent_org_unit_tier_id, org_unit_tier_id,))
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
    def __init__(self, id=None, name=None, parent_org_unit_id=None, parent_org_unit_name=None, org_unit_tier_name=None,
                 org_unit_tier_id=None):
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
            cursor.execute(query, (org_unit_name, org_unit_tier_id, parent_unit_id,))
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
            cursor.execute(query, (org_unit_name, org_unit_tier_id, parent_unit_id, org_unit_id,))
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
            cursor.execute(query, (menu_item_name, edit_menu_item_id,))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update menu item: ", e)
            return False
        finally:
            cursor.close()
            conn.close()


class Project:
    def __init__(self, id=None, project_code=None, project_name=None, project_objective=None, project_start_date=None,
                 project_end_date=None, project_status=None):
        self.id = id
        self.project_code = project_code
        self.project_name = project_name
        self.project_objective = project_objective
        self.project_start_date = project_start_date
        self.project_end_date = project_end_date
        self.project_status = project_status

    @staticmethod
    def get_all_projects():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                SELECT id, project_code, project_name FROM mst_project ORDER BY project_name
            """
            cursor.execute(query, )
            result = cursor.fetchall()

            projects = [
                Project(id=row.id, project_code=row.project_code, project_name=row.project_name, )
                for row in result
            ]
            return projects
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_projects_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT * FROM mst_project ORDER BY project_name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            project_details = [
                Project(id=row.id, project_code=row.project_code, project_name=row.project_name,
                        project_objective=row.project_objective, project_start_date=row.project_start_date,
                        project_end_date=row.project_end_date, project_status=row.project_status)
                for row in result
            ]
            return project_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()


class ActivityRequest:
    def __init__(self, id=None, name=None, user_id=None, creation_date=None, last_modified=None, status=None,
                 subject=None, objectives=None, scope=None, stakeholders=None, deliverables=None, assumptions=None,
                 current_request_id=None, activity_id=None, member_id=None, role_id=None, team_member_no=None,
                 task_no=None, task=None, key_process_id=None, start_date=None, end_date=None, project_code=None,
                 project_name=None, max_end_date=None, approve_as=None, credit_points_balance=None):
        self.id = id
        self.name = name
        self.user_id = user_id
        self.creation_date = creation_date
        self.last_modified = last_modified
        self.status = status
        self.subject = subject
        self.objectives = objectives
        self.scope = scope
        self.stakeholders = stakeholders
        self.deliverables = deliverables
        self.assumptions = assumptions
        self.current_request_id = current_request_id
        self.activity_id = activity_id
        self.member_id = member_id
        self.role_id = role_id
        self.team_member_no = team_member_no
        self.task_no = task_no
        self.task = task
        self.key_process_id = key_process_id
        self.start_date = start_date
        self.end_date = end_date
        self.project_code = project_code
        self.project_name = project_name
        self.max_end_date = max_end_date
        self.approve_as = approve_as
        self.credit_points_balance = credit_points_balance

    @staticmethod
    def get_activity_requests_pending_approval(user_id):
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
                                LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name,
                                pro.project_code, 
                                pro.project_name, 
                                taro.subject,  
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tar.id ORDER BY tar.creation_date DESC) AS row_num
                            FROM trn_activity_request tar
                            JOIN trn_activity_request_approvals tara ON tar.id = tara.activity_request_id
                            JOIN mst_project pro ON tar.project_id = pro.id
                            JOIN trn_activity_overview taro ON tar.id = taro.activity_id
                            JOIN users u ON tar.user_id = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                                    WHERE b.parent_org_unit_tier_id IN (
                                        SELECT d.organisation_unit_tier_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tar.status != 0 
                                AND tar.status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 1
                                        AND e.ID = @logged_in_user_id
                                )
                        ),
                        OrgBasedFiles AS (
                            -- Get files where responsibility is restricted to specific organizational units
                            SELECT 
                                LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name,
                                pro.project_code, 
                                pro.project_name, 
                                taro.subject,  
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tar.id ORDER BY tar.creation_date DESC) AS row_num
                            FROM trn_activity_request tar
                            JOIN trn_activity_request_approvals tara ON tar.id = tara.activity_request_id
                            JOIN mst_project pro ON tar.project_id = pro.id
                            JOIN trn_activity_overview taro ON tar.id = taro.activity_id
                            JOIN users u ON tar.user_id = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit b ON a.organisation_unit_id = b.id
                                    WHERE b.parent_org_unit_id IN (
                                        SELECT d.organisation_unit_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tar.status != 0 
                                AND tar.status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 0
                                        AND e.ID = @logged_in_user_id
                                )
                        )
                        -- name, project_code, project_name, subject
                        SELECT 
                            name, project_code, project_name, subject, approve_as
                        FROM (
                            SELECT * FROM GlobalFiles WHERE row_num = 1
                            UNION
                            SELECT * FROM OrgBasedFiles WHERE row_num = 1
                        ) AS UniqueResults
                        WHERE approve_as IS NOT NULL
                        ORDER BY project_code ASC;
            """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            pending_activity_requests = [
                ActivityRequest(name=row.name, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, approve_as=row.approve_as)
                for row in result
            ]

            return pending_activity_requests
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_fully_approved_activity_request_details(is_workflow_level, workflow_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()

        try:
            query = """
                        SELECT 
                            a.id,                        
                            LTRIM(RTRIM(CONCAT(d.Fname, ' ', d.Mname, ' ', d.Sname))) AS name,                        
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,
                        
                            (
                                SELECT TOP 1 
                                    CASE 
                                        WHEN ra.decision = 1 THEN 'Submitted by'
                                        WHEN ra.decision = 2 THEN 'Approved by'
                                        WHEN ra.decision = 3 THEN 'Rejected by'
                                        ELSE 'Unknown'
                                    END + ' ' + r.name
                                FROM trn_activity_request_approvals ra
                                LEFT JOIN workflow_breakdown wb 
                                    ON ra.level = wb.level 
                                LEFT JOIN role_workflow_breakdown rwb 
                                    ON wb.id = rwb.workflow_breakdown_id 
                                LEFT JOIN role r 
                                    ON rwb.role_id = r.id 
                                WHERE 
                                    ra.activity_request_id = a.id 
                                    AND wb.workflow_id = ?
                                    AND wb.is_workflow_level = ?
                                ORDER BY ra.id DESC
                            ) AS status
                        
                        FROM trn_activity_request a
                        
                        LEFT JOIN trn_activity_overview b 
                            ON a.id = b.activity_id
                        
                        LEFT JOIN mst_project c 
                            ON a.project_id = c.id
                        
                        LEFT JOIN users d
                            ON a.user_id = d.ID    
                        
                        WHERE 
                            a.status != 0 
                            AND a.status = (
                                SELECT COALESCE(MAX(wb.level), 0)
                                FROM workflow_breakdown wb
                                WHERE wb.workflow_id = ?
                            ) + 1;
            """

            cursor.execute(query, (workflow_id, is_workflow_level, workflow_id))
            rows = cursor.fetchall()

            # Map correctly
            results = []
            for row in rows:
                results.append({
                    "id": row.id,
                    "name": row.name,
                    "project_code": row.project_code,
                    "project_name": row.project_name,
                    "subject": row.subject,
                    "last_modified": row.last_modified,
                    "status": row.status
                })

            return results

        except Exception as e:
            print("Database error:", e)
            return []

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_fully_approved_completed_wip_activity_request_details(is_workflow_level, workflow_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()

        try:
            query = """
                        SELECT 
                            a.id,                        
                            LTRIM(RTRIM(CONCAT(d.Fname, ' ', d.Mname, ' ', d.Sname))) AS name,                        
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,

                            (
                                SELECT TOP 1 
                                    CASE 
                                        WHEN ra.decision = 1 THEN 'Submitted by'
                                        WHEN ra.decision = 2 THEN 'Approved by'
                                        WHEN ra.decision = 3 THEN 'Rejected by'
                                        ELSE 'Unknown'
                                    END + ' ' + r.name
                                FROM trn_completed_wip_activity_request_approvals ra
                                LEFT JOIN workflow_breakdown wb 
                                    ON ra.level = wb.level 
                                LEFT JOIN role_workflow_breakdown rwb 
                                    ON wb.id = rwb.workflow_breakdown_id 
                                LEFT JOIN role r 
                                    ON rwb.role_id = r.id 
                                WHERE 
                                    ra.activity_request_id = a.id 
                                    AND wb.workflow_id = ?
                                    AND wb.is_workflow_level = ?
                                ORDER BY ra.id DESC
                            ) AS status

                        FROM trn_activity_request a

                        LEFT JOIN trn_activity_overview b 
                            ON a.id = b.activity_id

                        LEFT JOIN mst_project c 
                            ON a.project_id = c.id

                        LEFT JOIN users d
                            ON a.user_id = d.ID    

                        WHERE 
                            a.wip_status != 0 
                            AND a.wip_status = (
                                SELECT COALESCE(MAX(wb.level), 0)
                                FROM workflow_breakdown wb
                                WHERE wb.workflow_id = ?
                            ) + 1;
            """

            cursor.execute(query, (workflow_id, is_workflow_level, workflow_id))
            rows = cursor.fetchall()

            # Map correctly
            results = []
            for row in rows:
                results.append({
                    "id": row.id,
                    "name": row.name,
                    "project_code": row.project_code,
                    "project_name": row.project_name,
                    "subject": row.subject,
                    "last_modified": row.last_modified,
                    "status": row.status
                })

            return results

        except Exception as e:
            print("Database error:", e)
            return []

        finally:
            cursor.close()
            conn.close()

    def get_activity_requests_pending_approval_details(workflow_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()

        try:
            query = """
                        SELECT 
                            a.id,                        
                        
                            LTRIM(RTRIM(
                                CONCAT(d.Fname, ' ', d.Mname, ' ', d.Sname)
                            )) AS name,                        
                        
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,
                        
                            (
                                SELECT TOP 1 r.name
                                FROM trn_activity_request_approvals ra
                                LEFT JOIN workflow_breakdown wb 
                                    ON ra.level + 1 = wb.level
                                LEFT JOIN role_workflow_breakdown rwb 
                                    ON wb.id = rwb.workflow_breakdown_id
                                LEFT JOIN role r 
                                    ON rwb.role_id = r.id
                                WHERE 
                                    ra.activity_request_id = a.id
                                ORDER BY ra.date_time DESC
                            ) AS status
                        
                        FROM trn_activity_request a
                        
                        LEFT JOIN trn_activity_overview b 
                            ON a.id = b.activity_id
                        
                        LEFT JOIN mst_project c 
                            ON a.project_id = c.id
                        
                        LEFT JOIN users d
                            ON a.user_id = d.ID    
                        
                        WHERE 
                            a.status != 0 
                            AND a.status < (
                                SELECT COALESCE(MAX(wb.level), 0)
                                FROM workflow_breakdown wb
                                WHERE wb.workflow_id = ?
                            ) + 1;
            """

            cursor.execute(query, (workflow_id, ))
            rows = cursor.fetchall()

            # Map correctly
            results = []
            for row in rows:
                results.append({
                    "id": row.id,
                    "name": row.name,
                    "project_code": row.project_code,
                    "project_name": row.project_name,
                    "subject": row.subject,
                    "last_modified": row.last_modified,
                    "status": row.status
                })

            return results

        except Exception as e:
            print("Database error:", e)
            return []

        finally:
            cursor.close()
            conn.close()

    def get_completed_wip_activity_requests_pending_approval_details(workflow_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()

        try:
            query = """
                        SELECT 
                            a.id,                        

                            LTRIM(RTRIM(
                                CONCAT(d.Fname, ' ', d.Mname, ' ', d.Sname)
                            )) AS name,                        

                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,

                            (
                                SELECT TOP 1 r.name
                                FROM trn_completed_wip_activity_request_approvals ra
                                LEFT JOIN workflow_breakdown wb 
                                    ON ra.level + 1 = wb.level
                                LEFT JOIN role_workflow_breakdown rwb 
                                    ON wb.id = rwb.workflow_breakdown_id
                                LEFT JOIN role r 
                                    ON rwb.role_id = r.id
                                WHERE 
                                    ra.activity_request_id = a.id
                                ORDER BY ra.date_time DESC
                            ) AS status

                        FROM trn_activity_request a

                        LEFT JOIN trn_activity_overview b 
                            ON a.id = b.activity_id

                        LEFT JOIN mst_project c 
                            ON a.project_id = c.id

                        LEFT JOIN users d
                            ON a.user_id = d.ID    

                        WHERE 
                            a.wip_status != 0 
                            AND a.wip_status < (
                                SELECT COALESCE(MAX(wb.level), 0)
                                FROM workflow_breakdown wb
                                WHERE wb.workflow_id = ?
                            ) + 1;
            """

            cursor.execute(query, (workflow_id,))
            rows = cursor.fetchall()

            # Map correctly
            results = []
            for row in rows:
                results.append({
                    "id": row.id,
                    "name": row.name,
                    "project_code": row.project_code,
                    "project_name": row.project_name,
                    "subject": row.subject,
                    "last_modified": row.last_modified,
                    "status": row.status
                })

            return results

        except Exception as e:
            print("Database error:", e)
            return []

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_completed_wip_activity_requests_pending_approval(user_id):
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
                                LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name,
                                pro.project_code, 
                                pro.project_name, 
                                taro.subject,  
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.wip_status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tar.id ORDER BY tar.creation_date DESC) AS row_num
                            FROM trn_activity_request tar
                            JOIN trn_completed_wip_activity_request_approvals tcwara ON tar.id = tcwara.activity_request_id
                            JOIN mst_project pro ON tar.project_id = pro.id
                            JOIN trn_activity_overview taro ON tar.id = taro.activity_id
                            JOIN users u ON tar.user_id = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tcwara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                                    WHERE b.parent_org_unit_tier_id IN (
                                        SELECT d.organisation_unit_tier_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tar.wip_status > 1 
                                AND tar.wip_status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 1
                                        AND e.ID = @logged_in_user_id
                                )
                        ),
                        OrgBasedFiles AS (
                            -- Get files where responsibility is restricted to specific organizational units
                            SELECT 
                                LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name,
                                pro.project_code, 
                                pro.project_name, 
                                taro.subject,  
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.wip_status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tar.id ORDER BY tar.creation_date DESC) AS row_num
                            FROM trn_activity_request tar
                            JOIN trn_completed_wip_activity_request_approvals tcwara ON tar.id = tcwara.activity_request_id
                            JOIN mst_project pro ON tar.project_id = pro.id
                            JOIN trn_activity_overview taro ON tar.id = taro.activity_id
                            JOIN users u ON tar.user_id = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tcwara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit b ON a.organisation_unit_id = b.id
                                    WHERE b.parent_org_unit_id IN (
                                        SELECT d.organisation_unit_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tar.wip_status > 1
                                AND tar.wip_status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 0
                                        AND e.ID = @logged_in_user_id
                                )
                        )
                        -- name, project_code, project_name, subject
                        SELECT 
                            name, project_code, project_name, subject, approve_as
                        FROM (
                            SELECT * FROM GlobalFiles WHERE row_num = 1
                            UNION
                            SELECT * FROM OrgBasedFiles WHERE row_num = 1
                        ) AS UniqueResults
                        WHERE approve_as IS NOT NULL
                        ORDER BY project_code ASC;
            """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            pending_activity_requests = [
                ActivityRequest(name=row.name, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, approve_as=row.approve_as)
                for row in result
            ]

            return pending_activity_requests
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def initiators_pending_submission_of_activity_requests():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT DISTINCT(user_id) 
                        FROM trn_activity_request 
                        WHERE status = 1;
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
    def get_all_user_ids():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT ID FROM users ORDER BY ID;
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
    def pending_activity_requests_submission_details(user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        DECLARE @UserID INT = ?;

                        SELECT c.project_code, c.project_name, d.subject 
                        FROM trn_activity_request a
                        LEFT JOIN users b ON a.user_id = b.ID
                        LEFT JOIN mst_project c ON a.project_id = c.id
                        LEFT JOIN trn_activity_overview d ON a.id = d.activity_id
                        WHERE a.id = @UserID
                        AND status = 1;
                  """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            # Convert query result into list
            activity_requests = [
                ActivityRequest(
                    project_code=row.project_code,
                    project_name=row.project_name,
                    subject=row.subject
                )
                for row in result
            ]
            return activity_requests
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_latest_activity_request_id():
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT TOP 1 COALESCE(id, 0) FROM trn_activity_request ORDER BY id DESC;
            """)
            row = cursor.fetchone()
            return row[0] if row else 0
        except Exception as e:
            print("Database error:", e)
            return None
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_requests_pending_submission(status, user_id):
        conn = get_db_connection()
        if conn is None:
            return 0  # Return 0 if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT COUNT(*)
                        FROM trn_activity_request a
                        WHERE a.status = ? AND a.user_id = ?
            """
            cursor.execute(query, [status, user_id])
            pending_submissions_count = cursor.fetchone()[0]
            return pending_submissions_count if pending_submissions_count is not None else 0
        except Exception as e:
            print("Database error:", e)
            return 0
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_status_for_dashboard_pie_chart():
        conn = get_db_connection()
        if conn is None:
            return {
                "pending_approval": 0,
                "wip_in_progress": 0,
                "wip_completed": 0
            }

        cursor = conn.cursor()

        try:
            query = """
                SELECT
                    SUM(CASE WHEN wip_status = 0 AND status > 1 THEN 1 ELSE 0 END) AS pending_approval,
                    SUM(CASE WHEN wip_status <> 0 AND wip_approval_complete = 0 THEN 1 ELSE 0 END) AS wip_in_progress,
                    SUM(CASE WHEN wip_status <> 0 AND wip_approval_complete = 1 THEN 1 ELSE 0 END) AS wip_completed
                FROM trn_activity_request;
            """

            cursor.execute(query)
            row = cursor.fetchone()

            if row:
                return {
                    "pending_approval": row[0] or 0,
                    "wip_in_progress": row[1] or 0,
                    "wip_completed": row[2] or 0
                }

            return {
                "pending_approval": 0,
                "wip_in_progress": 0,
                "wip_completed": 0
            }

        except Exception as e:
            print("Database error:", e)
            return {
                "pending_approval": 0,
                "wip_in_progress": 0,
                "wip_completed": 0
            }
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_requests_pending_approval_for_dashboard(status, wip_status):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """                   
                    SELECT 
                        CONCAT(b.project_code, ' - ', b.project_name) AS project_name,
                        c.subject,
                        LTRIM(RTRIM(COALESCE(d.Fname + ' ' + d.Mname + ' ' + d.Sname, ''))) AS name,
                        appr.submission_date AS creation_date
                    FROM trn_activity_request a
                    
                    LEFT JOIN mst_project b 
                        ON a.project_id = b.id
                    
                    LEFT JOIN trn_activity_overview c 
                        ON a.id = c.activity_id
                    
                    LEFT JOIN users d 
                        ON a.user_id = d.ID
                    
                    LEFT JOIN (
                        SELECT 
                            activity_request_id,
                            MIN(date_time) AS submission_date
                        FROM trn_activity_request_approvals
                        GROUP BY activity_request_id
                    ) appr 
                        ON appr.activity_request_id = a.id
                    
                    WHERE a.status > ? 
                      AND a.wip_status = ?
                    
                    ORDER BY appr.submission_date;
                    """
            cursor.execute(query, (status, wip_status,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(project_name=row.project_name, subject=row.subject, name=row.name, creation_date=row.creation_date)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_requests_under_wip_for_dashboard(wip_approval_complete, wip_status):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """                   
                    SELECT 
                        CONCAT(b.project_code, ' - ', b.project_name) AS project_name,
                        c.subject,
                        LTRIM(RTRIM(COALESCE(d.Fname + ' ' + d.Mname + ' ' + d.Sname, ''))) AS name,
                        appr.submission_date AS creation_date
                    FROM trn_activity_request a

                    LEFT JOIN mst_project b 
                        ON a.project_id = b.id

                    LEFT JOIN trn_activity_overview c 
                        ON a.id = c.activity_id

                    LEFT JOIN users d 
                        ON a.user_id = d.ID

                    LEFT JOIN (
                        SELECT 
                            activity_request_id,
                            MAX(date_time) AS submission_date
                        FROM trn_activity_request_approvals
                        GROUP BY activity_request_id
                    ) appr 
                        ON appr.activity_request_id = a.id

                    WHERE a.wip_approval_complete = ? 
                      AND a.wip_status <> ?

                    ORDER BY appr.submission_date;
                    """
            cursor.execute(query, (wip_approval_complete, wip_status,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(project_name=row.project_name, subject=row.subject, name=row.name,
                                creation_date=row.creation_date)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_completed_wip_activity_dashboard(wip_approval_complete, wip_status):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """                   
                    SELECT 
                        CONCAT(b.project_code, ' - ', b.project_name) AS project_name,
                        c.subject,
                        LTRIM(RTRIM(COALESCE(d.Fname + ' ' + d.Mname + ' ' + d.Sname, ''))) AS name,
                        appr.submission_date AS creation_date
                    FROM trn_activity_request a

                    LEFT JOIN mst_project b 
                        ON a.project_id = b.id

                    LEFT JOIN trn_activity_overview c 
                        ON a.id = c.activity_id

                    LEFT JOIN users d 
                        ON a.user_id = d.ID

                    LEFT JOIN (
                        SELECT 
                            activity_request_id,
                            MAX(date_time) AS submission_date
                        FROM trn_completed_wip_activity_request_approvals
                        GROUP BY activity_request_id
                    ) appr 
                        ON appr.activity_request_id = a.id

                    WHERE a.wip_approval_complete = ? 
                      AND a.wip_status <> ?

                    ORDER BY appr.submission_date;
                    """
            cursor.execute(query, (wip_approval_complete, wip_status,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(project_name=row.project_name, subject=row.subject, name=row.name,
                                creation_date=row.creation_date)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_officer_bookings_dashboard():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """                   
                        SELECT 
                            TRIM(
                                COALESCE(e.Fname + ' ', '') +
                                COALESCE(e.Mname + ' ', '') +
                                COALESCE(e.Sname, '')
                            ) AS name,
                        
                            TRIM(
                                COALESCE(c.project_code + ' - ', '') +
                                COALESCE(c.project_name, '')
                            ) AS project_name,
                        
                            b.subject,
                            md.max_end_date
                        
                        FROM trn_activity_request a
                        
                        INNER JOIN trn_activity_team_composition d
                            ON a.id = d.activity_id
                        
                        INNER JOIN (
                            SELECT 
                                ba.activity_id,
                                tc.member_user_id,
                                MAX(ba.end_date) AS max_end_date
                            FROM trn_activity_breakdown ba
                            INNER JOIN trn_activity_team_composition tc
                                ON ba.activity_id = tc.activity_id
                            GROUP BY ba.activity_id, tc.member_user_id
                        ) md
                            ON md.activity_id = a.id
                            AND md.member_user_id = d.member_user_id
                            AND md.max_end_date > GETDATE()
                        
                        LEFT JOIN trn_activity_overview b 
                            ON a.id = b.activity_id
                        
                        LEFT JOIN mst_project c 
                            ON a.project_id = c.id
                        
                        LEFT JOIN users e 
                            ON d.member_user_id = e.ID;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(name=row.name, project_name=row.project_name, subject=row.subject,
                                max_end_date=row.max_end_date)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_requests_pending_approval_count(user_id):
        conn = get_db_connection()
        if conn is None:
            return 0  # Return 0 if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        DECLARE @logged_in_user_id INT = ?; -- Set logged-in user's ID
                        
                        ;WITH GlobalFiles AS (
                            -- Files where responsibility is global
                            SELECT 
                                LTRIM(RTRIM(
                                    COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, '')
                                )) AS name,
                        
                                pro.project_code, 
                                pro.project_name, 
                                taro.subject,  
                        
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT JOIN user_role ur 
                                        ON r.id = ur.role_id
                                    LEFT JOIN role_workflow_breakdown rwb 
                                        ON ur.role_id = rwb.role_id
                                    LEFT JOIN workflow_breakdown wb 
                                        ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                        
                                ROW_NUMBER() OVER (
                                    PARTITION BY tar.id 
                                    ORDER BY tar.creation_date DESC
                                ) AS row_num
                        
                            FROM trn_activity_request tar
                        
                            JOIN trn_activity_request_approvals tara 
                                ON tar.id = tara.activity_request_id
                        
                            JOIN mst_project pro 
                                ON tar.project_id = pro.id
                        
                            JOIN trn_activity_overview taro 
                                ON tar.id = taro.activity_id
                        
                            JOIN users u 
                                ON tar.user_id = u.ID
                        
                            JOIN user_role ur 
                                ON u.ID = ur.user_id
                        
                            JOIN role r 
                                ON ur.role_id = r.id
                        
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                        
                                AND tara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit_tier b 
                                        ON a.organisation_unit_tier_id = b.id
                                    WHERE b.parent_org_unit_tier_id IN (
                                        SELECT d.organisation_unit_tier_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                        
                                AND tar.status != 0 
                        
                                AND tar.status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b 
                                        ON a.id = b.workflow_breakdown_id
                                    JOIN role c 
                                        ON b.role_id = c.id
                                    JOIN user_role d 
                                        ON c.id = d.role_id
                                    JOIN users e 
                                        ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 1
                                        AND e.ID = @logged_in_user_id
                                )
                        ),
                        
                        OrgBasedFiles AS (
                            -- Files where responsibility is restricted to specific organizational units
                            SELECT 
                                LTRIM(RTRIM(
                                    COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, '')
                                )) AS name,
                        
                                pro.project_code, 
                                pro.project_name, 
                                taro.subject,  
                        
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT JOIN user_role ur 
                                        ON r.id = ur.role_id
                                    LEFT JOIN role_workflow_breakdown rwb 
                                        ON ur.role_id = rwb.role_id
                                    LEFT JOIN workflow_breakdown wb 
                                        ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                        
                                ROW_NUMBER() OVER (
                                    PARTITION BY tar.id 
                                    ORDER BY tar.creation_date DESC
                                ) AS row_num
                        
                            FROM trn_activity_request tar
                        
                            JOIN trn_activity_request_approvals tara 
                                ON tar.id = tara.activity_request_id
                        
                            JOIN mst_project pro 
                                ON tar.project_id = pro.id
                        
                            JOIN trn_activity_overview taro 
                                ON tar.id = taro.activity_id
                        
                            JOIN users u 
                                ON tar.user_id = u.ID
                        
                            JOIN user_role ur 
                                ON u.ID = ur.user_id
                        
                            JOIN role r 
                                ON ur.role_id = r.id
                        
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                        
                                AND tara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit b 
                                        ON a.organisation_unit_id = b.id
                                    WHERE b.parent_org_unit_id IN (
                                        SELECT d.organisation_unit_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                        
                                AND tar.status != 0 
                        
                                AND tar.status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b 
                                        ON a.id = b.workflow_breakdown_id
                                    JOIN role c 
                                        ON b.role_id = c.id
                                    JOIN user_role d 
                                        ON c.id = d.role_id
                                    JOIN users e 
                                        ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 0
                                        AND e.ID = @logged_in_user_id
                                )
                        )
                        
                        -- Final Count
                        SELECT COUNT(*) AS TotalPendingApprovals
                        FROM (
                            SELECT 
                                name, 
                                project_code, 
                                project_name, 
                                subject, 
                                approve_as
                            FROM GlobalFiles 
                            WHERE row_num = 1
                        
                            UNION   -- use UNION for distinct results
                        
                            SELECT 
                                name, 
                                project_code, 
                                project_name, 
                                subject, 
                                approve_as
                            FROM OrgBasedFiles 
                            WHERE row_num = 1
                        ) AS UniqueResults
                        WHERE approve_as IS NOT NULL;
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
    def insert_into_trn_activity_request(current_request_id, user_id, status, project_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()
        now = datetime.now()

        try:
            cursor.execute(
                """
                    INSERT INTO trn_activity_request (id, user_id, creation_date, last_modified, status, project_id)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                (current_request_id, user_id, now, now, status, project_id),
            )
            conn.commit()
            return current_request_id
        except pyodbc.Error as e:
            print("Could not insert into table: trn_activity_request:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def insert_into_trn_activity_overview(current_request_id, subject, objectives, scope, stakeholders, deliverables,
                                          assumptions):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()
        now = datetime.now()

        try:
            cursor.execute(
                """
                INSERT INTO trn_activity_overview 
                (activity_id, subject, objectives, scope, stakeholders, deliverables, assumptions)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (current_request_id, subject, objectives, scope, stakeholders, deliverables, assumptions),
            )
            conn.commit()
            return current_request_id
        except pyodbc.Error as e:
            print("Could not insert into table: trn_activity_overview:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def update_trn_activity_overview(current_request_id, subject, objectives, scope, stakeholders, deliverables,
                                     assumptions):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                UPDATE trn_activity_overview
                SET subject = ?, objectives = ?, scope = ?, stakeholders = ?, deliverables = ?, assumptions = ?
                WHERE activity_id = ?
            """
            cursor.execute(query, (subject, objectives, scope, stakeholders, deliverables, assumptions,
                                   current_request_id))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update trn_activity_overview: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_activity_request_status(status, activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                UPDATE trn_activity_request
                SET status = ?
                WHERE id = ?
            """
            cursor.execute(query, (status, activity_request_id))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update status of trn_activity_request: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_trn_activity_request_project_id(activity_request_id, project_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                UPDATE trn_activity_request
                SET project_id = ?
                WHERE id = ?
            """
            cursor.execute(query, (activity_request_id, project_id))
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to update project_id of trn_activity_request: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_into_trn_activity_team_composition(team_member_no, activity_id, member_id, role_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()
        now = datetime.now()

        try:
            cursor.execute(
                """
                INSERT INTO trn_activity_team_composition 
                (id, activity_id, member_user_id, member_role_id)
                VALUES (?, ?, ?, ?)
                """,
                (team_member_no, activity_id, member_id, role_id),
            )
            conn.commit()
            return activity_id
        except pyodbc.Error as e:
            print("Could not insert into table: trn_activity_team_composition:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def insert_into_trn_activity_breakdown(task_no, activity_id, task, key_process_id, credit_points, start_date, end_date):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                    INSERT INTO trn_activity_breakdown 
                    (id, activity_id, task, key_process_id, credit_points, start_date, end_date)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (task_no, activity_id, task, key_process_id, credit_points, start_date, end_date),
            )
            conn.commit()
            return task_no
        except pyodbc.Error as e:
            print("Could not insert into table: trn_activity_breakdown:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def get_team_member_roles_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT * FROM team_member_role ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            project_details = [
                ActivityRequest(id=row.id, name=row.name)
                for row in result
            ]
            return project_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_key_process_details():
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT * FROM mst_key_process ORDER BY name;
                    """
            cursor.execute(query, )
            result = cursor.fetchall()

            # Convert query result into list of Reconciliation objects
            process_details = [
                ActivityRequest(id=row.id, name=row.name)
                for row in result
            ]
            return process_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_saved_activity_request_details(status, user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT 
                            a.id,
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,
                            CASE 
                                WHEN (SELECT COUNT(*) 
                                      FROM trn_activity_request_approvals ar 
                                      WHERE ar.activity_request_id = a.id) > 0 
                                THEN 'Rejected'
                                ELSE 'Pending Submission'
                            END AS status
                        FROM trn_activity_request a
                        LEFT JOIN trn_activity_overview b ON a.id = b.activity_id
                        LEFT JOIN mst_project c ON a.project_id = c.id
                        WHERE a.status = ?
                          AND a.user_id = ?
                        ORDER BY a.last_modified;
                    """
            cursor.execute(query, (status, user_id,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, last_modified=row.last_modified, status=row.status)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_wip_activity_request_details(status, user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT 
                            a.id,
                            LTRIM(RTRIM(CONCAT(d.Fname, ' ', d.Mname, ' ', d.Sname))) AS name,
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,
                            CASE 
                                WHEN EXISTS (
                                    SELECT 1
                                    FROM trn_activity_request_approvals ar 
                                    WHERE ar.activity_request_id = a.id
                                ) 
                                THEN 'Rejected'
                                ELSE 'Pending Submission'
                            END AS status
                        FROM trn_activity_request a
                        LEFT JOIN trn_activity_overview b 
                            ON a.id = b.activity_id
                        LEFT JOIN mst_project c 
                            ON a.project_id = c.id
                        LEFT JOIN users d 
                            ON a.user_id = d.ID     
                        WHERE a.wip_status = ?
                          AND (
                                a.user_id = ?
                                OR EXISTS (
                                    SELECT 1
                                    FROM trn_activity_team_composition t
                                    WHERE t.activity_id = a.id
                                      AND t.member_user_id = ?
                                )
                              )
                        ORDER BY a.last_modified;
                    """
            cursor.execute(query, (status, user_id, user_id))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, name=row.name, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, last_modified=row.last_modified, status=row.status)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_saved_activity_request_details_2(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT a.id, a.project_id as project_code, b.subject, b.objectives, b.scope, b.stakeholders, 
                        b.deliverables, b.assumptions 
                        FROM trn_activity_request a
                        LEFT OUTER JOIN trn_activity_overview b ON a.id = b.activity_id
                        LEFT OUTER JOIN mst_project c ON a.project_id = c.id
                        WHERE a.id = ?;
                    """
            cursor.execute(query, (activity_request_id,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, project_code=row.project_code, subject=row.subject, objectives=row.objectives,
                                scope=row.scope, stakeholders=row.stakeholders, deliverables=row.deliverables,
                                assumptions=row.assumptions)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_saved_activity_request_details_3(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT a.id, a.project_id as project_code, b.subject, b.objectives, b.scope, b.stakeholders, 
                        b.deliverables, b.assumptions 
                        FROM trn_completed_wip_activity_request_approvals a
                        LEFT OUTER JOIN trn_activity_overview b ON a.id = b.activity_id
                        LEFT OUTER JOIN mst_project c ON a.project_id = c.id
                        WHERE a.activity_request_id = ?;
                    """
            cursor.execute(query, (activity_request_id,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, project_code=row.project_code, subject=row.subject, objectives=row.objectives,
                                scope=row.scope, stakeholders=row.stakeholders, deliverables=row.deliverables,
                                assumptions=row.assumptions)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_saved_activity_request_details_3(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT a.id, c.project_code, c.project_name, b.subject
                        FROM trn_activity_request a
                        LEFT OUTER JOIN trn_activity_overview b ON a.id = b.activity_id
                        LEFT OUTER JOIN mst_project c ON a.project_id = c.id
                        WHERE a.id = ?
                        ORDER BY a.last_modified;
                    """
            cursor.execute(query, (activity_request_id,))
            result = cursor.fetchall()

            activity_request_details = [
                {
                    "id": row.id,
                    "project_code": row.project_code,
                    "project_name": row.project_name,
                    "subject": row.subject
                }
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_submitted_activity_request_details(status, user_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        DECLARE @workflow_id INT = 1;
                        
                        ;WITH WorkflowMaxLevel AS (
                            SELECT wf.id AS workflow_id, MAX(wb.level) AS max_level
                            FROM workflow wf
                            LEFT JOIN workflow_breakdown wb ON wf.id = wb.workflow_id
                            GROUP BY wf.id
                        ),
                        LatestApproval AS (
                            SELECT 
                                ar.activity_request_id,
                                MAX(ar.date_time) AS latest_date,
                                COUNT(*) AS approval_count
                            FROM trn_activity_request_approvals ar
                            GROUP BY ar.activity_request_id
                        ),
                        ApprovalLevel AS (
                            SELECT 
                                la.activity_request_id,
                                la.approval_count,
                                ar.level AS latest_level
                            FROM LatestApproval la
                            LEFT JOIN trn_activity_request_approvals ar
                                ON ar.activity_request_id = la.activity_request_id 
                                AND ar.date_time = la.latest_date
                        )
                        SELECT 
                            a.id,
                            LTRIM(RTRIM(COALESCE(d.Fname + ' ' + d.Mname + ' ' + d.Sname, ''))) AS name,
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,
                            CASE 
                                WHEN ISNULL(al.approval_count, 0) = 1 THEN 'Submitted'
                                WHEN al.latest_level = 1 AND al.approval_count > 1 THEN 'Re-submitted'
                                WHEN al.latest_level > 1 
                                     AND al.latest_level < wml.max_level THEN 'In Review'
                                WHEN al.latest_level = wml.max_level THEN 'Approved'
                                ELSE 'Unknown'
                            END AS status
                        FROM trn_activity_request a
                        LEFT JOIN trn_activity_overview b ON a.id = b.activity_id
                        LEFT JOIN mst_project c ON a.project_id = c.id
                        LEFT JOIN users d ON a.user_id = d.ID
                        LEFT JOIN ApprovalLevel al ON a.id = al.activity_request_id
                        LEFT JOIN WorkflowMaxLevel wml ON wml.workflow_id = @workflow_id
                        WHERE 
                            a.status != ?
                            AND (
                                a.user_id = ?
                                OR a.id IN (
                                    SELECT DISTINCT(activity_id)
                                    FROM trn_activity_team_composition
                                    WHERE member_user_id = ?
                                )
                            )
                        ORDER BY a.last_modified DESC;
                    """
            cursor.execute(query, (status, user_id, user_id,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, name=row.name, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, last_modified=row.last_modified, status=row.status)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_submitted_activity_request_details(status):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        DECLARE @workflow_id INT = 1;

                        ;WITH WorkflowMaxLevel AS (
                            SELECT wf.id AS workflow_id, MAX(wb.level) AS max_level
                            FROM workflow wf
                            LEFT JOIN workflow_breakdown wb ON wf.id = wb.workflow_id
                            GROUP BY wf.id
                        ),
                        LatestApproval AS (
                            SELECT 
                                ar.activity_request_id,
                                MAX(ar.date_time) AS latest_date,
                                COUNT(*) AS approval_count
                            FROM trn_activity_request_approvals ar
                            GROUP BY ar.activity_request_id
                        ),
                        ApprovalLevel AS (
                            SELECT 
                                la.activity_request_id,
                                la.approval_count,
                                ar.level AS latest_level
                            FROM LatestApproval la
                            LEFT JOIN trn_activity_request_approvals ar
                                ON ar.activity_request_id = la.activity_request_id 
                                AND ar.date_time = la.latest_date
                        )
                        SELECT 
                            a.id,
                            LTRIM(RTRIM(COALESCE(d.Fname + ' ' + d.Mname + ' ' + d.Sname, ''))) AS name,
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,
                            CASE 
                                WHEN ISNULL(al.approval_count, 0) = 1 THEN 'Submitted'
                                WHEN al.latest_level = 1 AND al.approval_count > 1 THEN 'Re-submitted'
                                WHEN al.latest_level > 1 
                                     AND al.latest_level < wml.max_level THEN 'In Review'
                                WHEN al.latest_level = wml.max_level THEN 'Approved'
                                ELSE 'Unknown'
                            END AS status
                        FROM trn_activity_request a
                        LEFT JOIN trn_activity_overview b ON a.id = b.activity_id
                        LEFT JOIN mst_project c ON a.project_id = c.id
                        LEFT JOIN users d ON a.user_id = d.ID
                        LEFT JOIN ApprovalLevel al ON a.id = al.activity_request_id
                        LEFT JOIN WorkflowMaxLevel wml ON wml.workflow_id = @workflow_id
                        WHERE 
                            a.status > ?
                        ORDER BY a.last_modified DESC;
                    """
            cursor.execute(query, (status,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, name=row.name, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, last_modified=row.last_modified, status=row.status)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_submitted_completed_wip_activity_request_details(status):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        DECLARE @workflow_id INT = 1;

                        ;WITH WorkflowMaxLevel AS (
                            SELECT wf.id AS workflow_id, MAX(wb.level) AS max_level
                            FROM workflow wf
                            LEFT JOIN workflow_breakdown wb ON wf.id = wb.workflow_id
                            GROUP BY wf.id
                        ),
                        LatestApproval AS (
                            SELECT 
                                ar.activity_request_id,
                                MAX(ar.date_time) AS latest_date,
                                COUNT(*) AS approval_count
                            FROM trn_completed_wip_activity_request_approvals ar
                            GROUP BY ar.activity_request_id
                        ),
                        ApprovalLevel AS (
                            SELECT 
                                la.activity_request_id,
                                la.approval_count,
                                ar.level AS latest_level
                            FROM LatestApproval la
                            LEFT JOIN trn_completed_wip_activity_request_approvals ar
                                ON ar.activity_request_id = la.activity_request_id 
                                AND ar.date_time = la.latest_date
                        )
                        SELECT 
                            a.id,
                            LTRIM(RTRIM(COALESCE(d.Fname + ' ' + d.Mname + ' ' + d.Sname, ''))) AS name,
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,
                            CASE 
                                WHEN ISNULL(al.approval_count, 0) = 1 THEN 'Submitted'
                                WHEN al.latest_level = 1 AND al.approval_count > 1 THEN 'Re-submitted'
                                WHEN al.latest_level > 1 
                                     AND al.latest_level < wml.max_level THEN 'In Review'
                                WHEN al.latest_level = wml.max_level THEN 'Approved'
                                ELSE 'Unknown'
                            END AS status
                        FROM trn_activity_request a
                        LEFT JOIN trn_activity_overview b ON a.id = b.activity_id
                        LEFT JOIN mst_project c ON a.project_id = c.id
                        LEFT JOIN users d ON a.user_id = d.ID
                        LEFT JOIN ApprovalLevel al ON a.id = al.activity_request_id
                        LEFT JOIN WorkflowMaxLevel wml ON wml.workflow_id = @workflow_id
                        WHERE 
                            a.wip_status > ?
                        ORDER BY a.last_modified DESC;
                    """
            cursor.execute(query, (status,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, name=row.name, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, last_modified=row.last_modified, status=row.status)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_activity_requests_pending_submission_details(status):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        DECLARE @workflow_id INT = 1;

                        ;WITH WorkflowMaxLevel AS (
                            SELECT wf.id AS workflow_id, MAX(wb.level) AS max_level
                            FROM workflow wf
                            LEFT JOIN workflow_breakdown wb ON wf.id = wb.workflow_id
                            GROUP BY wf.id
                        ),
                        LatestApproval AS (
                            SELECT 
                                ar.activity_request_id,
                                MAX(ar.date_time) AS latest_date,
                                COUNT(*) AS approval_count
                            FROM trn_activity_request_approvals ar
                            GROUP BY ar.activity_request_id
                        ),
                        ApprovalLevel AS (
                            SELECT 
                                la.activity_request_id,
                                la.approval_count,
                                ar.level AS latest_level
                            FROM LatestApproval la
                            LEFT JOIN trn_activity_request_approvals ar
                                ON ar.activity_request_id = la.activity_request_id 
                                AND ar.date_time = la.latest_date
                        )
                        SELECT 
                            a.id,
                            LTRIM(RTRIM(COALESCE(d.Fname + ' ' + d.Mname + ' ' + d.Sname, ''))) AS name,
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,
                            CASE 
                                WHEN ISNULL(al.approval_count, 0) = 1 THEN 'Submitted'
                                WHEN al.latest_level = 1 AND al.approval_count > 1 THEN 'Re-submitted'
                                WHEN al.latest_level > 1 
                                     AND al.latest_level < wml.max_level THEN 'In Review'
                                WHEN al.latest_level = wml.max_level THEN 'Approved'
                                ELSE 'Pending Submission'
                            END AS status
                        FROM trn_activity_request a
                        LEFT JOIN trn_activity_overview b ON a.id = b.activity_id
                        LEFT JOIN mst_project c ON a.project_id = c.id
                        LEFT JOIN users d ON a.user_id = d.ID
                        LEFT JOIN ApprovalLevel al ON a.id = al.activity_request_id
                        LEFT JOIN WorkflowMaxLevel wml ON wml.workflow_id = @workflow_id
                        WHERE 
                            a.status = ?
                        ORDER BY a.last_modified DESC;
                    """
            cursor.execute(query, (status,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, name=row.name, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, last_modified=row.last_modified, status=row.status)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_all_completed_wip_activity_requests_pending_submission_details(status):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        DECLARE @workflow_id INT = 1;

                        ;WITH WorkflowMaxLevel AS (
                            SELECT wf.id AS workflow_id, MAX(wb.level) AS max_level
                            FROM workflow wf
                            LEFT JOIN workflow_breakdown wb ON wf.id = wb.workflow_id
                            GROUP BY wf.id
                        ),
                        LatestApproval AS (
                            SELECT 
                                ar.activity_request_id,
                                MAX(ar.date_time) AS latest_date,
                                COUNT(*) AS approval_count
                            FROM trn_completed_wip_activity_request_approvals ar
                            GROUP BY ar.activity_request_id
                        ),
                        ApprovalLevel AS (
                            SELECT 
                                la.activity_request_id,
                                la.approval_count,
                                ar.level AS latest_level
                            FROM LatestApproval la
                            LEFT JOIN trn_completed_wip_activity_request_approvals ar
                                ON ar.activity_request_id = la.activity_request_id 
                                AND ar.date_time = la.latest_date
                        )
                        SELECT 
                            a.id,
                            LTRIM(RTRIM(COALESCE(d.Fname + ' ' + d.Mname + ' ' + d.Sname, ''))) AS name,
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,
                            CASE 
                                WHEN ISNULL(al.approval_count, 0) = 1 THEN 'Submitted'
                                WHEN al.latest_level = 1 AND al.approval_count > 1 THEN 'Re-submitted'
                                WHEN al.latest_level > 1 
                                     AND al.latest_level < wml.max_level THEN 'In Review'
                                WHEN al.latest_level = wml.max_level THEN 'Approved'
                                ELSE 'Pending Submission'
                            END AS status
                        FROM trn_activity_request a
                        LEFT JOIN trn_activity_overview b ON a.id = b.activity_id
                        LEFT JOIN mst_project c ON a.project_id = c.id
                        LEFT JOIN users d ON a.user_id = d.ID
                        LEFT JOIN ApprovalLevel al ON a.id = al.activity_request_id
                        LEFT JOIN WorkflowMaxLevel wml ON wml.workflow_id = @workflow_id
                        WHERE 
                            a.wip_status = ?
                        ORDER BY a.last_modified DESC;
                    """
            cursor.execute(query, (status,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, name=row.name, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, last_modified=row.last_modified, status=row.status)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_rejected_activity_requests_details(workflow_id, approval_action):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT 
                            tar.id, 
                            CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) AS name,
                            mp.project_code, 
                            mp.project_name, 
                            tao.subject,
                            CONVERT(VARCHAR(19), tar.last_modified, 120) AS last_modified,
                            (
                                SELECT TOP 1
                                    CASE 
                                        WHEN tara.decision = 1 THEN 'Submitted by'
                                        WHEN tara.decision = 2 THEN 'Approved by'
                                        WHEN tara.decision = 3 THEN 'Rejected by'
                                        ELSE 'Unknown'
                                    END + ' ' + ISNULL(r.name, '') 
                                FROM trn_activity_request_approvals tara
                                LEFT JOIN workflow_breakdown wb 
                                    ON tara.level - 1 = wb.level 
                                    AND wb.workflow_id = ?
                                LEFT JOIN role_workflow_breakdown rwb 
                                    ON wb.id = rwb.workflow_breakdown_id
                                LEFT JOIN role r 
                                    ON rwb.role_id = r.id
                                WHERE tara.activity_request_id = tar.id   
                                ORDER BY tara.id DESC
                            ) AS status
                        FROM trn_activity_request tar
                        
                        JOIN mst_project mp 
                            ON tar.project_id = mp.id
                        
                        JOIN trn_activity_overview tao 
                            ON tar.id = tao.activity_id
                        
                        JOIN users u 
                            ON tar.user_id = u.ID
                        
                        WHERE (
                            SELECT TOP 1 ra2.decision
                            FROM trn_activity_request_approvals ra2
                            WHERE ra2.activity_request_id = tar.id
                            ORDER BY ra2.id DESC
                        ) = ?;
                    """
            cursor.execute(query, (workflow_id, approval_action,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, name=row.name, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, last_modified=row.last_modified, status=row.status)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_rejected_completed_wip_activity_requests_details(workflow_id, approval_action):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT 
                            tar.id, 
                            CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) AS name,
                            mp.project_code, 
                            mp.project_name, 
                            tao.subject,
                            CONVERT(VARCHAR(19), tar.last_modified, 120) AS last_modified,
                            (
                                SELECT TOP 1
                                    CASE 
                                        WHEN tara.decision = 1 THEN 'Submitted by'
                                        WHEN tara.decision = 2 THEN 'Approved by'
                                        WHEN tara.decision = 3 THEN 'Rejected by'
                                        ELSE 'Unknown'
                                    END + ' ' + ISNULL(r.name, '') 
                                FROM trn_completed_wip_activity_request_approvals tara
                                LEFT JOIN workflow_breakdown wb 
                                    ON tara.level - 1 = wb.level 
                                    AND wb.workflow_id = ?
                                LEFT JOIN role_workflow_breakdown rwb 
                                    ON wb.id = rwb.workflow_breakdown_id
                                LEFT JOIN role r 
                                    ON rwb.role_id = r.id
                                WHERE tara.activity_request_id = tar.id   
                                ORDER BY tara.id DESC
                            ) AS status
                        FROM trn_activity_request tar

                        JOIN mst_project mp 
                            ON tar.project_id = mp.id

                        JOIN trn_activity_overview tao 
                            ON tar.id = tao.activity_id

                        JOIN users u 
                            ON tar.user_id = u.ID

                        WHERE (
                            SELECT TOP 1 ra2.decision
                            FROM trn_completed_wip_activity_request_approvals ra2
                            WHERE ra2.activity_request_id = tar.id
                            ORDER BY ra2.id DESC
                        ) = ?;
                    """
            cursor.execute(query, (workflow_id, approval_action,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, name=row.name, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, last_modified=row.last_modified, status=row.status)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_tasks_by_key_process(key_process_id, activity_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT
                            a.id,
                            a.task,
                            ISNULL(
                                (
                                    SELECT SUM(tab.credit_points)
                                    FROM trn_activity_breakdown tab
                                    INNER JOIN trn_activity_request tar
                                        ON tab.activity_id = tar.id
                                    WHERE tab.key_process_id = a.key_process_id
                                      AND tar.project_id = b.project_id
                                ), 0
                            )
                            -
                            ISNULL(
                                (
                                    SELECT SUM(talab.credit_points)
                                    FROM trn_activity_log_activity_breakdown talab
                                    INNER JOIN trn_activity_log_overview talo
                                        ON talab.trn_activity_log_id = talo.id
                                    INNER JOIN trn_activity_request tar
                                        ON talo.activity_id = tar.id
                                    WHERE tar.project_id = b.project_id
                                      AND EXISTS
                                      (
                                          SELECT 1
                                          FROM trn_activity_breakdown tab
                                          WHERE tab.activity_id = tar.id
                                            AND tab.key_process_id = a.key_process_id
                                      )
                                ), 0
                            ) AS credit_points_balance
                        FROM trn_activity_breakdown a
                        LEFT JOIN trn_activity_request b
                            ON a.activity_id = b.id
                        WHERE a.key_process_id = ?
                          AND a.activity_id = ?
                        ORDER BY a.task;
            """
            cursor.execute(query, (key_process_id, activity_id,))
            result = cursor.fetchall()

            activity_tasks = [
                ActivityRequest(id=row.id, task=row.task, credit_points_balance=row.credit_points_balance)
                for row in result
            ]
            return activity_tasks
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_credit_points_balance_by_task_id(task_id, key_process_id, activity_id):
        conn = get_db_connection()
        if conn is None:
            return 0

        cursor = conn.cursor()

        try:
            query = """
                SELECT
                    a.credit_points -
                    ISNULL(
                        (
                            SELECT SUM(talab.credit_points)
                            FROM trn_activity_log_activity_breakdown talab
                            INNER JOIN trn_activity_log_overview talo
                                ON talab.trn_activity_log_id = talo.id
                            WHERE talo.activity_id = a.activity_id
                              AND talo.key_process_id = a.key_process_id
                              AND talo.task_id = a.id
                        ),
                        0
                    ) AS credit_points_balance
                FROM trn_activity_breakdown a
                WHERE a.id = ?
                  AND a.activity_id = ?
                  AND a.key_process_id = ?;
            """

            cursor.execute(query, (task_id, activity_id, key_process_id))

            row = cursor.fetchone()

            return row.credit_points_balance if row else 0

        except Exception as e:
            print("Database error:", e)
            return 0

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_credit_points_balance_view_edit_log_modal(log_id, key_process_id, task_id):
        conn = get_db_connection()
        if conn is None:
            return 0

        cursor = conn.cursor()

        try:
            query = """
                        SELECT
                            ISNULL(
                                (
                                    SELECT SUM(tab.credit_points)
                                    FROM trn_activity_breakdown tab
                                    WHERE tab.activity_id = a.activity_id
                                      AND tab.key_process_id = ?
                                      AND tab.id = ?
                                ),
                                0
                            )
                            -
                            ISNULL(
                                (
                                    SELECT SUM(talab.credit_points)
                                    FROM trn_activity_log_activity_breakdown talab
                                    INNER JOIN trn_activity_log_overview talo
                                        ON talab.trn_activity_log_id = talo.id
                                    WHERE talo.activity_id = a.activity_id
                                      AND talo.key_process_id = ?
                                      AND talo.task_id = ?
                                ),
                                0
                            ) AS credit_points_balance
                        FROM trn_activity_log_overview a
                        WHERE a.id = ?;
            """

            cursor.execute(query, (key_process_id, task_id, key_process_id, task_id, log_id))

            row = cursor.fetchone()

            return row.credit_points_balance if row else 0

        except Exception as e:
            print("Database error:", e)
            return 0

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_breakdown_details_view_edit_log_modal(log_id, key_process_id, task_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()
        try:
            query = """
                        SELECT 
                            a.start_date,
                            a.end_date,
                            a.detail,
                            ISNULL(a.credit_points, 0) AS credit_points,

                            (
                                ISNULL(
                                    (
                                        SELECT SUM(tab.credit_points)
                                        FROM trn_activity_breakdown tab
                                        WHERE tab.activity_id = b.activity_id
                                          AND tab.key_process_id = b.key_process_id
                                          AND tab.id = b.task_id
                                    ),
                                    0
                                )
                                -
                                ISNULL(
                                    (
                                        SELECT SUM(talab.credit_points)
                                        FROM trn_activity_log_activity_breakdown talab
                                        INNER JOIN trn_activity_log_overview talo
                                            ON talab.trn_activity_log_id = talo.id
                                        WHERE talo.activity_id = b.activity_id
                                          AND talo.key_process_id = b.key_process_id
                                          AND talo.task_id = b.task_id
                                    ),
                                    0
                                )
                                +
                                ISNULL(
                                    (
                                        SELECT SUM(talab.credit_points)
                                        FROM trn_activity_log_activity_breakdown talab
                                        INNER JOIN trn_activity_log_overview talo
                                            ON talab.trn_activity_log_id = talo.id
                                        WHERE talo.id = b.id
                                          AND talo.activity_id = b.activity_id
                                          AND talo.key_process_id = b.key_process_id
                                          AND talo.task_id = b.task_id
                                    ),
                                    0
                                )
                            ) AS available_credit_points

                        FROM trn_activity_log_activity_breakdown a
                        INNER JOIN trn_activity_log_overview b
                            ON a.trn_activity_log_id = b.id
                        WHERE b.id = ? 
						and b.key_process_id = ?
						and b.task_id = ?;					
                    """
            cursor.execute(query, (log_id, key_process_id, task_id,))
            columns = [col[0] for col in cursor.description]
            result = [dict(zip(columns, row)) for row in cursor.fetchall()]
            print(result)
            return result

        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_process_by_activity_request_id(activity_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch tasks associated with the Key Process
            query = """
                SELECT id, name FROM mst_key_process 
                WHERE id IN (SELECT DISTINCT(key_process_id) FROM trn_activity_breakdown WHERE activity_id = ?)
                ORDER BY name
            """
            cursor.execute(query, (activity_id,))
            result = cursor.fetchall()

            activity_key_processes = [
                ActivityRequest(id=row.id, name=row.name)
                for row in result
            ]
            return activity_key_processes
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_team_composition_details(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()
        try:
            query = """
                SELECT id, activity_id, member_user_id, member_role_id
                FROM trn_activity_team_composition
                WHERE activity_id = ?
            """
            cursor.execute(query, (activity_request_id,))
            columns = [col[0] for col in cursor.description]
            result = cursor.fetchall()

            return [dict(zip(columns, row)) for row in result]

        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_team_composition_details_2(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()
        try:
            query = """
                        SELECT tatc.id, tatc.activity_id, tatc.member_user_id, tatc.member_role_id,
                        CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) AS member_name, tmr.name AS member_role
                        FROM trn_activity_team_composition tatc
                        LEFT OUTER JOIN users u ON tatc.member_user_id = u.ID
                        LEFT OUTER JOIN team_member_role tmr ON tatc.member_role_id = tmr.id
                        WHERE activity_id = ?
                        ORDER BY id
                    """
            cursor.execute(query, (activity_request_id,))
            columns = [col[0] for col in cursor.description]
            result = cursor.fetchall()

            return [dict(zip(columns, row)) for row in result]

        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_tasks_details(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()
        try:
            query = """
                        SELECT
                            a.id,
                            a.activity_id,
                            a.task,
                            a.key_process_id,
                        
                            ISNULL(kpi.total_credit_points, 0)
                            - ISNULL(used.used_credit_points, 0)
                            + ISNULL(a.credit_points, 0) AS available_credit_points,
                        
                            a.credit_points,
                            CONVERT(varchar, a.start_date, 120) AS start_date,
                            CONVERT(varchar, a.end_date, 120) AS end_date
                        
                        FROM trn_activity_breakdown a
                        INNER JOIN trn_activity_request b
                            ON a.activity_id = b.id
                        
                        OUTER APPLY (
                            SELECT SUM(kpsd.credit_points) AS total_credit_points
                            FROM trn_project_kpi_setup_details kpsd
                            INNER JOIN trn_project_kpi_setup kps
                                ON kpsd.project_kpi_setup_id = kps.id
                            WHERE kps.project_id = b.project_id
                              AND kpsd.key_process_id = a.key_process_id
                        ) kpi
                        
                        OUTER APPLY (
                            SELECT SUM(tab.credit_points) AS used_credit_points
                            FROM trn_activity_breakdown tab
                            INNER JOIN trn_activity_request tar
                                ON tab.activity_id = tar.id
                            WHERE tar.project_id = b.project_id
                              AND tab.key_process_id = a.key_process_id
                        ) used
                        
                        WHERE a.activity_id = ?
                        ORDER BY a.id;
            """
            cursor.execute(query, (activity_request_id,))
            columns = [col[0] for col in cursor.description]
            result = cursor.fetchall()
            return [dict(zip(columns, row)) for row in result]

        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_tasks_details_2(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()
        try:
            query = """
                        SELECT
                            a.id,
                            a.activity_id,
                            a.task,
                            a.key_process_id,
                            b.name AS process_name,
                            a.credit_points,
                        
                            ISNULL(
                                (
                                    SELECT SUM(tpksd.credit_points)
                                    FROM trn_project_kpi_setup_details tpksd
                                    INNER JOIN trn_project_kpi_setup tpkpis
                                        ON tpksd.project_kpi_setup_id = tpkpis.id
                                    WHERE tpkpis.project_id = c.project_id
                                      AND tpksd.key_process_id = a.key_process_id
                                ),
                                0
                            )
                            -
                            ISNULL(
                                (
                                    SELECT SUM(tab.credit_points)
                                    FROM trn_activity_breakdown tab
                                    INNER JOIN trn_activity_request tar
                                        ON tab.activity_id = tar.id
                                    WHERE tar.project_id = c.project_id
                                      AND tab.key_process_id = a.key_process_id
                                ),
                                0
                            ) AS credit_points_balance,
                        
                            CONVERT(varchar, a.start_date, 23) AS start_date,
                            CONVERT(varchar, a.end_date, 23) AS end_date
                        
                        FROM trn_activity_breakdown a
                        INNER JOIN mst_key_process b
                            ON a.key_process_id = b.id
                        INNER JOIN trn_activity_request c
                            ON a.activity_id = c.id
                        INNER JOIN mst_project d
                            ON c.project_id = d.id
                        WHERE a.activity_id = ?
                        ORDER BY a.id;
            """
            cursor.execute(query, (activity_request_id,))
            columns = [col[0] for col in cursor.description]
            result = cursor.fetchall()
            return [dict(zip(columns, row)) for row in result]

        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_into_trn_activity_attachment(id, activity_id, file, description):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO trn_activity_attachment ([id], [activity_id], [file], [description]) "
                "VALUES (?, ?, ?, ?)",
                (id, activity_id, file, description),
            )
            conn.commit()
            return id
        except pyodbc.Error as e:
            print("Database insert error:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def get_activity_attachments(activity_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()
        try:
            cursor.execute("""
                SELECT [id], [activity_id], [file], [description]
                FROM trn_activity_attachment
                WHERE activity_id = ?
                ORDER BY id
            """, (activity_id,))
            rows = cursor.fetchall()

            attachments = []
            for row in rows:
                attachments.append({
                    "id": row.id,
                    "activity_id": row.activity_id,
                    "file": row.file,
                    "description": row.description
                })
            return attachments
        except Exception as e:
            print("Error fetching attachments:", e)
            return []
        finally:
            conn.close()

    @staticmethod
    def delete_activity_request(current_request_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                DELETE FROM trn_activity_request                
                WHERE id = ?
            """
            cursor.execute(query, current_request_id)
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to delete from trn_activity_request: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_activity_overview(current_request_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                DELETE FROM trn_activity_overview                
                WHERE activity_id = ?
            """
            cursor.execute(query, current_request_id)
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to delete from trn_activity_overview: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_activity_team(current_request_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                DELETE FROM trn_activity_team_composition                
                WHERE activity_id = ?
            """
            cursor.execute(query, current_request_id)
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to delete from trn_activity_overview: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_activity_tasks(current_request_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                DELETE FROM trn_activity_breakdown                
                WHERE activity_id = ?
            """
            cursor.execute(query, current_request_id)
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to delete from trn_activity_breakdown: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_activity_attachments(current_request_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                DELETE FROM trn_activity_attachment                
                WHERE activity_id = ?
            """
            cursor.execute(query, current_request_id)
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to delete from trn_activity_breakdown: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_removed_attachments(activity_id, retained_ids):
        """
        Deletes attachments from trn_activity_attachment that are NOT in retained_ids
        for the given activity_id.
        """
        conn = get_db_connection()
        if conn is None:
            return

        cursor = conn.cursor()
        try:
            if retained_ids:
                placeholders = ",".join("?" for _ in retained_ids)
                query = f"""
                    DELETE FROM trn_activity_attachment
                    WHERE activity_id = ? AND id NOT IN ({placeholders})
                """
                params = [activity_id] + retained_ids
            else:
                query = "DELETE FROM trn_activity_attachment WHERE activity_id = ?"
                params = [activity_id]

            cursor.execute(query, params)
            conn.commit()
        except Exception as e:
            print("Error deleting removed attachments:", e)
            conn.rollback()
        finally:
            conn.close()


class ActivityRequestApprovals:
    def __init__(self, id=None, activity_request_id=None, decision=None, approver_id=None, approver=None, level=None,
                 comment=None, date_time=None, project_code=None, project_name=None, subject=None, approve_as=None,
                 requester=None):
        self.id = id
        self.activity_request_id = activity_request_id
        self.decision = decision
        self.approver_id = approver_id
        self.approver = approver
        self.level = level
        self.comment = comment
        self.date_time = date_time
        self.project_code = project_code
        self.project_name = project_name
        self.subject = subject
        self.approve_as = approve_as
        self.requester = requester

    @staticmethod
    def get_activity_requests_pending_approval(user_id):
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
                                (SELECT CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) FROM users WHERE ID = tar.user_id) 
                                AS requester,
                                tar.id AS activity_request_id, 
                                mp.project_code AS project_code, 
                                mp.project_name AS project_name, 
                                tao.subject AS subject,
                                FORMAT(tar.last_modified, 'yyyy-MM-dd HH:mm:ss') AS date_time, 
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tar.id ORDER BY tar.last_modified DESC) AS row_num
                            FROM trn_activity_request tar
                            JOIN trn_activity_request_approvals tara ON tar.id = tara.activity_request_id
                            JOIN mst_project mp ON tar.project_id = mp.id
                            JOIN trn_activity_overview tao ON tar.id = tao.activity_id
                            JOIN users u ON tar.user_id = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                                    WHERE b.parent_org_unit_tier_id IN (
                                        SELECT d.organisation_unit_tier_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tar.status != 1 
                                AND tar.status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 1
                                        AND e.ID = @logged_in_user_id
                                )
                        ),
                        OrgBasedFiles AS (
                            -- Get files where responsibility is restricted to specific organizational units
                            SELECT 
                                (SELECT CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) FROM users WHERE ID = tar.user_id) 
                                AS requester,
                                tar.id AS activity_request_id, 
                                mp.project_code AS project_code, 
                                mp.project_name AS project_name, 
                                tao.subject AS subject,
                                FORMAT(tar.last_modified, 'yyyy-MM-dd HH:mm:ss') AS date_time, 
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tar.id ORDER BY tar.last_modified DESC) AS row_num
                            FROM trn_activity_request tar
                            JOIN trn_activity_request_approvals tara ON tar.id = tara.activity_request_id
                            JOIN mst_project mp ON tar.project_id = mp.id
                            JOIN trn_activity_overview tao ON tar.id = tao.activity_id
                            JOIN users u ON tar.user_id = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit b ON a.organisation_unit_id = b.id
                                    WHERE b.parent_org_unit_id IN (
                                        SELECT d.organisation_unit_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tar.status != 1 
                                AND tar.status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 0
                                        AND e.ID = @logged_in_user_id
                                )
                        )

                        -- Combine results
                        SELECT 
                            requester, activity_request_id, project_code, project_name, subject, date_time, approve_as
                        FROM (
                            SELECT * FROM GlobalFiles WHERE row_num = 1
                            UNION
                            SELECT * FROM OrgBasedFiles WHERE row_num = 1
                        ) AS UniqueResults
                        WHERE approve_as IS NOT NULL
                        ORDER BY project_code, date_time, subject ASC;
            """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            activity_requests = [
                ActivityRequestApprovals(requester=row.requester, activity_request_id=row.activity_request_id,
                                         project_code=row.project_code, project_name=row.project_name,
                                         subject=row.subject, date_time=row.date_time, approve_as=row.approve_as)
                for row in result
            ]
            return activity_requests
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_request_approval_levels(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                           SELECT tara.level, CASE WHEN tara.decision = 1 
                           THEN 'Submitted' WHEN tara.decision = 2 THEN 'Approved' WHEN tara.decision = 3 
                           THEN 'Rejected' 
                           ELSE 'Pending' 
                           END AS decision,
                           CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) AS approver, tara.date_time, tara.comment 
                           FROM trn_activity_request_approvals tara
                           LEFT OUTER JOIN users u ON tara.approver_id = u.ID
                           WHERE tara.activity_request_id = ? ORDER BY tara.date_time
                       """
            cursor.execute(query, (activity_request_id,))  # Pass the parameter twice
            result = cursor.fetchall()  # Fetch results properly

            return result if result else []
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_latest_activity_request_approval_level(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # check if User has a request pending submission
            cursor.execute("SELECT TOP 1 COALESCE(level, 0) FROM trn_activity_request_approvals "
                           "WHERE activity_request_id = ? ORDER BY date_time DESC;", activity_request_id)

            latest_approval_level = cursor.fetchone()[0]  # Fetch last batch_id
            return latest_approval_level
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_status_of_activity_request(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # Check if a record with the given bank_account, year, and month exists
            cursor.execute(
                "SELECT status FROM trn_activity_request WHERE id = ?", activity_request_id
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
    def get_activity_request_initiator_user_id(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # check if User has a request pending submission
            cursor.execute("SELECT user_id FROM trn_activity_request WHERE id = ?", activity_request_id)

            id_of_initiator = cursor.fetchone()[0]  # Fetch last batch_id

            return id_of_initiator
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_request_initiator_email_and_fname(user_id):
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

    @staticmethod
    def get_next_approver_fname_email(user_id, activity_request_status):
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
                    AND ur.start_datetime <= GETDATE() 
                    AND ur.expiry_datetime >= GETDATE()
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
                    AND ur.start_datetime <= GETDATE() 
                    AND ur.expiry_datetime >= GETDATE()
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

            cursor.execute(query, (user_id, user_id, activity_request_status, activity_request_status))
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
    def get_max_approval_level(workflow_id):
        """
        Returns the maximum approval level for a given workflow_id.
        If no levels are found, returns 0.
        If a database error occurs, returns None.
        """
        conn = get_db_connection()
        if conn is None:
            app.logger.error("Database connection failed in get_max_approval_level()")
            return None

        try:
            with conn.cursor() as cursor:
                query = """
                    SELECT COALESCE(MAX(wb.level), 0)
                    FROM workflow wf
                    LEFT JOIN workflow_breakdown wb ON wf.id = wb.workflow_id
                    WHERE wf.id = ?
                """
                cursor.execute(query, (workflow_id,))
                result = cursor.fetchone()
                return result[0] if result else 0

        except Exception as e:
            app.logger.error(f"Database error in get_max_approval_level({workflow_id}): {e}")
            return None

        finally:
            conn.close()

    @staticmethod
    def insert_into_trn_activity_request_approvals(activity_request_id, decision, approver_id, level, comment):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        now = datetime.now()

        try:
            cursor.execute("SELECT COALESCE(MAX(id), 0) FROM trn_activity_request_approvals")
            last_activity_request_approvals_id = cursor.fetchone()[0]  # Fetch last batch_id

            # Set new batch_id
            last_activity_request_approvals_id = (last_activity_request_approvals_id + 1) \
                if last_activity_request_approvals_id else 1

            cursor.execute(
                "INSERT INTO trn_activity_request_approvals (id, activity_request_id, decision, approver_id, level, "
                "comment, date_time)"
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (last_activity_request_approvals_id, activity_request_id, decision, approver_id, level, comment, now),
            )
            conn.commit()

            return last_activity_request_approvals_id
        except pyodbc.Error as e:
            print("Database insert error:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def update_activity_request_approval_status(activity_request_id, action, workflow_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            if action == "reject":
                query = """
                    UPDATE trn_activity_request
                    SET status = 1
                    WHERE id = ?;
                """
                cursor.execute(query, (activity_request_id,))

            else:
                query = """                    
                    UPDATE trn_activity_request
                    SET 
                        status = status + 1,
                        wip_status = CASE 
                                        WHEN status = (
                                            SELECT MAX(wb.level)
                                            FROM workflow wf
                                            LEFT JOIN workflow_breakdown wb 
                                                ON wf.id = wb.workflow_id
                                            WHERE wf.id = ?
                                        ) 
                                        THEN 1
                                        ELSE 0
                                    END
                    WHERE id = ?;
                """
                cursor.execute(query, (workflow_id, activity_request_id))

            conn.commit()
            return True
        except Exception as e:
            print(f"Error updating approval status of trn_activity_request record: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_activity_request_approval_status_following_a_rejected_approval(activity_request_id):

        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            query = """
                UPDATE trn_activity_request
                SET status = 1
                WHERE id = ?
            """
            file_upload_id = cursor.execute(query, activity_request_id)
            conn.commit()
            return activity_request_id
        except Exception as e:
            print(f"Error updating status of trn_activity_request following a rejected request: {e}")

        finally:
            cursor.close()
            conn.close()


class ActivityRequestLog:
    def __init__(self, id=None, activity_id=None, key_process_id=None, task_id=None, user_id=None, key_process_name=None,
                 user_name=None, task=None, creation_date=None, requester=None, activity_request_id=None,
                 project_code=None, project_name=None, subject=None, date_time=None, approve_as=None, status_info=None):
        self.id = id
        self.activity_id = activity_id
        self.key_process_id = key_process_id
        self.task_id = task_id
        self.user_id = user_id
        self.key_process_name = key_process_name
        self.user_name = user_name
        self.task = task
        self.creation_date = creation_date
        self.requester = requester
        self.activity_request_id = activity_request_id
        self.project_code = project_code
        self.project_name = project_name
        self.subject = subject
        self.date_time = date_time
        self.approve_as = approve_as
        self.status_info = status_info

    @staticmethod
    def get_approved_activity_requests(user_id):
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
                            a.id,
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,                                                
                            (
                                SELECT TOP 1
                                    CASE 
                                        WHEN tara.decision = 1 THEN 'Submitted by'
                                        WHEN tara.decision = 2 THEN 'Approved by'
                                        WHEN tara.decision = 3 THEN 'Rejected by'
                                        ELSE 'Unknown'
                                    END + ' ' + r.name
                                FROM trn_activity_request_approvals tara
                                LEFT JOIN workflow_breakdown wb ON tara.level = wb.level AND wb.workflow_id = @workflow_id
                                LEFT JOIN role_workflow_breakdown rwb ON wb.id = rwb.workflow_breakdown_id
                                LEFT JOIN role r ON rwb.role_id = r.id
                                WHERE tara.activity_request_id = a.id
                                ORDER BY tara.id DESC
                            ) AS status
                        FROM trn_activity_request a
                        LEFT JOIN trn_activity_overview b ON a.id = b.activity_id
                        LEFT JOIN mst_project c ON a.project_id = c.id
                        WHERE EXISTS (
                            SELECT 1 FROM trn_activity_request_approvals ra
                            WHERE ra.activity_request_id = a.id
                            AND ra.approver_id = ?
                            AND ra.decision IN (2, 3) -- Only Approved or Rejected
                        ) ORDER BY c.project_code, a.last_modified;
                    """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, last_modified=row.last_modified, status=row.status)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_approved_completed_wip_activity_requests(user_id):
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
                            a.id,
                            c.project_code,
                            c.project_name,
                            b.subject,
                            a.last_modified,                                                
                            (
                                SELECT TOP 1
                                    CASE 
                                        WHEN tara.decision = 1 THEN 'Submitted by'
                                        WHEN tara.decision = 2 THEN 'Approved by'
                                        WHEN tara.decision = 3 THEN 'Rejected by'
                                        ELSE 'Unknown'
                                    END + ' ' + r.name
                                FROM trn_completed_wip_activity_request_approvals tara
                                LEFT JOIN workflow_breakdown wb ON tara.level = wb.level AND wb.workflow_id = @workflow_id
                                LEFT JOIN role_workflow_breakdown rwb ON wb.id = rwb.workflow_breakdown_id
                                LEFT JOIN role r ON rwb.role_id = r.id
                                WHERE tara.activity_request_id = a.id
                                ORDER BY tara.id DESC
                            ) AS status
                        FROM trn_activity_request a
                        LEFT JOIN trn_activity_overview b ON a.id = b.activity_id
                        LEFT JOIN mst_project c ON a.project_id = c.id
                        WHERE EXISTS (
                            SELECT 1 FROM trn_completed_wip_activity_request_approvals ra
                            WHERE ra.activity_request_id = a.id
                            AND ra.approver_id = ?
                            AND ra.decision IN (2, 3) -- Only Approved or Rejected
                        ) ORDER BY c.project_code, a.last_modified;
                    """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequest(id=row.id, project_code=row.project_code, project_name=row.project_name,
                                subject=row.subject, last_modified=row.last_modified, status=row.status)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_id_of_insert_into_trn_activity_log_overview_row(activity_id, key_process_id, task_id, user_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # Check if a record with the given bank_account, year, and month exists
            cursor.execute(
                "SELECT MAX(id) FROM trn_activity_log_overview WHERE activity_id=? AND "
                "key_process_id=? AND task_id=? AND user_id=?", activity_id, key_process_id,
                task_id, user_id
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
    def get_logs_list_by_activity_request_id(activity_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT talo.id, mkp.name AS key_process_name, tab.task AS task, 
                        CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) AS user_name, talo.creation_date
                        FROM trn_activity_log_overview talo
                        LEFT OUTER JOIN mst_key_process mkp ON talo.key_process_id = mkp.id
                        LEFT OUTER JOIN trn_activity_breakdown tab ON talo.activity_id = tab.activity_id 
                        AND talo.key_process_id = tab.key_process_id
                        AND talo.task_id = tab.id
                        LEFT OUTER JOIN users u ON u.ID = talo.user_id
                        WHERE talo.activity_id = ?
                        ORDER BY talo.creation_date DESC;
                    """
            cursor.execute(query, (activity_id,))
            result = cursor.fetchall()

            activity_request_details = [
                ActivityRequestLog(id=row.id, key_process_name=row.key_process_name, task=row.task,
                                   user_name=row.user_name, creation_date=row.creation_date)
                for row in result
            ]
            return activity_request_details
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_view_edit_activity_log_key_process_task(log_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()
        try:
            cursor.execute(
                """
                SELECT key_process_id, task_id FROM trn_activity_log_overview WHERE id = ?
                """,
                (log_id,)
            )
            row = cursor.fetchone()

            if not row:
                return None

            return {
                "key_process_id": row[0],
                "task_id": row[1]
            }

        except Exception as e:
            print("Failed to get key_process_id, task_id from trn_activity_log_overview table", e)
            return None
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_breakdown_details(log_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()
        try:
            query = """
                        SELECT 
                            a.start_date,
                            a.end_date,
                            a.detail,
                            ISNULL(a.credit_points, 0) AS credit_points,

                            (
                                ISNULL(
                                    (
                                        SELECT SUM(tab.credit_points)
                                        FROM trn_activity_breakdown tab
                                        WHERE tab.activity_id = b.activity_id
                                          AND tab.key_process_id = b.key_process_id
                                          AND tab.id = b.task_id
                                    ),
                                    0
                                )
                                -
                                ISNULL(
                                    (
                                        SELECT SUM(talab.credit_points)
                                        FROM trn_activity_log_activity_breakdown talab
                                        INNER JOIN trn_activity_log_overview talo
                                            ON talab.trn_activity_log_id = talo.id
                                        WHERE talo.activity_id = b.activity_id
                                          AND talo.key_process_id = b.key_process_id
                                          AND talo.task_id = b.task_id
                                    ),
                                    0
                                )
                                +
                                ISNULL(
                                    (
                                        SELECT SUM(talab.credit_points)
                                        FROM trn_activity_log_activity_breakdown talab
                                        INNER JOIN trn_activity_log_overview talo
                                            ON talab.trn_activity_log_id = talo.id
                                        WHERE talo.id = b.id
                                          AND talo.activity_id = b.activity_id
                                          AND talo.key_process_id = b.key_process_id
                                          AND talo.task_id = b.task_id
                                    ),
                                    0
                                )
                            ) AS available_credit_points

                        FROM trn_activity_log_activity_breakdown a
                        INNER JOIN trn_activity_log_overview b
                            ON a.trn_activity_log_id = b.id
                        WHERE b.id = ?
                        ORDER BY a.activity_breakdown_details_count;
                    """
            cursor.execute(query, (log_id,))
            columns = [col[0] for col in cursor.description]
            result = cursor.fetchall()
            return [dict(zip(columns, row)) for row in result]

        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_activity_log_attachments(log_id):
        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()
        try:
            cursor.execute("""
                            SELECT [id], [activity_log_id], [file], [description] 
                            FROM trn_activity_log_attachment 
                            WHERE activity_log_id = ? 
                            ORDER BY attachment_counter;
            """, (log_id,))
            rows = cursor.fetchall()

            attachments = []
            for row in rows:
                attachments.append({
                    "id": row.id,
                    "activity_log_id": row.activity_log_id,
                    "file": row.file,
                    "description": row.description
                })
            return attachments
        except Exception as e:
            print("Error fetching attachments:", e)
            return []
        finally:
            conn.close()

    @staticmethod
    def get_completed_wip_activity_requests_pending_approval(user_id):
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
                                (SELECT CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) FROM users WHERE ID = tar.user_id) 
                                AS requester,
                                tar.id AS activity_request_id, 
                                mp.project_code AS project_code, 
                                mp.project_name AS project_name, 
                                tao.subject AS subject,
                                FORMAT(tar.last_modified, 'yyyy-MM-dd HH:mm:ss') AS date_time, 
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.wip_status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tar.id ORDER BY tar.last_modified DESC) AS row_num
                            FROM trn_activity_request tar
                            JOIN trn_activity_request_approvals tara ON tar.id = tara.activity_request_id
                            JOIN mst_project mp ON tar.project_id = mp.id
                            JOIN trn_activity_overview tao ON tar.id = tao.activity_id
                            JOIN users u ON tar.user_id = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                                    WHERE b.parent_org_unit_tier_id IN (
                                        SELECT d.organisation_unit_tier_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tar.wip_status > 1 
                                AND tar.wip_status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 1
                                        AND e.ID = @logged_in_user_id
                                )
                        ),
                        OrgBasedFiles AS (
                            -- Get files where responsibility is restricted to specific organizational units
                            SELECT 
                                (SELECT CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) FROM users WHERE ID = tar.user_id) 
                                AS requester,
                                tar.id AS activity_request_id, 
                                mp.project_code AS project_code, 
                                mp.project_name AS project_name, 
                                tao.subject AS subject,
                                FORMAT(tar.last_modified, 'yyyy-MM-dd HH:mm:ss') AS date_time, 
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.wip_status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tar.id ORDER BY tar.last_modified DESC) AS row_num
                            FROM trn_activity_request tar
                            JOIN trn_activity_request_approvals tara ON tar.id = tara.activity_request_id
                            JOIN mst_project mp ON tar.project_id = mp.id
                            JOIN trn_activity_overview tao ON tar.id = tao.activity_id
                            JOIN users u ON tar.user_id = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit b ON a.organisation_unit_id = b.id
                                    WHERE b.parent_org_unit_id IN (
                                        SELECT d.organisation_unit_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tar.wip_status > 1 
                                AND tar.wip_status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 0
                                        AND e.ID = @logged_in_user_id
                                )
                        )

                        -- Combine results
                        SELECT 
                            requester, activity_request_id, project_code, project_name, subject, date_time, approve_as
                        FROM (
                            SELECT * FROM GlobalFiles WHERE row_num = 1
                            UNION
                            SELECT * FROM OrgBasedFiles WHERE row_num = 1
                        ) AS UniqueResults
                        WHERE approve_as IS NOT NULL
                        ORDER BY project_code, date_time, subject ASC;

            """
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()

            activity_requests = [
                ActivityRequestApprovals(requester=row.requester, activity_request_id=row.activity_request_id,
                                         project_code=row.project_code, project_name=row.project_name,
                                         subject=row.subject, date_time=row.date_time, approve_as=row.approve_as)
                for row in result
            ]
            return activity_requests
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    def get_submitted_and_approved_wip_activity_requests(user_id, workflow_id, is_workflow_level):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            # Fetch submitted reconciliations
            query = """
                        SELECT 
                            CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) AS requester,
                            tar.id AS activity_request_id, 
                            mp.project_code, 
                            mp.project_name, 
                            tao.subject,
                            CONVERT(VARCHAR(19), tar.last_modified, 120) AS date_time,
                            status_info.status
                        FROM trn_activity_request tar
                        
                        JOIN mst_project mp 
                            ON tar.project_id = mp.id
                        
                        JOIN trn_activity_overview tao 
                            ON tar.id = tao.activity_id
                        
                        JOIN users u 
                            ON tar.user_id = u.ID
                        
                        OUTER APPLY (
                            SELECT TOP 1 
                                CASE 
                                    WHEN ra.decision = 1 THEN 'Submitted by'
                                    WHEN ra.decision = 2 THEN 'Approved by'
                                    WHEN ra.decision = 3 THEN 'Rejected by'
                                    ELSE 'Unknown'
                                END + ' ' + r.name AS status
                            FROM trn_completed_wip_activity_request_approvals ra
                            JOIN workflow_breakdown wb 
                                ON ra.level = wb.level
                                AND wb.workflow_id = ?
                                AND wb.is_workflow_level = ?
                            JOIN role_workflow_breakdown rwb 
                                ON wb.id = rwb.workflow_breakdown_id
                            JOIN role r 
                                ON rwb.role_id = r.id
                            WHERE ra.activity_request_id = tar.id
                            ORDER BY ra.id DESC
                        ) status_info
                        
                        WHERE tar.wip_status > 1
                          AND (
                                tar.user_id = ?
                                OR EXISTS (
                                    SELECT 1
                                    FROM trn_activity_team_composition t
                                    WHERE t.activity_id = tar.id
                                      AND t.member_user_id = ?
                                )
                              );
            """
            cursor.execute(query, (workflow_id, is_workflow_level, user_id, user_id,))
            result = cursor.fetchall()

            activity_requests = [
                ActivityRequestLog(requester=row.requester, activity_request_id=row.activity_request_id,
                                         project_code=row.project_code, project_name=row.project_name,
                                         subject=row.subject, date_time=row.date_time, status_info=row.status)
                for row in result
            ]
            return activity_requests
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_completed_wip_activity_requests_pending_approval_count(user_id):
        conn = get_db_connection()
        if conn is None:
            return 0  # Return 0 if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        DECLARE @logged_in_user_id INT = ?; -- Set logged-in user's ID
                        
                        ;WITH GlobalFiles AS (
                            -- Get files where responsibility is global
                            SELECT 
                                LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name,
                                pro.project_code, 
                                pro.project_name, 
                                taro.subject,  
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.wip_status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tar.id ORDER BY tar.creation_date DESC) AS row_num
                            FROM trn_activity_request tar
                            JOIN trn_completed_wip_activity_request_approvals tcwara ON tar.id = tcwara.activity_request_id
                            JOIN mst_project pro ON tar.project_id = pro.id
                            JOIN trn_activity_overview taro ON tar.id = taro.activity_id
                            JOIN users u ON tar.user_id = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tcwara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit_tier b ON a.organisation_unit_tier_id = b.id
                                    WHERE b.parent_org_unit_tier_id IN (
                                        SELECT d.organisation_unit_tier_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tar.wip_status > 1 
                                AND tar.wip_status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 1
                                        AND e.ID = @logged_in_user_id
                                )
                        ),
                        OrgBasedFiles AS (
                            -- Get files where responsibility is restricted to specific organizational units
                            SELECT 
                                LTRIM(RTRIM(COALESCE(u.Fname + ' ' + u.Mname + ' ' + u.Sname, ''))) AS name,
                                pro.project_code, 
                                pro.project_name, 
                                taro.subject,  
                                (
                                    SELECT TOP 1 r.name 
                                    FROM role r 
                                    LEFT OUTER JOIN user_role ur ON r.id = ur.role_id
                                    LEFT OUTER JOIN role_workflow_breakdown rwb ON ur.role_id = rwb.role_id
                                    LEFT OUTER JOIN workflow_breakdown wb ON rwb.workflow_breakdown_id = wb.id
                                    WHERE 
                                        wb.is_workflow_level = 1 
                                        AND wb.level = tar.wip_status
                                        AND ur.user_id = @logged_in_user_id
                                ) AS approve_as,
                                ROW_NUMBER() OVER (PARTITION BY tar.id ORDER BY tar.creation_date DESC) AS row_num
                            FROM trn_activity_request tar
                            JOIN trn_completed_wip_activity_request_approvals tcwara ON tar.id = tcwara.activity_request_id
                            JOIN mst_project pro ON tar.project_id = pro.id
                            JOIN trn_activity_overview taro ON tar.id = taro.activity_id
                            JOIN users u ON tar.user_id = u.ID
                            JOIN user_role ur ON u.ID = ur.user_id
                            JOIN role r ON ur.role_id = r.id
                            WHERE 
                                ur.start_datetime <= GETDATE() 
                                AND ur.expiry_datetime >= GETDATE()
                                AND tcwara.approver_id IN (
                                    SELECT DISTINCT a.ID
                                    FROM users a
                                    JOIN organisation_unit b ON a.organisation_unit_id = b.id
                                    WHERE b.parent_org_unit_id IN (
                                        SELECT d.organisation_unit_id 
                                        FROM users d 
                                        WHERE d.ID = @logged_in_user_id
                                    )
                                )
                                AND tar.wip_status > 1
                                AND tar.wip_status IN (
                                    SELECT DISTINCT a.level
                                    FROM workflow_breakdown a
                                    JOIN role_workflow_breakdown b ON a.id = b.workflow_breakdown_id
                                    JOIN role c ON b.role_id = c.id
                                    JOIN user_role d ON c.id = d.role_id
                                    JOIN users e ON d.user_id = e.ID
                                    WHERE 
                                        a.is_responsibility_global = 0
                                        AND e.ID = @logged_in_user_id
                                )
                        )
                        -- name, project_code, project_name, subject

                        SELECT COUNT(*) AS total_count
                        FROM (
                            SELECT 
                                name, project_code, project_name, subject, approve_as
                            FROM (
                                SELECT * FROM GlobalFiles WHERE row_num = 1
                                UNION
                                SELECT * FROM OrgBasedFiles WHERE row_num = 1
                            ) AS UniqueResults
                            WHERE approve_as IS NOT NULL
                        ) AS CountResults;
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
    def get_latest_completed_wip_activity_request_approval_level(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # check if User has a request pending submission
            cursor.execute("SELECT COALESCE((SELECT TOP 1 level FROM trn_completed_wip_activity_request_approvals "
                           "WHERE activity_request_id = ? ORDER BY date_time DESC), 0) AS level;", activity_request_id)

            latest_approval_level = cursor.fetchone()[0]  # Fetch last batch_id
            return latest_approval_level
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_wip_status_of_activity_request(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            # Check if a record with the given bank_account, year, and month exists
            cursor.execute(
                "SELECT wip_status FROM trn_activity_request WHERE id = ?", activity_request_id
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
    def get_completed_wip_activity_requests_pending_submission(user_id):
        conn = get_db_connection()
        if conn is None:
            return 0  # Return 0 if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                        SELECT COUNT(*)
                        FROM trn_activity_request a
                        WHERE a.wip_status = 1
                          AND (
                                a.user_id = ?
                                OR EXISTS (
                                    SELECT 1
                                    FROM trn_activity_team_composition t
                                    WHERE t.activity_id = a.id
                                      AND t.member_user_id = ?
                                )
                              );
            """
            cursor.execute(query, [user_id, user_id])
            pending_submissions_count = cursor.fetchone()[0]
            return pending_submissions_count if pending_submissions_count is not None else 0
        except Exception as e:
            print("Database error:", e)
            return 0
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_completed_wip_activity_request_approval_levels(activity_request_id):
        conn = get_db_connection()
        if conn is None:
            return []  # Return empty list if the database connection fails

        cursor = conn.cursor()

        try:
            query = """
                           SELECT tara.level, CASE WHEN tara.decision = 1 
                           THEN 'Submitted' WHEN tara.decision = 2 THEN 'Approved' WHEN tara.decision = 3 
                           THEN 'Rejected' 
                           ELSE 'Pending' 
                           END AS decision,
                           CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) AS approver, tara.date_time, tara.comment 
                           FROM trn_completed_wip_activity_request_approvals tara
                           LEFT OUTER JOIN users u ON tara.approver_id = u.ID
                           WHERE tara.activity_request_id = ? ORDER BY tara.date_time
                       """
            cursor.execute(query, (activity_request_id,))  # Pass the parameter twice
            result = cursor.fetchall()  # Fetch results properly

            return result if result else []
        except Exception as e:
            print("Database error:", e)
            return []
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_completed_wip_logs(activity_id):

        conn = get_db_connection()
        if conn is None:
            return []

        cursor = conn.cursor()

        try:
            query = """
                SELECT 
                    a.id AS activity_log_id,
                    CONCAT(u.Fname, ' ', u.Mname, ' ', u.Sname) AS team_member,
                    a.creation_date,
                    d.task,
                    e.start_date,
                    e.end_date,
                    COALESCE(e.detail,'') AS detail,
                    COALESCE(STRING_AGG(f.[file], ', '), '') AS files
                FROM trn_activity_log_overview a
                LEFT JOIN users u ON u.ID = a.user_id
                LEFT JOIN trn_activity_breakdown d 
                       ON d.id = a.task_id 
                      AND d.activity_id = a.activity_id
                LEFT JOIN trn_activity_log_activity_breakdown e 
                       ON e.trn_activity_log_id = a.id
                LEFT JOIN trn_activity_log_attachment f 
                       ON f.activity_log_id = a.id
                WHERE a.activity_id = ?
                GROUP BY 
                    a.id,
                    u.Fname, u.Mname, u.Sname,
                    a.creation_date,
                    d.task,
                    e.start_date,
                    e.end_date,
                    e.detail
                ORDER BY a.id
            """

            cursor.execute(query, (activity_id,))
            columns = [column[0] for column in cursor.description]
            rows = [dict(zip(columns, row)) for row in cursor.fetchall()]

            grouped = defaultdict(list)

            for row in rows:
                grouped[row["activity_log_id"]].append(row)

            logs = []

            for log_id, items in grouped.items():
                logs.append({
                    "activity_log_id": log_id,
                    "team_member": items[0]["team_member"],
                    "creation_date": items[0]["creation_date"].strftime('%d %b %Y %H:%M')
                    if items[0]["creation_date"] else "",
                    "task": items[0]["task"],
                    "files": items[0]["files"],
                    "row_count": len(items),
                    "breakdowns": [
                        {
                            "start_date": i["start_date"].strftime('%d %b %Y')
                            if i["start_date"] else "",
                            "end_date": i["end_date"].strftime('%d %b %Y')
                            if i["end_date"] else "",
                            "detail": i["detail"]
                        }
                        for i in items
                    ]
                })

            return logs

        except Exception as e:
            print("Database error:", e)
            return []

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_log_overview_count(activity_id):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM trn_activity_log_overview WHERE activity_id = ?"
            cursor.execute(query, (activity_id,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to pick count from trn_activity_log_overview: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def get_is_user_requester_of_activity(activity_id, user_id):
        conn = get_db_connection()
        if conn is None:
            return False  # Assume doesn't exist if DB is unreachable

        cursor = conn.cursor()

        try:
            query = "SELECT COUNT(*) FROM trn_activity_request WHERE id = ? AND user_id = ?"
            cursor.execute(query, (activity_id, user_id,))
            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print("Database error; failed to pick count from trn_activity_log_overview: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_activity_log_id_of_trn_activity_log_attachment(old_activity_log_id, new_activity_log_id):
        conn = get_db_connection()
        if conn is None:
            return False

        cursor = conn.cursor()

        try:
            query = """
                UPDATE trn_activity_log_attachment
                SET activity_log_id = ?
                WHERE activity_log_id = ?
            """
            cursor.execute(query, (new_activity_log_id, old_activity_log_id))
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(
                "Database error; failed to update trn_activity_log_attachment:",
                e
            )
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_completed_wip_activity_request_approval_wip_status(activity_request_id, action, workflow_id):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            if action == "reject":
                query = """
                    UPDATE trn_activity_request
                    SET wip_status = 1
                    WHERE id = ?;
                """
                cursor.execute(query, (activity_request_id,))

            else:
                query = """                    
                    UPDATE trn_activity_request
                    SET 
                        wip_status = wip_status + 1,  
                        wip_approval_complete = CASE 
                            WHEN wip_status = (
                                SELECT MAX(wb.level)
                                FROM workflow wf
                                LEFT JOIN workflow_breakdown wb 
                                    ON wf.id = wb.workflow_id
                                WHERE wf.id = ?
                            ) 
                            THEN 1
                            ELSE 0
                        END                      
                    WHERE id = ?;
                """
                cursor.execute(query, (workflow_id, activity_request_id))

            conn.commit()
            return True
        except Exception as e:
            print(f"Error updating wip_status of trn_activity_request record: {e}")
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def update_completed_wip_activity_request_approval_status_following_a_rejected_approval(activity_request_id):

        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            query = """
                UPDATE trn_activity_request
                SET wip_status = 1
                WHERE id = ?
            """
            file_upload_id = cursor.execute(query, activity_request_id)
            conn.commit()
            return activity_request_id
        except Exception as e:
            print(f"Error updating status of trn_activity_request following a rejected completed wip activity "
                  f"approval request: {e}")

        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def submit_wip_activity_for_approval(activity_task_request_id):
        conn = get_db_connection()
        if conn is None:
            return False

        cursor = conn.cursor()

        try:
            query = """
                UPDATE trn_activity_request
                SET wip_status = 2
                WHERE id = ?
            """
            cursor.execute(query, activity_task_request_id)
            conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(
                "Database error; failed to update table: trn_activity_request:",
                e
            )
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def insert_into_trn_activity_log_overview(activity_id, key_process_id, task_id, user_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()
        now = datetime.now()

        try:
            cursor.execute(
                """
                    INSERT INTO trn_activity_log_overview (activity_id, key_process_id, task_id, creation_date, user_id)
                    VALUES (?, ?, ?, ?, ?)
                """,
                (activity_id, key_process_id, task_id, now, user_id),
            )
            conn.commit()
            return activity_id
        except pyodbc.Error as e:
            print("Could not insert into table: trn_activity_log_overview:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def insert_into_trn_activity_log_activity_breakdown(activity_breakdown_count, trn_activity_log_id, start_date, end_Date, activity_breakdown_detail, credit_points_requested):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            cursor.execute(
                """
                    INSERT INTO 
                        trn_activity_log_activity_breakdown 
                            (activity_breakdown_details_count, 
                            trn_activity_log_id, 
                            start_date, 
                            end_date, 
                            detail, 
                            credit_points)
                    VALUES 
                        (?, ?, ?, ?, ?, ?)
                """,
                (activity_breakdown_count, trn_activity_log_id, start_date, end_Date, activity_breakdown_detail, credit_points_requested),
            )
            conn.commit()
            return activity_breakdown_count
        except pyodbc.Error as e:
            print("Could not insert into table: trn_activity_log_activity_breakdown:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def insert_into_trn_activity_log_attachment(attachment_counter, trn_activity_log_id, file, description):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        try:
            cursor.execute(
                "INSERT INTO trn_activity_log_attachment ([attachment_counter], [activity_log_id], [file], "
                "[description]) VALUES (?, ?, ?, ?)",
                (attachment_counter, trn_activity_log_id, file, description),
            )
            conn.commit()
            return id
        except pyodbc.Error as e:
            print("Database insert error:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def insert_into_trn_completed_wip_activity_request_approvals(activity_request_id, decision, approver_id, level, comment):
        conn = get_db_connection()
        if conn is None:
            return None  # Handle database connection failure

        cursor = conn.cursor()

        now = datetime.now()

        try:

            cursor.execute(
                "INSERT INTO trn_completed_wip_activity_request_approvals (activity_request_id, decision, "
                "approver_id, level, comment, date_time) VALUES (?, ?, ?, ?, ?, ?)",
                (activity_request_id, decision, approver_id, level, comment, now),
            )
            conn.commit()
            return activity_request_id
        except pyodbc.Error as e:
            print("Database insert error:", e)
            conn.rollback()
            return None
        finally:
            conn.close()

    @staticmethod
    def delete_trn_activity_log_overview(activity_log_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                DELETE FROM trn_activity_log_overview                
                WHERE id = ?
            """
            cursor.execute(query, activity_log_id)
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to delete from trn_activity_log_overview: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_trn_activity_log_activity_breakdown(activity_log_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                DELETE FROM trn_activity_log_activity_breakdown                
                WHERE trn_activity_log_id = ?
            """
            cursor.execute(query, activity_log_id)
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to delete from trn_activity_log_activity_breakdown: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_trn_activity_log_attachment(activity_log_id):
        conn = get_db_connection()
        if conn is None:
            return None

        cursor = conn.cursor()

        try:
            query = """
                DELETE FROM trn_activity_log_attachment                
                WHERE activity_log_id = ?
            """
            cursor.execute(query, activity_log_id)
            conn.commit()
            return True
        except Exception as e:
            print("Database error; failed to delete from trn_activity_log_attachment: ", e)
            return False
        finally:
            cursor.close()
            conn.close()

    @staticmethod
    def delete_attachments_except(activity_log_id, retained_ids):

        conn = get_db_connection()
        if conn is None:
            return False

        cursor = conn.cursor()

        try:
            # Case 1: No retained attachments → delete all
            if not retained_ids:
                query = """
                    DELETE FROM trn_activity_log_attachment
                    WHERE activity_log_id = ?
                """
                cursor.execute(query, (activity_log_id,))
                conn.commit()
                return True

            # Case 2: Delete everything except retained IDs
            placeholders = ",".join("?" for _ in retained_ids)

            query = f"""
                DELETE FROM trn_activity_log_attachment
                WHERE activity_log_id = ?
                AND id NOT IN ({placeholders})
            """

            params = [activity_log_id] + list(retained_ids)

            cursor.execute(query, params)
            conn.commit()
            return True

        except Exception as e:
            conn.rollback()
            print(
                "Database error; failed to delete from trn_activity_log_attachment:",
                e
            )
            return False

        finally:
            cursor.close()
            conn.close()
