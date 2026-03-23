from ActivityTracker import app, os, allowed_file
from ActivityTracker.models import (User, FileUploadBatch, FileUpload, FileDelete, BankAccount,
                                    ReconciliationApprovals, WorkflowBreakdown, EmailHelper, Audit, UserSummary,
                                    Role, UserRole, Currency, BankAccountResponsibleUser, OrganisationUnitTier,
                                    OrganisationUnit, Workflow, Project, MenuItem, ActivityRequest,
                                    ActivityRequestApprovals, ActivityRequestLog, TeamMemberRole, KeyProcess)
from ActivityTracker.forms import LoginForm
from flask import render_template, redirect, url_for, flash, request, jsonify, session, send_from_directory, abort
import re
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime
from ActivityTracker.rbac import role_required
import json
import threading
from ActivityTracker import app


@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login_page():
    form = LoginForm()

    if form.validate_on_submit():
        attempted_user = User.get_by_username(form.username.data)

        # Case 1: User not found (invalid username)
        if attempted_user is None:
            Audit.log_audit_trail(
                user_id=None,
                action="User Login Failed",
                details=f"Login failed: username '{form.username.data}' not found",
                ip_address=request.remote_addr
            )
            flash('Username and/or Password is incorrect. Please try again!', category='danger')

        # Case 2: User found but password incorrect
        elif not attempted_user.check_password(form.password.data):
            Audit.log_audit_trail(
                user_id=attempted_user.id,
                action="User Login Failed",
                details=f"Login failed: incorrect password for username '{form.username.data}'",
                ip_address=request.remote_addr
            )
            flash('Username and/or Password is incorrect. Please try again!', category='danger')

        # Case 3: User found but account is inactive
        elif attempted_user.is_activated == 0:
            Audit.log_audit_trail(
                user_id=attempted_user.id,
                action="User Login Denied",
                details=f"Login denied: inactive account for username '{form.username.data}'",
                ip_address=request.remote_addr
            )
            flash('Your account is disabled. Please contact the System Administrator for assistance.',
                  category='danger')

        # Case 4: Successful login
        else:
            session.permanent = True
            login_user(attempted_user)
            flash('You are logged in!', category='success')

            Audit.log_audit_trail(
                user_id=attempted_user.id,
                action="User Login",
                details=f"Login successful for username '{form.username.data}'",
                ip_address=request.remote_addr
            )

            return redirect(url_for('dashboard_page'))

    return render_template('login.html', form=form)


@app.route('/home', methods=['GET', 'POST'])
@login_required
def home_page():
    if not current_user.is_authenticated:
        return redirect(url_for("login_page"))  # Redirect if user is not authenticated

    all_projects_details = Project.get_projects_details()

    return render_template('home.html', all_projects_details=all_projects_details)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard_page():
    if not current_user.is_authenticated:
        return redirect(url_for("login_page"))

    # Get project from query parameters
    project_id = request.args.get('project_id')
    project_name = request.args.get('project_name')
    project_code = request.args.get('project_code')

    # Store in session
    if project_id and project_name and project_code:
        session['selected_project'] = {
            'id': project_id,
            'name': project_name,
            'code': project_code
        }

    return render_template('dashboard.html')


@app.route('/activity-request', methods=['GET', 'POST'])
@login_required
@role_required(1, 25)
# hint: "@role_required" refers to id of workflow_breakdown database table
def activity_request_page():
    user_details = UserSummary.get_all_usersnames()
    project_details = Project.get_projects_details()
    team_member_details = ActivityRequest.get_team_member_roles_details()
    key_process_details = ActivityRequest.get_key_process_details()
    activity_request_details = ActivityRequest.get_saved_activity_request_details(1, current_user.id)

    return render_template('activity_request.html', project_details=project_details,
                           user_details=user_details, team_member_details=team_member_details,
                           key_process_details=key_process_details, activity_request_details=activity_request_details)


@app.route("/get-saved-activity-request-details", methods=["GET"])
def get_saved_activity_request_details():
    activity_request_id = request.args.get("activity_request_id")
    saved_activity_request_details_2 = ActivityRequest.get_saved_activity_request_details_2(activity_request_id)

    if not saved_activity_request_details_2:
        return jsonify({"error": "Activity Request ID not found"}), 404

    saved_activity_request_detail = saved_activity_request_details_2[0]

    # Serialize manually
    saved_activity_request_data = {
        "id": saved_activity_request_detail.id,
        "project_code": saved_activity_request_detail.project_code,
        "subject": saved_activity_request_detail.subject,
        "objectives": saved_activity_request_detail.objectives,
        "scope": saved_activity_request_detail.scope,
        "stakeholders": saved_activity_request_detail.stakeholders,
        "deliverables": saved_activity_request_detail.deliverables,
        "assumptions": saved_activity_request_detail.assumptions
    }

    return jsonify(saved_activity_request_data)


@app.route("/delete-saved-activity-request-details", methods=["POST"])
@login_required
def delete_saved_activity_request_details():
    activity_request_id = request.form.get("activity_request_id")

    if not activity_request_id:
        return jsonify({"message": "Invalid activity ID."}), 400

    # Delete related records
    ActivityRequest.delete_activity_request(activity_request_id)
    ActivityRequest.delete_activity_overview(activity_request_id)
    ActivityRequest.delete_activity_team(activity_request_id)
    ActivityRequest.delete_activity_tasks(activity_request_id)
    ActivityRequest.delete_activity_attachments(activity_request_id)

    return jsonify({"message": "Activity request deleted successfully."}), 200


@app.route("/get-activity-team-composition-details", methods=["GET"])
def get_activity_team_composition_details():
    activity_request_id = request.args.get("activity_request_id", type=int)

    if not activity_request_id:
        return jsonify({"error": "Missing activity_request_id"}), 400

    team = ActivityRequest.get_team_composition_details(activity_request_id)

    return jsonify({"team": team})


@app.route("/get-view-edit-activity-log-key-process-task/<int:log_id>", methods=["GET"])
def get_view_edit_activity_log_key_process_task(log_id):

    result = ActivityRequestLog.get_view_edit_activity_log_key_process_task(log_id)

    if not result:
        return jsonify({"error": "Activity log not found"}), 404

    return jsonify(result), 200


@app.route("/get-activity-tasks-details", methods=["GET"])
def get_activity_tasks_details():
    activity_request_id = request.args.get("activity_request_id", type=int)

    if not activity_request_id:
        return jsonify({"error": "Missing activity_request_id"}), 400

    tasks = ActivityRequest.get_activity_tasks_details(activity_request_id)

    return jsonify({"tasks": tasks})


@app.route("/get-activity-breakdown-details", methods=["GET"])
def get_activity_breakdown_details():
    log_id = request.args.get("log_id", type=int)

    if not log_id:
        return jsonify({"error": "Missing log_id"}), 400

    activity_breakdown_details = ActivityRequestLog.get_activity_breakdown_details(log_id)

    return jsonify({"activity_breakdown_details": activity_breakdown_details})


@app.route('/get-activity-attachments', methods=['GET'])
@login_required
def get_activity_attachments():
    activity_id = request.args.get('activity_request_id')

    if not activity_id:
        return jsonify({"error": "Missing activity_request_id"}), 400

    try:
        attachments = ActivityRequest.get_activity_attachments(activity_id)
        return jsonify({"attachments": attachments})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/get-activity-log-attachments', methods=['GET'])
@login_required
def get_activity_log_attachments():
    log_id = request.args.get('log_id')

    if not log_id:
        return jsonify({"error": "Missing log_id"}), 400

    try:
        attachments = ActivityRequestLog.get_activity_log_attachments(log_id)
        return jsonify({"attachments": attachments})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/upload', methods=['POST'])
@login_required
def upload_files():
    if 'files' not in request.files:
        return jsonify({"error": "No file selected for upload"}), 400

    files = request.files.getlist('files')
    duplicate_rows = []  # Store rows that have duplicates

    num_of_pending_batches = FileUploadBatch.get_count_of_batch_pending_submission_by_user(current_user.id)

    if num_of_pending_batches == 0:
        new_batch_id = FileUploadBatch.allocate_batch_id()
        new_batch_row = FileUploadBatch.insert_into_file_upload_batch(current_user.id, new_batch_id)
        if new_batch_row is None:
            return jsonify({"error": "Database error while creating batch file upload"}), 500
    else:
        new_batch_id = FileUploadBatch.get_latest_batch_pending_submission_by_user(current_user.id)

    for i, file in enumerate(files):
        if file.filename == '':
            continue

        bank_account = request.form.getlist("bank_account")[i]
        year = request.form.getlist("year")[i]
        month = request.form.getlist("month")[i]

        # Check for duplicate entry
        exists = FileUpload.check_for_already_existing_reconciliation(bank_account, year, month)
        if exists:
            duplicate_rows.append(i)  # Add the index of duplicate row
            continue  # Skip saving this file

        if file and allowed_file(file.filename):
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            filename = secure_filename(file.filename)
            new_filename = f"{timestamp}_{current_user.id}_{filename}"
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
            file.save(file_path)

            new_file_id = FileUpload.insert_into_file_upload(new_batch_id, new_filename, bank_account, year, month)
            user_id = current_user.id
            username = current_user.username
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert in table: file_upload",
                details=f"Reconciliation File Upload, Batch ID: '{username}', Bank Account: '{bank_account}',"
                        f" Year: '{year}', Month: '{month}', File Name: '{new_filename}'",
                ip_address=request.remote_addr
            )
            if new_file_id is None:
                return jsonify({"error": "Database error while adding uploaded file"}), 500

    # Fetch updated uploaded files
    uploaded_files = FileUpload.get_uploaded_pending_submission_files_by_user(current_user.id)

    response_data = {"files": uploaded_files}

    if duplicate_rows:
        response_data["duplicates"] = duplicate_rows  # Include duplicates in response
        response_data["message"] = "Some files were not uploaded because their details already exist in the database."

    if uploaded_files:
        response_data["message"] = "Files uploaded successfully!"

    return jsonify(response_data), 200


@app.route('/update-uploaded-file', methods=['POST'])
@login_required
def update_uploaded_file():
    file = request.files.get("file")
    bank_account = request.form.get("bank_account")
    year = request.form.get("year")
    month = request.form.get("month")

    if not file or file.filename.strip() == "":
        return jsonify({"error": "No file selected."}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "File type not allowed."}), 400

    # Find the existing file entry
    existing = FileUpload.get_id_of_file_upload_2(bank_account, year, month)
    if not existing:
        return jsonify({"error": "Original file not found."}), 404

    try:
        # Optionally delete the old file (if stored on disk)
        old_filepath = os.path.join(app.config['UPLOAD_FOLDER'], existing.file_name)
        if os.path.exists(old_filepath):
            os.remove(old_filepath)

        # Save new file
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        filename = secure_filename(file.filename)
        new_filename = f"{timestamp}_{current_user.id}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
        file.save(file_path)

        # Update DB
        FileUpload.update_file_name(existing.id, new_filename)
        # update audit trail
        user_id = current_user.id
        Audit.log_audit_trail(
            user_id=user_id,
            action="Update table: file_upload",
            details=f"Reconciliation File Change, Previous File Name: '{existing.file_name}', "
                    f"New File Name: '{new_filename}'",
            ip_address=request.remote_addr
        )
        return jsonify({"message": "File updated successfully."}), 200

    except Exception as e:
        print(f"Error updating uploaded file: {e}")
        return jsonify({"error": "An internal server error occurred."}), 500


@app.route('/delete-file', methods=['POST'])
@login_required
def delete_file():
    data = request.get_json()
    filename = data.get('filename').strip()

    if not filename:
        return jsonify({"error": "Filename not provided"}), 400

    # Update the file_upload table, set removed_by_user_on_upload_page column to 1 for corresponding file name of
    # file removed by user
    new_uploaded_file_name = FileDelete.remove_file_by_user_on_upload_page(filename)
    # update audit trail
    user_id = current_user.id
    Audit.log_audit_trail(
        user_id=user_id,
        action="Update table: file_upload",
        details=f"Reconciliation File Deletion, File Name: '{filename}'",
        ip_address=request.remote_addr
    )
    if new_uploaded_file_name is None:
        return jsonify({"error": "Database error while updating status of file removed by User"}), 500

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    # Remove file from the server
    if os.path.exists(file_path):
        os.remove(file_path)
        return jsonify({"message": f"File '{filename}' deleted successfully!"}), 200
    else:
        return jsonify({"error": "File not found"}), 404


@app.route('/get-uploaded-files', methods=['GET'])
@login_required
def get_uploaded_files():
    # Fetch uploaded files for the current user
    uploaded_files = FileUpload.get_uploaded_pending_submission_files_by_user(current_user.id)

    if uploaded_files is None:
        return jsonify({"error": "Database error while fetching uploaded files"}), 500

    return jsonify({"files": uploaded_files}), 200


@app.route('/save_activity_request', methods=['POST'])
@login_required
@role_required(1, 25)
def save_activity_request():
    try:
        data = json.loads(request.form.get("data", "{}"))

        # Get mode (1 = Save, 2 = Submit)
        activity_mode = data.get("activity_mode", 1)

        # Determine status based on mode
        status = 1 if activity_mode == 1 else 2

        overview = data.get("overview", {})
        team = data.get("team", [])
        tasks = data.get("tasks", [])

        # Pick latest level of reconciliation file from reconciliation_approvals table
        latest_activity_request_id = (ActivityRequest.get_latest_activity_request_id())
        if latest_activity_request_id is None:
            return jsonify({"error": "Database error while getting latest_activity_request_id from "
                                     "trn_activity_request table"}), 500

        # reconciliation_approvals table
        current_request_id = latest_activity_request_id + 1

        # # pick id of selected project
        # project = session.get("selected_project")
        # project_id = project.get("id") if project else None
        #
        # if not project_id:
        #     return "No project selected", 400

        # Save Activity Request
        activity_id = ActivityRequest.insert_into_trn_activity_request(
            current_request_id=current_request_id,
            user_id=current_user.id,
            status=status,
            project_id=overview.get("project_id")
        )
        Audit.log_audit_trail(
            user_id=current_user.id,
            action="Insert in table: trn_activity_request",
            details=f"Saved Activity Request ID: '{current_request_id}'",
            ip_address=request.remote_addr
        )
        if not activity_id:
            return jsonify({"error": "Database error while saving activity request", "type": "danger"}), 500

        # Save in trn_activity_request_approvals
        if activity_mode == 2:
            decision = 1
            level = 1
            comment = ""

            last_activity_request_approvals_id = (ActivityRequestApprovals.insert_into_trn_activity_request_approvals
                                                  (current_request_id, decision, current_user.id, level, comment))
            if last_activity_request_approvals_id is None:
                return jsonify(
                    {"error": "Database error while writing to trn_activity_request_approvals table",
                     "type": "danger"}), 500

            Audit.log_audit_trail(
                user_id=current_user.id,
                action="Insert in table: trn_activity_request_approvals",
                details=f"Saved Activity Request ID: '{current_request_id}'",
                ip_address=request.remote_addr
            )
            if not activity_id:
                return jsonify({"error": "Database error while saving activity request in "
                                         "trn_activity_request_approvals table", "type": "danger"}), 500

        # Save Activity Overview
        activity_id = ActivityRequest.insert_into_trn_activity_overview(
            current_request_id=current_request_id,
            subject=overview.get("subject"),
            objectives=overview.get("objectives"),
            scope=overview.get("scope"),
            stakeholders=overview.get("stakeholders"),
            deliverables=overview.get("deliverables"),
            assumptions=overview.get("assumptions"),
        )
        Audit.log_audit_trail(
            user_id=current_user.id,
            action="Insert in table: trn_activity_overview",
            details=f"Saved Activity Request ID: '{current_request_id}'",
            ip_address=request.remote_addr
        )
        if not activity_id:
            return jsonify({"error": "Database error while saving activity request", "type": "danger"}), 500

        # Save team members into trn_activity_team
        team_member_no = 1

        for member in team:
            team_saved = ActivityRequest.insert_into_trn_activity_team_composition(
                team_member_no=team_member_no,
                activity_id=current_request_id,
                member_id=member.get("member_id"),
                role_id=member.get("role_id")
            )
            Audit.log_audit_trail(
                user_id=current_user.id,
                action="Insert in table: trn_activity_team_composition",
                details=f"Saved Activity Request ID: '{current_request_id}', Team Member Num: "
                        f"'{member.get('member_id')}', Role ID: '{member.get('role_id')}'",
                ip_address=request.remote_addr
            )
            if not team_saved:
                return jsonify({"error": "Error saving team member", "type": "danger"}), 500

            team_member_no += 1

        # Save team members into trn_activity_team
        task_no = 1

        for task in tasks:
            team_saved = ActivityRequest.insert_into_trn_activity_breakdown(
                task_no=task_no,
                activity_id=current_request_id,
                task=task.get("task"),
                key_process_id=task.get("key_process"),
                start_date=task.get("start_date"),
                end_date=task.get("end_date"),
            )
            Audit.log_audit_trail(
                user_id=current_user.id,
                action="Insert in table: trn_activity_breakdown",
                details=f"Saved Activity Request ID: '{current_request_id}', Task Num: '{team_saved}'",
                ip_address=request.remote_addr
            )
            if not team_saved:
                return jsonify({"error": "Error saving activity task", "type": "danger"}), 500

            task_no += 1

        # Save attachments
        files = request.files.getlist("attachments")  # <-- from request.files
        descriptions = request.form.getlist("attachment_descriptions")  # <-- from form fields

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        attachment_counter = 1

        upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'activity_docs')
        os.makedirs(upload_folder, exist_ok=True)

        for file, desc in zip(files, descriptions):
            if file and file.filename:
                filename = secure_filename(file.filename)
                new_filename = f"{timestamp}_{current_user.id}_{attachment_counter}_{filename}"
                file.save(os.path.join(upload_folder, new_filename))

                attachment_saved = ActivityRequest.insert_into_trn_activity_attachment(
                    id=attachment_counter,
                    activity_id=current_request_id,
                    file=new_filename,
                    description=desc
                )

                Audit.log_audit_trail(
                    user_id=current_user.id,
                    action="Insert in table: trn_activity_attachment",
                    details=f"Saved file '{new_filename}' for Activity Request ID: '{current_request_id}'",
                    ip_address=request.remote_addr
                )
                if not attachment_saved:
                    return jsonify({"error": "Error saving attachment", "type": "danger"}), 500

                attachment_counter += 1

        # --- Dynamic message based on status ---
        if status == 1:
            message = "Activity Request saved successfully"

        elif status == 2:
            try:
                user_fname = current_user.fname
                user_id = current_user.id

                activity_request_status = ActivityRequestApprovals.get_status_of_activity_request(current_request_id)

                activity_request_details_for_email_table = (
                    ActivityRequest.get_saved_activity_request_details_3(current_request_id))

                # Get next approver(s)
                next_approvers = (ActivityRequestApprovals.get_next_approver_fname_email
                                  (user_id, activity_request_status))

                if not next_approvers:
                    return jsonify({"error": "No next approver found"}), 500

                # Send emails in the background with app context
                def send_emails():
                    with app.app_context():  # Ensure Flask app context is available in the thread
                        for approver in next_approvers:
                            EmailHelper.send_submitted_activity_request_email(
                                user_fname, approver["Email"], approver["Fname"],
                                activity_request_details_for_email_table)

                email_thread = threading.Thread(target=send_emails)
                email_thread.start()

                message = "Activity Request submitted successfully"

            except Exception as e:
                return jsonify({"error": str(e), "type": "danger"}), 500

        else:
            message = "Activity Request processed successfully"

        return jsonify({"message": message}), 200

    except Exception as e:
        return jsonify({"error": str(e), "type": "danger"}), 500


@app.route('/save_activity_request_log', methods=['POST'])
@login_required
@role_required(1, 25, 59, 69, 70, 71)
def save_activity_request_log():
    try:
        data = json.loads(request.form.get("data", "{}"))

        overview = data.get("overview", {})
        activity_id = overview.get("activity_task_id")
        key_process_id = overview.get("key_process_id")
        task_id = overview.get("task_id")
        user_id = current_user.id

        # Save Activity Request
        activity_id = ActivityRequestLog.insert_into_trn_activity_log_overview(
            activity_id, key_process_id, task_id, user_id
        )
        Audit.log_audit_trail(
            user_id=current_user.id,
            action="Insert in table: trn_activity_log_overview",
            details=f"Saved Activity Request ID: '{activity_id}'; Key Process ID: '{key_process_id}'; Task ID: '{task_id}'",
            ip_address=request.remote_addr
        )

        if not activity_id:
            return jsonify({"error": "Database error while saving activity request log", "type": "danger"}), 500

        # Pick id of insert_into_trn_activity_log_overview row
        trn_activity_log_id = ActivityRequestLog.get_id_of_insert_into_trn_activity_log_overview_row(
            activity_id, key_process_id, task_id, user_id
        )

        # Save activity breakdown details into trn_activity_log_activity_breakdown
        activity_breakdown = data.get("activityBreakdown", [])

        activity_breakdown_count = 1

        for breakdown in activity_breakdown:
            start_date = breakdown.get("start_date")
            end_date = breakdown.get("end_date")
            activity_breakdown_detail = breakdown.get("activityBreakdownDetail")

            activity_breakdown_saved = ActivityRequestLog.insert_into_trn_activity_log_activity_breakdown(
                activity_breakdown_count=activity_breakdown_count,
                trn_activity_log_id=trn_activity_log_id,
                start_date=start_date,
                end_Date=end_date,
                activity_breakdown_detail=activity_breakdown_detail
            )

            Audit.log_audit_trail(
                user_id=current_user.id,
                action="Insert in table: trn_activity_log_activity_breakdown",
                details=f"Saved Activity Log ID: '{trn_activity_log_id}', "
                        f"Activity Breakdown Count: '{activity_breakdown_count}'",
                ip_address=request.remote_addr
            )

            if not activity_breakdown_saved:
                return jsonify({
                    "error": "Error saving activity breakdown",
                    "type": "danger"
                }), 500

            activity_breakdown_count += 1

        # Save attachments
        files = request.files.getlist("wip_attachments")  # <-- from request.files
        descriptions = request.form.getlist("wip_attachment_descriptions")  # <-- from form fields

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        attachment_counter = 1

        upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'activity_log_docs')
        os.makedirs(upload_folder, exist_ok=True)

        for file, desc in zip(files, descriptions):
            if file and file.filename:
                filename = secure_filename(file.filename)
                new_filename = f"{timestamp}_{current_user.id}_{attachment_counter}_{filename}"
                file.save(os.path.join(upload_folder, new_filename))

                attachment_saved = ActivityRequestLog.insert_into_trn_activity_log_attachment(
                    attachment_counter=attachment_counter,
                    trn_activity_log_id=trn_activity_log_id,
                    file=new_filename,
                    description=desc
                )

                Audit.log_audit_trail(
                    user_id=current_user.id,
                    action="Insert in table: trn_activity_attachment",
                    details=f"Saved file '{new_filename}' for Activity Log ID: '{trn_activity_log_id}'",
                    ip_address=request.remote_addr
                )
                if not attachment_saved:
                    return jsonify({"error": "Error saving attachment", "type": "danger"}), 500

                attachment_counter += 1

        else:
            message = "Activity Request Log processed successfully"

        return jsonify({"message": message}), 200

    except Exception as e:
        return jsonify({"error": str(e), "type": "danger"}), 500


@app.route("/edit_activity_request_log", methods=["POST"])
@login_required
@role_required(1, 25)
def edit_activity_request_log():

    try:
        # ----------------------------------
        # 1️⃣ Read request data
        # ----------------------------------
        activity_log_id = request.form.get("activity_log_id")
        data = json.loads(request.form.get("data", "{}"))

        retained_ids = json.loads(request.form.get("retained_attachment_ids", "[]"))

        overview = data.get("overview", {})
        activity_breakdown = data.get("activityBreakdown", [])

        if not activity_log_id or not overview:
            return jsonify({"error": "Invalid request data.", "type": "danger"}), 400

        activity_id = overview.get("activity_task_id")
        key_process_id = overview.get("key_process_id")
        task_id = overview.get("task_id")
        user_id = current_user.id

        # ----------------------------------
        # 2️⃣ DELETE + REINSERT (safe tables)
        # ----------------------------------
        ActivityRequestLog.delete_trn_activity_log_overview(activity_log_id)
        ActivityRequestLog.delete_trn_activity_log_activity_breakdown(activity_log_id)

        # ⚠️ OPTION A: attachments
        ActivityRequestLog.delete_attachments_except(
            activity_log_id,
            retained_ids
        )

        # ----------------------------------
        # 3️⃣ Re-insert overview
        # ----------------------------------
        ActivityRequestLog.insert_into_trn_activity_log_overview(
            activity_id,
            key_process_id,
            task_id,
            user_id
        )

        Audit.log_audit_trail(
            user_id=user_id,
            action="Edit: trn_activity_log_overview",
            details=(
                f"Edited Activity Log ID: '{activity_log_id}'; "
                f"Key Process ID: '{key_process_id}'; Task ID: '{task_id}'"
            ),
            ip_address=request.remote_addr
        )

        # ----------------------------------
        # 4️⃣ Get trn_activity_log_id
        # ----------------------------------
        trn_activity_log_id = (
            ActivityRequestLog
            .get_id_of_insert_into_trn_activity_log_overview_row(
                activity_id,
                key_process_id,
                task_id,
                user_id
            )
        )

        if not trn_activity_log_id:
            return jsonify({
                "error": "Failed to resolve activity log ID",
                "type": "danger"
            }), 500

        # ----------------------------------
        # 5️⃣ Re-insert activity breakdown
        # ----------------------------------
        activity_breakdown_count = 1

        for breakdown in activity_breakdown:

            start_date = breakdown.get("start_date")
            end_date = breakdown.get("end_date")
            detail = breakdown.get("activityBreakdownDetail")

            saved = ActivityRequestLog.insert_into_trn_activity_log_activity_breakdown(
                activity_breakdown_count=activity_breakdown_count,
                trn_activity_log_id=trn_activity_log_id,
                start_date=start_date,
                end_Date=end_date,
                activity_breakdown_detail=detail
            )

            Audit.log_audit_trail(
                user_id=user_id,
                action="Edit: trn_activity_log_activity_breakdown",
                details=(
                    f"Activity Log ID: '{trn_activity_log_id}', "
                    f"Breakdown Count: '{activity_breakdown_count}'"
                ),
                ip_address=request.remote_addr
            )

            if not saved:
                return jsonify({
                    "error": "Error saving activity breakdown",
                    "type": "danger"
                }), 500

            activity_breakdown_count += 1

        # ----------------------------------
        # 6️⃣ Save NEW attachments only
        # ----------------------------------

        updated = ActivityRequestLog.update_activity_log_id_of_trn_activity_log_attachment(
            old_activity_log_id=activity_log_id,
            new_activity_log_id=trn_activity_log_id
        )

        if not updated and retained_ids:
            return jsonify({
                "error": "Failed to re-link retained attachments",
                "type": "danger"
            }), 500

        files = request.files.getlist("wip_view_edit_attachments[]")
        descriptions = request.form.getlist("wip_view_edit_attachment_descriptions[]")

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        attachment_counter = 1

        upload_folder = os.path.join(app.config["UPLOAD_FOLDER"], "activity_log_docs")
        os.makedirs(upload_folder, exist_ok=True)

        for idx, file in enumerate(files):

            if not file or not file.filename:
                continue

            # SAFE description lookup
            desc = descriptions[idx] if idx < len(descriptions) else None

            filename = secure_filename(file.filename)
            new_filename = (
                f"{timestamp}_{current_user.id}_"
                f"{attachment_counter}_{filename}"
            )

            file.save(os.path.join(upload_folder, new_filename))

            saved = ActivityRequestLog.insert_into_trn_activity_log_attachment(
                attachment_counter=attachment_counter,
                trn_activity_log_id=trn_activity_log_id,
                file=new_filename,
                description=desc
            )

            if not saved:
                return jsonify({
                    "error": "Error saving attachment",
                    "type": "danger"
                }), 500

            attachment_counter += 1

        # ----------------------------------
        # 7️⃣ Done
        # ----------------------------------
        return jsonify({
            "message": "Activity log updated successfully."
        }), 200

    except Exception as e:
        return jsonify({
            "error": str(e),
            "type": "danger"
        }), 500


@app.route("/delete-saved-activity-wip-log-details", methods=["POST"])
@login_required
def delete_saved_activity_wip_log_details():
    activity_log_id = request.form.get("activity_log_id")

    if not activity_log_id:
        return jsonify({"message": "Invalid activity ID."}), 400

    # Delete related records
    ActivityRequestLog.delete_trn_activity_log_overview(activity_log_id)
    ActivityRequestLog.delete_trn_activity_log_activity_breakdown(activity_log_id)
    ActivityRequestLog.delete_trn_activity_log_attachment(activity_log_id)

    Audit.log_audit_trail(
        user_id=current_user.id,
        action="Deleted from tables: trn_activity_log_overview, trn_activity_log_activity_breakdown, "
               "trn_activity_log_attachment",
        details=f"Saved Activity Log ID: '{activity_log_id}'",
        ip_address=request.remote_addr
    )

    return jsonify({"message": "Activity log deleted successfully."}), 200


@app.route("/delete-saved-activity-wip-log-details-for-editing", methods=["POST"])
@login_required
def delete_saved_activity_wip_log_details_for_editing():
    activity_log_id = request.form.get("activity_log_id")

    if not activity_log_id:
        return jsonify({"message": "Invalid activity ID."}), 400

    # Delete related records
    ActivityRequestLog.delete_trn_activity_log_overview(activity_log_id)
    ActivityRequestLog.delete_trn_activity_log_activity_breakdown(activity_log_id)
    ActivityRequestLog.delete_trn_activity_log_attachment(activity_log_id)

    Audit.log_audit_trail(
        user_id=current_user.id,
        action="Deleted from tables due to editing saved logs: trn_activity_log_overview, "
               "trn_activity_log_activity_breakdown, trn_activity_log_attachment",
        details=f"Edited Saved Activity Log ID: '{activity_log_id}'",
        ip_address=request.remote_addr
    )

    return jsonify({"message": "Activity log deleted successfully."}), 200


@app.route('/update_activity_request', methods=['POST'])
@login_required
@role_required(1, 25)
def update_activity_request():
    try:
        data = json.loads(request.form.get("data", "{}"))
        activity_request_id = data.get("activity_request_id")

        # Get mode (1 = Save, 2 = Submit)
        activity_mode = data.get("activity_mode", 1)

        # Determine status based on mode
        status = 1 if activity_mode == 1 else 2

        # Save in trn_activity_request_approvals
        if activity_mode == 2:
            decision = 1
            level = 1
            comment = ""

            last_activity_request_approvals_id = (ActivityRequestApprovals.insert_into_trn_activity_request_approvals
                                                  (activity_request_id, decision, current_user.id, level, comment))
            if last_activity_request_approvals_id is None:
                return jsonify(
                    {"error": "Database error while writing to trn_activity_request_approvals table",
                     "type": "danger"}), 500

            Audit.log_audit_trail(
                user_id=current_user.id,
                action="Insert in table: trn_activity_request_approvals",
                details=f"Saved Activity Request ID: '{activity_request_id}'",
                ip_address=request.remote_addr
            )
            if not activity_request_id:
                return jsonify({"error": "Database error while saving activity request in "
                                         "trn_activity_request_approvals table", "type": "danger"}), 500

        if not activity_request_id:
            return jsonify({"error": "Missing activity_request_id"}), 400

        overview = data.get("overview", {})
        team = data.get("team", [])
        tasks = data.get("tasks", [])

        # Update request status
        ActivityRequest.update_activity_request_status(status, activity_request_id)
        # Delete overview
        ActivityRequest.delete_activity_overview(activity_request_id)
        # Update project_id of trn_activity_request table
        ActivityRequest.update_trn_activity_request_project_id(activity_request_id, overview.get("project_id"))
        # Update overview
        ActivityRequest.insert_into_trn_activity_overview(
            current_request_id=activity_request_id,
            subject=overview.get("subject"),
            objectives=overview.get("objectives"),
            scope=overview.get("scope"),
            stakeholders=overview.get("stakeholders"),
            deliverables=overview.get("deliverables"),
            assumptions=overview.get("assumptions")
        )

        # Replace existing team
        ActivityRequest.delete_activity_team(activity_request_id)
        for i, member in enumerate(team, start=1):
            ActivityRequest.insert_into_trn_activity_team_composition(
                team_member_no=i,
                activity_id=activity_request_id,
                member_id=member.get("member_id"),
                role_id=member.get("role_id")
            )

        # Replace existing tasks
        ActivityRequest.delete_activity_tasks(activity_request_id)
        for i, task in enumerate(tasks, start=1):
            ActivityRequest.insert_into_trn_activity_breakdown(
                task_no=i,
                activity_id=activity_request_id,
                task=task.get("task"),
                key_process_id=task.get("key_process"),
                start_date=task.get("start_date"),
                end_date=task.get("end_date")
            )

        # Handle attachments
        files = request.files.getlist("attachments")
        descriptions = request.form.getlist("attachment_descriptions")
        retained_ids = json.loads(request.form.get("retained_attachment_ids", "[]"))

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        upload_folder = os.path.join(app.config['UPLOAD_FOLDER'], 'activity_docs')
        os.makedirs(upload_folder, exist_ok=True)

        # Delete attachments not retained
        ActivityRequest.delete_removed_attachments(activity_request_id, retained_ids)

        # Get current attachments to determine next available ID
        existing_attachments = ActivityRequest.get_activity_attachments(activity_request_id)
        existing_ids = [att["id"] for att in existing_attachments]
        next_id = (max(existing_ids) + 1) if existing_ids else 1

        # Insert new attachments
        for file, desc in zip(files, descriptions):
            if file and file.filename:
                filename = secure_filename(file.filename)
                new_filename = f"{timestamp}_{current_user.id}_{next_id}_{filename}"
                file.save(os.path.join(upload_folder, new_filename))

                ActivityRequest.insert_into_trn_activity_attachment(
                    id=next_id,
                    activity_id=activity_request_id,
                    file=new_filename,
                    description=desc
                )

                Audit.log_audit_trail(
                    user_id=current_user.id,
                    action="Insert in table: trn_activity_attachment",
                    details=f"Saved new file '{new_filename}' (ID: {next_id}, Activity: {activity_request_id})",
                    ip_address=request.remote_addr
                )
                next_id += 1

        # --- Dynamic message based on status ---
        if status == 1:
            message = "Activity Request updated successfully"

        elif status == 2:
            try:
                user_fname = current_user.fname
                user_id = current_user.id

                activity_request_status = ActivityRequestApprovals.get_status_of_activity_request(activity_request_id)

                activity_request_details_for_email_table = ActivityRequest.get_saved_activity_request_details_3(activity_request_id)

                # Get next approver(s)
                next_approvers = (ActivityRequestApprovals.get_next_approver_fname_email
                                  (user_id, activity_request_status))

                if not next_approvers:
                    return jsonify({"error": "No next approver found"}), 500

                # Send emails in the background with app context
                def send_emails():
                    with app.app_context():  # Ensure Flask app context is available in the thread
                        for approver in next_approvers:
                            EmailHelper.send_submitted_activity_request_email(user_fname, approver["Email"],
                                                                             approver["Fname"], activity_request_details_for_email_table)

                email_thread = threading.Thread(target=send_emails)
                email_thread.start()

                message = "Activity Request submitted successfully"

            except Exception as e:
                return jsonify({"error": str(e), "type": "danger"}), 500
        else:
            message = "Activity Request processed successfully"

        return jsonify({"message": message}), 200

    except Exception as e:
        return jsonify({"error": str(e), "type": "danger"}), 500


@app.route('/submit-wip-activity-for-approval/<int:activity_task_request_id>', methods=['POST'])
@login_required
@role_required(1, 25, 58, 59, 69, 70, 71, 72)
def submit_wip_activity_for_approval(activity_task_request_id):
    try:
        is_user_requester_of_activity = ActivityRequestLog.get_is_user_requester_of_activity(activity_task_request_id, current_user.id)

        if is_user_requester_of_activity is None:
            return jsonify(
                {"error": "Database error while retrieving is_user_requester_of_activity.",
                 "type": "danger"}), 500

        elif is_user_requester_of_activity == 0:
            return jsonify(
                {"error": "Only the original requester of this activity is authorized to close it.",
                 "type": "danger"}), 400  # 400 is more appropriate than 500 here

        log_overview_count = ActivityRequestLog.get_log_overview_count(activity_task_request_id)

        if log_overview_count is None:
            return jsonify(
                {"error": "Database error while retrieving activity logs.",
                 "type": "danger"}), 500

        elif log_overview_count == 0:
            return jsonify(
                {"error": "You must submit at least one (1) activity log before you can close this activity.",
                 "type": "danger"}), 400   # 400 is more appropriate than 500 here

        decision = 1
        level = 1
        comment = ""

        last_activity_request_approvals_id = (ActivityRequestLog.insert_into_trn_completed_wip_activity_request_approvals(activity_task_request_id, decision, current_user.id, level, comment))
        if last_activity_request_approvals_id is None:
            return jsonify(
                {"error": "Database error while writing to trn_completed_wip_activity_request_approvals table",
                 "type": "danger"}), 500

        Audit.log_audit_trail(
            user_id=current_user.id,
            action="Insert in table: trn_completed_wip_activity_request_approvals",
            details=f"Saved Activity Request ID: '{activity_task_request_id}'",
            ip_address=request.remote_addr
        )
        if not activity_task_request_id:
            return jsonify({"error": "Database error while saving activity request in "
                                     "trn_completed_wip_activity_request_approvals table", "type": "danger"}), 500

        updated = ActivityRequestLog.submit_wip_activity_for_approval(activity_task_request_id)

        if not updated:
            return jsonify({
                "error": "Failed to update wip_status in trn_activity_request table.",
                "type": "danger"
            }), 500

        Audit.log_audit_trail(
            user_id=current_user.id,
            action="Update table: trn_activity_request; wip_status changed to 1",
            details=f"Activity Request ID: '{activity_task_request_id}'",
            ip_address=request.remote_addr
        )

        return jsonify({
            "message": "Activity successfully submitted for approval."
        }), 200

    except Exception as e:
        return jsonify({
            "error": str(e),
            "type": "danger"
        }), 500


@app.route('/send_email_reminders', methods=['GET', 'POST'])
def send_email_reminders():
    with app.app_context():
        initiators_pending_submission_of_activity_requests = ActivityRequest.initiators_pending_submission_of_activity_requests()

        for initiator_id in initiators_pending_submission_of_activity_requests:
            # Fetch initiator details
            initiator_fname_email = ActivityRequest.get_user_fname_email(initiator_id)

            if initiator_fname_email:
                pending_activity_requests_submission_details = ActivityRequest.pending_activity_requests_submission_details(
                    initiator_id)
                EmailHelper.email_reminder_to_initiator_activity_requests_pending_submission(
                    initiator_fname_email["fname"],
                    initiator_fname_email["email"],
                    pending_activity_requests_submission_details)

        user_ids = ActivityRequest.get_all_user_ids()

        for user_id in user_ids:
            user_fname_email = ActivityRequest.get_user_fname_email(user_id)

            if user_fname_email:
                pending_approval_details = ActivityRequest.get_activity_requests_pending_approval(user_id)
                if pending_approval_details:
                    EmailHelper.email_reminder_to_approve_submitted_activity_requests(user_fname_email["fname"], user_fname_email["email"], pending_approval_details)

        for user_id in user_ids:
            user_fname_email = ActivityRequest.get_user_fname_email(user_id)

            if user_fname_email:
                pending_approval_details = ActivityRequest.get_completed_wip_activity_requests_pending_approval(user_id)
                if pending_approval_details:
                    EmailHelper.email_reminder_to_approve_submitted_completed_wip_activity_requests(user_fname_email["fname"], user_fname_email["email"], pending_approval_details)


@app.route('/submitted_activity_requests', methods=['GET', 'POST'])
@login_required
@role_required(2, 26)
def submitted_activity_requests_page():
    activity_request_details = ActivityRequest.get_submitted_activity_request_details(1, current_user.id)
    return render_template('submitted_activity_requests.html',
                           activity_request_details=activity_request_details)


@app.route('/work-in-progress', methods=['GET', 'POST'])
@login_required
@role_required(2, 26, 58, 69, 70, 71, 72)
def work_in_progress_page():
    activity_request_details = ActivityRequest.get_wip_activity_request_details(1, current_user.id)
    return render_template('work_in_progress.html',
                           activity_request_details=activity_request_details)


@app.route('/approve-activity-requests', methods=['GET', 'POST'])
@login_required
@role_required(3, 5, 27, 47)
def approve_activity_requests_page():
    activity_requests = ActivityRequestApprovals.get_activity_requests_pending_approval(current_user.id)
    return render_template(
        'approve_activity_requests.html', activity_requests=activity_requests)


@app.route('/approve-completed-wip-activity-requests', methods=['GET', 'POST'])
@login_required
@role_required(3, 5, 27, 47, 52)
def approve_completed_wip_activity_requests_page():
    activity_requests = ActivityRequestLog.get_completed_wip_activity_requests_pending_approval(current_user.id)
    return render_template(
        'approve_completed_wip_activity_requests.html', activity_requests=activity_requests)


@app.route('/submitted-work-in-progress', methods=['GET', 'POST'])
@login_required
@role_required(2, 26, 57)
def submitted_work_in_progress_page():
    submitted_wip_activities = ActivityRequestLog.get_submitted_and_approved_wip_activity_requests(current_user.id, 3, 1)
    return render_template(
        'submitted_work_in_progress.html', submitted_wip_activities=submitted_wip_activities)


@app.route('/approved-activity-requests', methods=['GET', 'POST'])
@login_required
@role_required(4, 6, 28, 48)
def approved_activity_requests_page():
    activity_requests = ActivityRequestLog.get_approved_activity_requests(current_user.id)
    return render_template('approved_activity_requests.html', activity_requests=activity_requests)


@app.route('/approved-completed-wip-activity-requests', methods=['GET', 'POST'])
@login_required
@role_required(4, 6, 28, 48)
def approved_completed_wip_activity_requests_page():
    activity_requests = ActivityRequestLog.get_approved_completed_wip_activity_requests(current_user.id)
    return render_template('approved_completed_wip_activity_requests.html', activity_requests=activity_requests)


@app.route('/approve-activity-requests-update', methods=['POST'])
@login_required
@role_required(3, 4, 5, 6, 47)
def approve_activity_requests_update():

    try:
        data = request.get_json()
        action = data.get("action")
        comment = data.get("comment", "").strip()
        files = data.get("files", [])
        decision = 2 if action == "approve" else 3
        action_for_email = "approved" if action == "approve" else "rejected"
        max_approval_level = 0
        activity_request_status = 0
        initiator_id = None

        if not files:
            return jsonify({"error": "No requests provided"}), 400

        if action not in ["approve", "reject"]:
            return jsonify({"error": "Invalid action selected"}), 400

        max_approval_level = ActivityRequestApprovals.get_max_approval_level(1)

        if max_approval_level is None:
            return jsonify({"error": "Could not determine max approval level", "type": "danger"}), 500

        for file in files:
            activity_request_id = file.get("activity_request_id")

            print(action)
            # Update file status
            updated_activity_request_record = (ActivityRequestApprovals.update_activity_request_approval_status
                                               (activity_request_id, action, 1))
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: trn_activity_request",
                details=f"Update status of Activity Request, Id: '{activity_request_id}'",
                ip_address=request.remote_addr
            )
            if updated_activity_request_record is False:
                return jsonify({"error": "Database error while updating status of trn_activity_request table"}), 500

            # Pick latest level of reconciliation file from reconciliation_approvals table
            latest_approval_level = (ActivityRequestApprovals.get_latest_activity_request_approval_level
                                     (activity_request_id))
            if latest_approval_level is None:
                return jsonify({"error": "Database error while getting latest_approval_level from "
                                         "trn_activity_request_approvals table"}), 500

            # reconciliation_approvals table
            level = latest_approval_level + 1

            last_activity_request_approvals_id = (ActivityRequestApprovals.insert_into_trn_activity_request_approvals
                                                  (activity_request_id, decision, current_user.id, level, comment))

            if last_activity_request_approvals_id is None:
                return jsonify({"error": "Database error while writing to reconciliation_approvals table"}), 500

            if decision == 0:
                activity_request_id_rejected = (
                    ActivityRequestApprovals.update_activity_request_approval_status_following_a_rejected_approval
                    (activity_request_id))
                # update audit trail
                user_id = current_user.id
                Audit.log_audit_trail(
                    user_id=user_id,
                    action="Update table: trn_activity_request",
                    details=f"Activity Request Rejection, Id: '{activity_request_id}'",
                    ip_address=request.remote_addr
                )
                if activity_request_id_rejected is None:
                    return jsonify({"error": "Database error while updating status of activity request in "
                                             "trn_activity_request table following a rejected request"}), 500

            # get the user id of the initiator of the bank reconciliation
            initiator_id = ActivityRequestApprovals.get_activity_request_initiator_user_id(activity_request_id)
            if not initiator_id:
                continue  # Skip if no initiator found

            activity_request_status = ActivityRequestApprovals.get_status_of_activity_request(activity_request_id)

        # Store user details before threading
        user_fname = current_user.fname
        user_id = current_user.id

        # Get initiator's email and first name
        activity_requester_email_and_fname = (
            ActivityRequestApprovals.get_activity_request_initiator_email_and_fname(initiator_id))

        if not activity_requester_email_and_fname:
            return jsonify({"error": "No requestor of activity found"}), 500

        # Send emails in the background with app context
        def send_emails():
            try:
                with app.app_context():
                    for initiator in activity_requester_email_and_fname:
                        # Enrich each file with project and subject details
                        for f in files:
                            details = ActivityRequest.get_saved_activity_request_details_3(f["activity_request_id"])
                            if details:
                                d = details[0]
                                f["project_code"] = d["project_code"]
                                f["project_name"] = d["project_name"]
                                f["subject"] = d["subject"]

                        EmailHelper.send_approval_summary_emails(
                            user_fname,
                            initiator["Email"],
                            initiator["Fname"],
                            files,
                            action_for_email
                        )

            except Exception as e:
                app.logger.error(f"Error in email thread 1: {e}")

        email_thread = threading.Thread(target=send_emails, daemon=True)
        email_thread.start()

        # Get next approver(s)
        if action == "approve" and (activity_request_status <= max_approval_level):

            next_approvers = ActivityRequestApprovals.get_next_approver_fname_email(user_id, activity_request_status)

            if next_approvers:
                def send_emails2():
                    try:
                        with app.app_context():  # Ensure Flask app context is available in the thread
                            for approver in next_approvers:
                                # Enrich each file with project and subject details
                                for f in files:
                                    details = ActivityRequest.get_saved_activity_request_details_3(
                                        f["activity_request_id"])
                                    if details:
                                        d = details[0]
                                        f["project_code"] = d["project_code"]
                                        f["project_name"] = d["project_name"]
                                        f["subject"] = d["subject"]

                                EmailHelper.send_email_notification_to_next_approver(
                                    user_fname,
                                    approver["Email"],
                                    approver["Fname"],
                                    files
                                )
                    except Exception as e:
                        app.logger.error(f"Error in email thread 2: {e}")

                email_thread2 = threading.Thread(target=send_emails2, daemon=True)
                email_thread2.daemon = True
                email_thread2.start()

            if not next_approvers:
                # return jsonify({"error": "No next approver found"}), 500
                pass

        return jsonify({"message": "Activity Request(s) approved successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/approve-completed-wip-activity-requests-update', methods=['POST'])
@login_required
@role_required(3, 4, 5, 6, 47)
def approve_completed_wip_activity_requests_update():

    try:
        data = request.get_json()
        action = data.get("action")
        comment = data.get("comment", "").strip()
        files = data.get("files", [])
        decision = 2 if action == "approve" else 3
        action_for_email = "approved" if action == "approve" else "rejected"
        activity_request_wip_status = 0
        initiator_id = None

        if not files:
            return jsonify({"error": "No requests provided"}), 400

        if action not in ["approve", "reject"]:
            return jsonify({"error": "Invalid action selected"}), 400

        max_approval_level = ActivityRequestApprovals.get_max_approval_level(3)

        if max_approval_level is None:
            return jsonify({"error": "Could not determine max approval level", "type": "danger"}), 500

        for file in files:
            activity_request_id = file.get("activity_request_id")

            # Update file status
            updated_activity_request_record = ActivityRequestLog.update_completed_wip_activity_request_approval_wip_status(activity_request_id, action, 3)
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: trn_activity_request",
                details=f"Update wip_status of Activity Request, Id: '{activity_request_id}'",
                ip_address=request.remote_addr
            )
            if updated_activity_request_record is False:
                return jsonify({"error": "Database error while updating wip_status of trn_activity_request table"}), 500

            # Pick latest level of reconciliation file from reconciliation_approvals table
            latest_approval_level = (ActivityRequestLog.get_latest_completed_wip_activity_request_approval_level
                                     (activity_request_id))
            if latest_approval_level is None:
                return jsonify({"error": "Database error while getting latest_approval_level from "
                                         "trn_completed_wip_activity_request_approvals table"}), 500

            # reconciliation_approvals table
            level = latest_approval_level + 1

            last_activity_request_approvals_id = (ActivityRequestLog.insert_into_trn_completed_wip_activity_request_approvals
                                                  (activity_request_id, decision, current_user.id, level, comment))

            if last_activity_request_approvals_id is None:
                return jsonify({"error": "Database error while writing to "
                                         "trn_completed_wip_activity_request_approvals table"}), 500

            if decision == 0:
                activity_request_id_rejected = (
                    ActivityRequestLog.update_completed_wip_activity_request_approval_status_following_a_rejected_approval(activity_request_id))
                # update audit trail
                user_id = current_user.id
                Audit.log_audit_trail(
                    user_id=user_id,
                    action="Update table: trn_activity_request",
                    details=f"Completed WIP Activity Request Rejection, Id: '{activity_request_id}'",
                    ip_address=request.remote_addr
                )
                if activity_request_id_rejected is None:
                    return jsonify({"error": "Database error while updating wip_status of completed wip activity "
                                             "request in trn_activity_request table following a rejected request"}), 500

            # get the user id of the initiator of the bank reconciliation
            initiator_id = ActivityRequestApprovals.get_activity_request_initiator_user_id(activity_request_id)
            if not initiator_id:
                continue  # Skip if no initiator found

            activity_request_wip_status = ActivityRequestLog.get_wip_status_of_activity_request(activity_request_id)

        # Store user details before threading
        user_fname = current_user.fname
        user_id = current_user.id

        # Get initiator's email and first name
        activity_requester_email_and_fname = (
            ActivityRequestApprovals.get_activity_request_initiator_email_and_fname(initiator_id))

        if not activity_requester_email_and_fname:
            return jsonify({"error": "No requestor of activity found"}), 500

        # Send emails in the background with app context
        def send_emails():
            try:
                with app.app_context():
                    for initiator in activity_requester_email_and_fname:
                        # Enrich each file with project and subject details
                        for f in files:
                            details = ActivityRequest.get_saved_activity_request_details_3(f["activity_request_id"])
                            if details:
                                d = details[0]
                                f["project_code"] = d["project_code"]
                                f["project_name"] = d["project_name"]
                                f["subject"] = d["subject"]

                        EmailHelper.send_approval_summary_emails(
                            user_fname,
                            initiator["Email"],
                            initiator["Fname"],
                            files,
                            action_for_email
                        )

            except Exception as e:
                app.logger.error(f"Error in email thread 1: {e}")

        email_thread = threading.Thread(target=send_emails, daemon=True)
        email_thread.start()

        # Get next approver(s)
        if action == "approve" and (activity_request_wip_status <= max_approval_level):

            next_approvers = ActivityRequestApprovals.get_next_approver_fname_email(user_id, activity_request_wip_status)

            if next_approvers:
                def send_emails2():
                    try:
                        with app.app_context():  # Ensure Flask app context is available in the thread
                            for approver in next_approvers:
                                # Enrich each file with project and subject details
                                for f in files:
                                    details = ActivityRequest.get_saved_activity_request_details_3(
                                        f["activity_request_id"])
                                    if details:
                                        d = details[0]
                                        f["project_code"] = d["project_code"]
                                        f["project_name"] = d["project_name"]
                                        f["subject"] = d["subject"]

                                EmailHelper.send_email_notification_to_next_approver(
                                    user_fname,
                                    approver["Email"],
                                    approver["Fname"],
                                    files
                                )
                    except Exception as e:
                        app.logger.error(f"Error in email thread 2: {e}")

                email_thread2 = threading.Thread(target=send_emails2, daemon=True)
                email_thread2.daemon = True
                email_thread2.start()

            if not next_approvers:
                # return jsonify({"error": "No next approver found"}), 500
                pass

        return jsonify({"message": "Completed WIP Activity Request(s) approved successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get-activity-request-approval-workflow", methods=["GET"])
def get_reconciliation_workflow():
    activity_request_id = request.args.get("activity_Request_ID")
    workflow_id = request.args.get("workflow_ID")

    # Get the latest approval level of given activity request
    approvals = ActivityRequestApprovals.get_activity_request_approval_levels(activity_request_id)
    if approvals is None:
        return jsonify({"error": "Database error while picking latest approval level of given activity request",
                        "type": "danger"}), 500

    approval_dict = {a[0]: {"decision": a[1], "approver": a[2], "date": a[3], "comment": a[4]} for a in approvals}

    # Get workflow breakdown for "Activity Request Approval"
    workflow_steps = WorkflowBreakdown.get_workflow_breakdown_for_reconciliation_approval(workflow_id, 1)
    if workflow_steps is None:
        return jsonify({"error": "Database error while picking workflow breakdown for Reconciliation Approval workflow",
                        "type": "danger"}), 500

    workflow_list = []
    for step in workflow_steps:
        approval = approval_dict.get(step.level, None)
        workflow_list.append({
            "level": step.level,
            "name": step.name,
            "role": step.role_name,
            "status": approval["decision"] if approval else "Pending",
            "approver": approval["approver"] if approval else "N/A",
            "date": approval["date"] if approval else "N/A",
            "comment": approval["comment"] if approval else " "
        })

    # Get Activity Request details"
    saved_activity_request_details_2 = ActivityRequest.get_saved_activity_request_details_2(activity_request_id)
    if not saved_activity_request_details_2:
        return jsonify({"error": "Activity Request ID not found"}), 404

    saved_activity_request_detail = saved_activity_request_details_2[0]

    # Serialize manually
    saved_activity_request_data = {
        "id": saved_activity_request_detail.id,
        "subject": saved_activity_request_detail.subject,
        "objectives": saved_activity_request_detail.objectives,
        "scope": saved_activity_request_detail.scope,
        "stakeholders": saved_activity_request_detail.stakeholders,
        "deliverables": saved_activity_request_detail.deliverables,
        "assumptions": saved_activity_request_detail.assumptions
    }

    team = ActivityRequest.get_team_composition_details_2(activity_request_id)

    tasks = ActivityRequest.get_activity_tasks_details_2(activity_request_id)

    attachments = ActivityRequest.get_activity_attachments(activity_request_id)

    return jsonify({
        "workflow_steps": workflow_list,
        "saved_activity_request_details_2": saved_activity_request_data,
        "team": team or [],
        "tasks": tasks or [],
        "attachments": attachments or []
    })


@app.route("/get-completed-wip-activity-approval-request-workflow", methods=["GET"])
def get_completed_wip_activity_approval_request_workflow():
    activity_request_id = request.args.get("activity_Request_ID")
    workflow_id = request.args.get("workflow_ID")

    # Get the latest approval level of given activity request
    approvals = ActivityRequestLog.get_completed_wip_activity_request_approval_levels(activity_request_id)
    if approvals is None:
        return jsonify({"error": "Database error while picking latest approval level of given activity request",
                        "type": "danger"}), 500

    approval_dict = {a[0]: {"decision": a[1], "approver": a[2], "date": a[3], "comment": a[4]} for a in approvals}

    # Get workflow breakdown for "Activity Request Approval"
    workflow_steps = WorkflowBreakdown.get_workflow_breakdown_for_reconciliation_approval(workflow_id, 1)
    if workflow_steps is None:
        return jsonify({"error": "Database error while picking workflow breakdown for Reconciliation Approval workflow",
                        "type": "danger"}), 500

    workflow_list = []
    for step in workflow_steps:
        approval = approval_dict.get(step.level, None)
        workflow_list.append({
            "level": step.level,
            "name": step.name,
            "role": step.role_name,
            "status": approval["decision"] if approval else "Pending",
            "approver": approval["approver"] if approval else "N/A",
            "date": approval["date"] if approval else "N/A",
            "comment": approval["comment"] if approval else " "
        })

    # Get Activity Request details"
    saved_activity_request_details_2 = ActivityRequest.get_saved_activity_request_details_2(activity_request_id)
    if not saved_activity_request_details_2:
        return jsonify({"error": "Activity Request ID not found"}), 404

    saved_activity_request_detail = saved_activity_request_details_2[0]

    # Serialize manually
    saved_activity_request_data = {
        "id": saved_activity_request_detail.id,
        "subject": saved_activity_request_detail.subject,
        "objectives": saved_activity_request_detail.objectives,
        "scope": saved_activity_request_detail.scope,
        "stakeholders": saved_activity_request_detail.stakeholders,
        "deliverables": saved_activity_request_detail.deliverables,
        "assumptions": saved_activity_request_detail.assumptions
    }

    team = ActivityRequest.get_team_composition_details_2(activity_request_id)

    tasks = ActivityRequest.get_activity_tasks_details_2(activity_request_id)

    attachments = ActivityRequest.get_activity_attachments(activity_request_id)

    return jsonify({
        "workflow_steps": workflow_list,
        "saved_activity_request_details_2": saved_activity_request_data,
        "team": team or [],
        "tasks": tasks or [],
        "attachments": attachments or []
    })


@app.route("/get-completed-wip-activity-approval-request-log-details", methods=["GET"])
def get_completed_wip_activity_approval_request_workflow_log_details():
    activity_request_id = request.args.get("activity_Request_ID")

    # Get Activity Request details"
    saved_activity_request_details_2 = ActivityRequest.get_saved_activity_request_details_2(activity_request_id)
    if not saved_activity_request_details_2:
        return jsonify({"error": "Activity Request ID not found"}), 404

    saved_activity_request_detail = saved_activity_request_details_2[0]

    # Serialize manually
    saved_activity_request_data = {
        "id": saved_activity_request_detail.id,
        "subject": saved_activity_request_detail.subject,
        "objectives": saved_activity_request_detail.objectives,
        "scope": saved_activity_request_detail.scope,
        "stakeholders": saved_activity_request_detail.stakeholders,
        "deliverables": saved_activity_request_detail.deliverables,
        "assumptions": saved_activity_request_detail.assumptions
    }

    team = ActivityRequest.get_team_composition_details_2(activity_request_id)

    # Log Details
    logs = ActivityRequestLog.get_completed_wip_logs(activity_request_id)

    return jsonify({
        "saved_activity_request_details_2": saved_activity_request_data,
        "team": team or [],
        "logs": logs or []
    })


@app.route("/download/<filename>")
@login_required
def download_file(filename):
    """Serves files from the uploads directory."""

    upload_folder = os.path.join(app.config["UPLOAD_FOLDER"], "activity_docs")

    try:
        return send_from_directory(upload_folder, filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)


@app.route('/download/activity-log/<filename>')
@login_required
def download_log_file(filename):
    """Serves files from the uploads directory."""

    upload_folder = os.path.join(app.config["UPLOAD_FOLDER"], "activity_log_docs")

    try:
        return send_from_directory(upload_folder, filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)


@app.route('/report-activity-requests-pending-submission', methods=['GET', 'POST'])
@login_required
@role_required(7, 11, 15, 29, 52)
def report_activity_requests_pending_submission_page():
    activity_request_details = ActivityRequest.get_all_activity_requests_pending_submission_details(1)
    return render_template('report_activity_requests_pending_submission.html', activity_request_details=activity_request_details)


@app.route('/report-completed-wip-activity-requests-pending-submission', methods=['GET', 'POST'])
@login_required
@role_required(7, 11, 15, 29, 52)
def report_completed_wip_activity_requests_pending_submission_page():
    activity_request_details = ActivityRequest.get_all_completed_wip_activity_requests_pending_submission_details(3)
    return render_template('report_completed_wip_activity_requests_pending_submission.html', activity_request_details=activity_request_details)


@app.route('/report-all-submitted-activity-requests', methods=['GET', 'POST'])
@login_required
@role_required(8, 12, 16, 31, 49)
def report_all_submitted_activity_requests_page():
    activity_request_details = ActivityRequest.get_all_submitted_activity_request_details(1)
    return render_template('report_all_submitted_activity_requests.html', activity_request_details=activity_request_details)


@app.route('/report-all-submitted-completed-wip-activity-requests', methods=['GET', 'POST'])
@login_required
@role_required(8, 12, 16, 31, 49)
def report_all_submitted_completed_wip_activity_requests_page():
    activity_request_details = ActivityRequest.get_all_submitted_completed_wip_activity_request_details(1)
    return render_template('report_all_submitted_completed_wip_activity_requests.html', activity_request_details=activity_request_details)


@app.route('/report-audit-trail', methods=['GET', 'POST'])
@login_required
@role_required(24)
def report_report_audit_trail_page():
    audit_trail_records = Audit.get_all_audit_trail_records()
    return render_template('report_audit_trail.html', audit_trail_records=audit_trail_records)


@app.route('/report-activity-requests-pending-approval-page', methods=['GET', 'POST'])
@login_required
@role_required(9, 13, 17, 32, 51)
def report_activity_requests_pending_approval_page():
    activity_request_details = ActivityRequest.get_activity_requests_pending_approval_details(1)
    return render_template('report_activity_requests_pending_approval.html', activity_request_details=activity_request_details)


@app.route('/report-completed-wip-activity-requests-pending-approval', methods=['GET', 'POST'])
@login_required
@role_required(9, 13, 17, 32, 51)
def report_completed_wip_activity_requests_pending_approval_page():
    activity_request_details = ActivityRequest.get_completed_wip_activity_requests_pending_approval_details(3)
    return render_template('report_completed_wip_activity_requests_pending_approval.html', activity_request_details=activity_request_details)


@app.route('/report-fully-approved-activity-requests', methods=['GET', 'POST'])
@login_required
@role_required(10, 14, 18, 33, 50)
def report_fully_approved_activity_requests_page():
    activity_request_details = ActivityRequest.get_fully_approved_activity_request_details(1, 1)
    return render_template('report_fully_approved_activity_requests.html', activity_request_details=activity_request_details)


@app.route('/report-fully-approved-completed-wip-activity-requests', methods=['GET', 'POST'])
@login_required
@role_required(10, 14, 18, 33, 50)
def report_fully_approved_completed_wip_activity_requests_page():
    activity_request_details = ActivityRequest.get_fully_approved_completed_wip_activity_request_details(1, 3)
    return render_template('report_fully_approved_completed_wip_activity_requests.html', activity_request_details=activity_request_details)


@app.route('/report-rejected-activity-requests', methods=['GET', 'POST'])
@login_required
@role_required(19, 20, 21, 34, 53)
def report_rejected_activity_requests_page():
    activity_request_details = ActivityRequest.get_rejected_activity_requests_details(1, 3)
    return render_template('report_rejected_activity_requests.html', activity_request_details=activity_request_details)


@app.route('/report-rejected-completed-wip-activity-requests', methods=['GET', 'POST'])
@login_required
@role_required(19, 20, 21, 34, 53)
def report_rejected_completed_wip_activity_requests_page():
    activity_request_details = ActivityRequest.get_rejected_completed_wip_activity_requests_details(3, 3)
    return render_template('report_rejected_completed_wip_activity_requests.html', activity_request_details=activity_request_details)


@app.route('/admin-users', methods=['GET', 'POST'])
@login_required
@role_required(44)
def admin_users_page():
    user_details = UserSummary.get_all_users_details()
    org_unit_tier = UserSummary.get_organisation_unit_tier()
    # org_unit = UserSummary.get_organisation_units()
    return render_template('users.html', user_details=user_details, org_unit_tier=org_unit_tier)


@app.route('/get-organisation-units/<int:org_unit_tier_id>', methods=['GET', 'POST'])
@login_required
def get_organisation_units_by_tier(org_unit_tier_id):
    org_unit = UserSummary.get_organisation_units_by_tier(org_unit_tier_id)
    return jsonify([{'id': u.id, 'name': u.name} for u in org_unit])


@app.route('/get-tasks-by-key-process/<int:key_process_id>/<int:activity_id>', methods=['GET'])
@login_required
def get_tasks_by_key_process(key_process_id, activity_id):
    tasks = ActivityRequest.get_tasks_by_key_process(key_process_id, activity_id)
    return jsonify([
        {'id': task.id, 'task': task.task}
        for task in tasks
    ])


@app.route('/get-process-by-activity-request-id/<int:activity_id>', methods=['GET'])
@login_required
def get_process_by_activity_request_id(activity_id):
    key_processes = ActivityRequest.get_process_by_activity_request_id(activity_id)
    return jsonify([
        {'id': key_process.id, 'name': key_process.name}
        for key_process in key_processes
    ])


@app.route('/get-logs-list-by-activity-request-id/<int:activity_id>', methods=['GET'])
@login_required
def get_logs_list_by_activity_request_id(activity_id):
    activity_logs = ActivityRequestLog.get_logs_list_by_activity_request_id(activity_id)
    return jsonify([
        {'id': activity_log.id, 'key_process_name': activity_log.key_process_name, 'task': activity_log.task,
         'user_name': activity_log.user_name, 'creation_date': activity_log.creation_date}
        for activity_log in activity_logs
    ])


@app.route('/admin-register-new-user', methods=['POST'])
@login_required
@role_required(7, 8, 9, 10)
def admin_register_new_user():
    data = request.get_json()

    try:
        # Extract fields
        username = data.get("username")
        email = data.get("email")
        fname = data.get("fname")
        mname = data.get("mname") or ""
        sname = data.get("sname")
        password = data.get("password")
        confirm_password = data.get("confirm_password")
        org_unit_tier_id = data.get("organisationUnitTier")
        org_unit_id = data.get("organisationUnit")

        # Validate required fields
        if not all([username, email, fname, sname, password, org_unit_tier_id, org_unit_id]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Validate password
        if password != confirm_password:
            return jsonify({"success": False, "message": "Passwords do not match."})

        if not is_password_complex(password):
            return jsonify({"success": False, "message": "Password does not meet complexity requirements."})

        # Insert user into DB (pseudo-function: implement in your model)
        result = UserSummary.insert_new_user(
            username=username,
            email=email,
            fname=fname,
            mname=mname,
            sname=sname,
            password=password,
            org_unit_tier_id=org_unit_tier_id,
            org_unit_id=org_unit_id
        )
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: users",
                details=f"Add User, username: '{username}', email: '{email}', fname: '{fname}', mname: '{mname}', "
                        f"sname: '{sname}', password: '{password}', org_unit_tier_id: '{org_unit_tier_id}',"
                        f" org_unit_id: '{org_unit_id}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "User added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert user.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


def is_password_complex(password):
    pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()_\-+=\[\]{};\'":\\|,.<>\/?]).{8,}$'
    return re.match(pattern, password)


@app.route('/admin-user-password-update', methods=['POST'])
@login_required
@role_required(7, 8, 9, 10)
def admin_user_password_update():
    data = request.get_json()

    try:
        # Extract fields
        username = data.get("username")
        password = data.get("password")
        confirm_password = data.get("confirmPassword")

        if password != confirm_password:
            return jsonify({"success": False, "message": "Passwords do not match."})

        if not is_password_complex(password):
            return jsonify({"success": False, "message": "Password does not meet complexity requirements."})

        # Validate required fields
        if not all([username, password]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = UserSummary.update_user_password(
            username=username,
            password=password
        )
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: users",
                details=f"Update User Password, username: '{username}': password: '{password}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "User Password updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update user password.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-update-user', methods=['POST'])
@login_required
@role_required(44)
def admin_update_user():
    data = request.get_json()

    try:
        # Extract fields
        username = data.get("username")
        email = data.get("email")
        fname = data.get("fname")
        mname = data.get("mname") or ""
        sname = data.get("sname")
        org_unit_tier_id = data.get("organisationUnitTier")
        org_unit_id = data.get("organisationUnit")
        is_active = int(data.get("is_active"))

        # Validate required fields
        required_fields = [username, email, fname, mname, sname, org_unit_tier_id, org_unit_id, is_active]
        if any(field is None for field in required_fields):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = UserSummary.update_user(
            username=username,
            email=email,
            fname=fname,
            mname=mname,
            sname=sname,
            org_unit_tier_id=org_unit_tier_id,
            org_unit_id=org_unit_id,
            is_active=is_active
        )
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: users",
                details=f"Update User, username: '{username}', email: '{email}', fname: '{fname}', mname: '{mname}', "
                        f"sname: '{sname}', org_unit_tier_id: '{org_unit_tier_id}', org_unit_id: '{org_unit_id}', "
                        f"is_active: '{is_active}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "User updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update user.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/check-username/<string:username>', methods=['GET'])
@login_required
def check_username_exists(username):
    exists = UserSummary.username_exists(username)
    return jsonify({"exists": exists})


@app.route("/get-user-account-details", methods=["GET"])
def get_user_account_details():
    username = request.args.get("user_name")
    user_account_details = UserSummary.get_user_account_details(username)

    if not user_account_details:
        return jsonify({"error": "User not found"}), 404

    user = user_account_details[0]
    return jsonify(user)


@app.route('/admin-roles', methods=['GET', 'POST'])
@login_required
@role_required(42)
def admin_roles():
    role_details = Role.get_all_role_details()
    return render_template('roles.html', role_details=role_details)


@app.route('/check-role-name/<string:rolename>', methods=['GET'])
@login_required
def check_role_name_exists(rolename):
    exists = Role.role_name_exists(rolename)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-role', methods=['POST'])
@login_required
@role_required(42)
def admin_register_new_role():
    data = request.get_json()

    try:
        # Extract fields
        rolename = data.get("roleName", "").strip()

        # Validate required fields
        if not all([rolename]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = Role.insert_new_role(role_name=rolename)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: role",
                details=f"Add Role, role_name: '{role_name}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Role added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert role.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route("/get-role-details", methods=["GET"])
def get_role_details():
    role_name = request.args.get("role_name")
    role_details = Role.get_role_details(role_name)

    if not role_details:
        return jsonify({"error": "Role not found"}), 404

    role = role_details[0]

    # Serialize manually
    role_data = {
        "id": role.id,
        "role_name": role.name
    }
    return jsonify(role_data)


@app.route('/admin-update-role', methods=['POST'])
@login_required
@role_required(42)
def admin_update_role():
    data = request.get_json()

    try:
        # Extract fields
        role_id = data.get("role_id")
        role_name = data.get("role_name")

        # Validate required fields
        if not role_id or not role_name or role_name.strip() == "":
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = Role.update_role(role_id, role_name)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: role",
                details=f"Update Role, role_id: '{role_id}': role_name: '{role_name}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Role updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update user.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-user-roles', methods=['GET', 'POST'])
@login_required
@role_required(43)
def admin_user_roles_page():
    user_role_details = UserRole.get_all_user_roles_details()

    usernames = UserSummary.get_all_usernames()
    # for user in usernames:
    #     print(f"User ID: {user.id}, Username: {user.username}")

    roles = Role.get_all_roles()
    # for role in roles:
    #     print(f"Role ID: {role.id}, Role Name: {role.name}")

    return render_template(
        'user_roles.html',
        user_role_details=user_role_details,
        usernames=usernames,
        roles=roles
    )


@app.route('/check-user-role/<int:user_id>/<int:role_id>', methods=['GET'])
@login_required
def check_user_role_exists(user_id, role_id):
    exists = UserRole.user_role_exists(user_id, role_id)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-user-role', methods=['POST'])
@login_required
@role_required(43)
def admin_register_new_user_role():
    data = request.get_json()

    try:
        # Extract fields
        user_id = data.get("user_id")
        role_id = data.get("role_id")
        start_date = data.get("start_date")
        end_date = data.get("end_date")

        # Validate required fields
        if not all([user_id, role_id, start_date, end_date]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        result = UserRole.insert_new_user_role(
            user_id=user_id,
            role_id=role_id,
            start_date=start_date,
            end_date=end_date
        )
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: user_role",
                details=f"Add User-Role, user_id: '{user_id}': role_id: '{role_id}': start_date: '{start_date}': "
                        f"end_date: '{end_date}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "User role added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert user role.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route("/get-user-role-id", methods=["GET"])
def get_user_role_id():
    user_name = request.args.get("username")
    role_name = request.args.get("role_name")
    user_role_id_details = UserRole.get_user_role_id(user_name, role_name)

    if not user_role_id_details:
        return jsonify({"error": "User-Role not found"}), 404

    user_role_id = user_role_id_details[0]["id"]
    return jsonify({"user_role_id": user_role_id})


@app.route('/admin-update-user-role', methods=['POST'])
@login_required
@role_required(43)
def admin_update_user_role():
    data = request.get_json()

    try:
        # Extract fields
        user_role_id = data.get("user_role_id")
        start_date = data.get("start_date")
        expiry_date = data.get("end_date")

        # Validate required fields
        if not user_role_id or not start_date or expiry_date.strip() == "":
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = UserRole.update_user_role(user_role_id, start_date, expiry_date)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: user_role",
                details=f"Update User-Role, user_role_id: '{user_role_id}': start_date: '{start_date}': "
                        f"expiry_date: '{expiry_date}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "User-Role updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update User-Role.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/team-member-role', methods=['GET', 'POST'])
@login_required
@role_required(36)
def team_member_role():
    team_member_roles = TeamMemberRole.get_all_team_member_roles()
    return render_template('team_member_role.html', team_member_roles=team_member_roles)


@app.route('/check-team-member-role-name/<string:teamMemberRoleName>', methods=['GET'])
@login_required
def check_team_member_role_name_exists(teamMemberRoleName):
    exists = TeamMemberRole.team_member_role_name_exists(teamMemberRoleName)
    return jsonify({"exists": exists})


@app.route('/check-key-process-name/<string:key_process_name>', methods=['GET'])
@login_required
def check_key_process_name_exists(key_process_name):
    exists = KeyProcess.key_process_name_exists(key_process_name)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-team-member-role', methods=['POST'])
@login_required
@role_required(36)
def admin_register_new_team_member_role():
    data = request.get_json()

    try:
        # Extract fields
        team_member_role_ = data.get("teamMemberRoleName", "").strip()

        # Validate required fields
        if not all([team_member_role_]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = TeamMemberRole.insert_new_team_member_role(name=team_member_role_)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: team_member_role",
                details=f"Add team_member_role, role name: '{team_member_role_}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Team Member Role added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert Team Member Role.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-register-new-key-process', methods=['POST'])
@login_required
@role_required(36)
def admin_register_new_key_process():
    data = request.get_json()

    try:
        # Extract fields
        key_process_name_ = data.get("key_process_name", "").strip()

        # Validate required fields
        if not all([key_process_name_]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = KeyProcess.insert_new_key_process(name=key_process_name_)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: mst_key_process",
                details=f"Add key process, process name: '{key_process_name_}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Key Process added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert Key Process.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new key process:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route("/get-team-member-role-details", methods=["GET"])
def get_bank_details():
    team_member_role_name = request.args.get("team_member_role_name")
    team_member_role_details = TeamMemberRole.get_team_member_role_details(team_member_role_name)

    if not team_member_role_details:
        return jsonify({"error": "Bank not found"}), 404

    team_member_role = team_member_role_details[0]

    # Serialize manually
    team_member_role_data = {
        "id": team_member_role.id,
        "team_member_role_name": team_member_role.name
    }
    return jsonify(team_member_role_data)


@app.route("/get-key-process-details", methods=["GET"])
def get_key_process_details():
    key_process_name = request.args.get("key_process_name")
    key_process_details = KeyProcess.get_key_process_details(key_process_name)

    if not key_process_details:
        return jsonify({"error": "Bank not found"}), 404

    key_process = key_process_details[0]

    # Serialize manually
    key_process_data = {
        "id": key_process.id,
        "key_process_name": key_process.name
    }
    return jsonify(key_process_data)


@app.route('/admin-update-team-member-role', methods=['POST'])
@login_required
@role_required(36)
def admin_update_team_member_role():
    data = request.get_json()

    try:
        # Extract fields
        team_member_role_id = data.get("team_member_role_id")
        team_member_role_name_2 = data.get("team_member_role_name_2")

        # Validate required fields
        if not team_member_role_id or not team_member_role_name_2 or team_member_role_name_2.strip() == "":
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = TeamMemberRole.update_team_member_role(team_member_role_id, team_member_role_name_2)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: team_member_role",
                details=f"Update team_member_role, team_member_role_id: '{team_member_role_id}': "
                        f"team_member_role_name: '{team_member_role_name_2}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Team Member Role updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update Team Member Role.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new Team Member Role:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-update-key-process', methods=['POST'])
@login_required
@role_required(36)
def admin_update_key_process():
    data = request.get_json()

    try:
        # Extract fields
        key_process_id = data.get("key_process_id")
        key_process_name_2 = data.get("key_process_name_2")

        # Validate required fields
        if not key_process_id or not key_process_name_2 or key_process_name_2.strip() == "":
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = KeyProcess.update_key_process(key_process_id, key_process_name_2)
        if result:
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: mst_key_process",
                details=f"Update key_process, key_process_id: '{key_process_id}': "
                        f"key_process_name: '{key_process_name_2}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Key Process updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update Key Process.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new Key Process:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-bank-accounts', methods=['GET', 'POST'])
@login_required
@role_required(35)
def admin_bank_accounts():
    bank_account_details = BankAccount.get_all_bank_account_details()
    banks = BankAccount.get_all_bank_details()
    currencies = Currency.get_all_currency_details()
    org_units = UserSummary.get_organisation_units()
    return render_template('bank_accounts.html', bank_account_details=bank_account_details,
                           banks=banks, currencies=currencies, org_units=org_units)


@app.route('/check-bank-account-name/<string:bankaccountname>', methods=['GET'])
@login_required
def check_bank_account_name_exists(bankaccountname):
    exists = BankAccount.bank_account_name_exists(bankaccountname)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-bank-account', methods=['POST'])
@login_required
@role_required(35)
def admin_register_new_bank_account():
    data = request.get_json()

    try:
        # Extract fields
        bankAccountName = data.get("bankAccountName", "").strip()
        bank_id = data.get("bank_id", "").strip()
        currency_id = data.get("currency_id", "").strip()
        org_unit_id = data.get("org_unit_id", "").strip()

        # Validate required fields
        if not all([bankAccountName, bank_id, currency_id, org_unit_id]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = BankAccount.insert_new_bank_account(bankAccountName, bank_id, currency_id, org_unit_id)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: bank_account",
                details=f"Add Bank Account, bankAccountName: '{bankAccountName}': bank_id: '{bank_id}'"
                        f": currency_id: '{currency_id}': org_unit_id: '{org_unit_id}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Bank Account added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert bank account.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route("/get-bank-account-details", methods=["GET"])
def get_bank_account_details():
    bank_account_name = request.args.get("bank_account_name")
    bank_account_details = BankAccount.get_bank_account_details(bank_account_name)

    if not bank_account_details:
        return jsonify({"error": "User not found"}), 404

    bank_accounts = bank_account_details[0]
    return jsonify(bank_accounts)


@app.route('/admin-update-bank-account', methods=['POST'])
@login_required
@role_required(35)
def admin_update_bank_account():
    data = request.get_json()

    try:
        # Extract fields
        bank_acc_id = data.get("bank_acc_id")
        bank_id = data.get("bank_id")
        currency_id = data.get("currency_id")
        org_unit_id = data.get("org_unit_id")
        creation_date = data.get("creation_date")

        # Validate required fields
        if not bank_acc_id or not bank_id or not currency_id or not org_unit_id or not creation_date:
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = BankAccount.update_bank_account(bank_acc_id, bank_id, currency_id, org_unit_id, creation_date)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: bank_account",
                details=f"Update Bank Account, bank_acc_id: '{bank_acc_id}': bank_id: '{bank_id}'"
                        f": currency_id: '{currency_id}': org_unit_id: '{org_unit_id}': creation_date: '{creation_date}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Bank account updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update bank account.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new bank:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-key-processes', methods=['GET', 'POST'])
@login_required
@role_required(37)
def admin_key_processes():
    key_processes = KeyProcess.get_all_key_processes()
    return render_template('key_processes.html', key_processes=key_processes)


@app.route('/check-currency-name/<string:currencyName>', methods=['GET'])
@login_required
def check_currency_name_exists(currencyName):
    exists = Currency.currency_name_exists(currencyName)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-currency', methods=['POST'])
@login_required
@role_required(7, 8, 9, 10)
def admin_register_new_currency():
    data = request.get_json()

    try:
        # Extract fields
        currencyname = data.get("currencyName", "").strip()
        currencycode = data.get("codeName", "").strip()

        # Validate required fields
        if not all([currencyname]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = Currency.insert_new_currency(currency_name=currencyname, currency_code=currencycode)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: currency",
                details=f"Add Currency, currency_name: '{currencyname}': currency_code: '{currencycode}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Currency added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert currency.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route("/get-currency-details", methods=["GET"])
def get_currency_details():
    currency_name = request.args.get("currency_name")
    currency_details = Currency.get_currency_details(currency_name)

    if not currency_details:
        return jsonify({"error": "Role not found"}), 404

    currency = currency_details[0]

    # Serialize manually
    currency_data = {
        "id": currency.id,
        "currency_name": currency.name,
        "currency_code": currency.code
    }

    return jsonify(currency_data)


@app.route('/admin-update-currency', methods=['POST'])
@login_required
@role_required(7, 8, 9, 10)
def admin_update_currency():
    data = request.get_json()

    try:
        # Extract fields
        currency_id = data.get("currency_id")
        currency_name = data.get("currency_name")
        currency_code = data.get("currency_code")

        # Validate required fields
        if not currency_id or not currency_name or currency_name.strip() == "" or not currency_code or currency_code.strip() == "":
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = Currency.update_currency(currency_id, currency_name, currency_code)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: currency",
                details=f"Update Currency, currency_id: '{currency_id}': currency_name: '{currency_name}': "
                        f"currency_code: '{currency_code}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Currency updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update currency.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-bank-account-responsible-user', methods=['GET', 'POST'])
@login_required
@role_required(35)
def admin_bank_account_responsible_user():
    bank_account_responsible_user_details = BankAccountResponsibleUser.get_all_bank_responsible_person_details()
    bank_accounts = BankAccount.get_all_bank_account_details()
    usernames = UserSummary.get_all_usernames()
    return render_template('bank_account_responsible_user.html',
                           bank_account_responsible_user_details=bank_account_responsible_user_details,
                           bank_accounts=bank_accounts, usernames=usernames)


@app.route('/check-bank-account-responsibility-role/<int:bankAccId>/<int:userId>', methods=['GET'])
@login_required
def check_bank_account_responsibility_role_exists(bankAccId, userId):
    exists = BankAccountResponsibleUser.bank_account_responsibility_exists(bankAccId, userId)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-bank-account-responsibility', methods=['POST'])
@login_required
@role_required(35)
def admin_register_new_bank_account_responsibility():
    data = request.get_json()

    try:
        # Extract fields
        bank_acc_id = data.get("bankAccId")
        user_id = data.get("userId")

        # Validate required fields
        if not all([bank_acc_id, user_id]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        result = BankAccountResponsibleUser.insert_new_bank_account_responsibility(
            bank_acc_id=bank_acc_id,
            user_id=user_id
        )
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert in table: bank_account_responsible_user",
                details=f"Add Bank Account Responsible User, bank_acc_id: '{bank_acc_id}': user_id: '{user_id}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Bank Account responsibility added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert Bank Account responsibility.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route("/get-bank-account-responsibility-details", methods=["GET"])
def get_bank_account_responsibility_details():
    bank_account_name = request.args.get("bank_account_name")
    username = request.args.get("username")
    bank_acc_responsibility_details = BankAccountResponsibleUser.get_bank_account_responsibility_details(
        bank_account_name, username)

    if not bank_acc_responsibility_details:
        return jsonify({"error": "Bank Account responsibility not found"}), 404

    responsibility = bank_acc_responsibility_details[0]

    # Serialize manually
    responsibility_data = {
        "id": responsibility.id,
        "bank_account_id": responsibility.bank_account_id,
        "user_id": responsibility.user_id,
        "is_active": responsibility.is_active
    }

    return jsonify(responsibility_data)


@app.route('/admin-update-bank-account-responsibility', methods=['POST'])
@login_required
@role_required(35)
def admin_update_bank_account_responsibility():
    data = request.get_json()

    try:
        # Extract fields
        responsibility_id = data.get("responsibility_id")
        bank_acc_id = data.get("bank_acc_id")
        user_id = data.get("user_id")
        is_active = int(data.get("is_active"))

        # Validate required fields
        if responsibility_id is None or bank_acc_id is None or user_id is None or is_active is None:
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = BankAccountResponsibleUser.update_bank_account_responsibility(responsibility_id, bank_acc_id, user_id,
                                                                               is_active)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: bank_account_responsible_user",
                details=f"Update Bank Account Responsible User, responsibility_id: '{responsibility_id}': "
                        f"bank_acc_id: '{bank_acc_id}': user_id: '{user_id}': is_active: '{is_active}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Bank Account Responsibility updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update Bank Account Responsibility.", "type": "danger"}), 500

    except Exception as e:
        print("Error updating bank account responsible person:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-organisation-unit-tier', methods=['GET', 'POST'])
@login_required
@role_required(40)
def admin_organisation_unit_tier():
    unit_tier_details = OrganisationUnitTier.get_all_org_unit_tier_details()
    return render_template('organisation_unit_tier.html', unit_tier_details=unit_tier_details)


@app.route('/check-org-unit-tier-name/<string:unit_tier_name>', methods=['GET'])
@login_required
def check_unit_tier_name_exists(unit_tier_name):
    exists = OrganisationUnitTier.org_unit_name_exists(unit_tier_name)
    return jsonify({"exists": exists})


@app.route('/admin-register-org-unit-tier', methods=['POST'])
@login_required
@role_required(40)
def admin_register_org_unit_tier():
    data = request.get_json()

    try:
        # Extract fields
        unit_tier_name = data.get("unit_tier_name", "").strip()
        parent_unit_tier = data.get("parent_unit_tier", "").strip()

        # Validate required fields
        if unit_tier_name is None or parent_unit_tier is None:
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = OrganisationUnitTier.insert_new_org_unit_tier(unit_tier_name=unit_tier_name,
                                                               parent_unit_tier=parent_unit_tier)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: organisation_unit_tier",
                details=f"Add Organisation Unit Tier, unit_tier_name: '{unit_tier_name}': "
                        f"parent_unit_tier: '{parent_unit_tier}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Organisation Unit Tier added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert Organisation Unit Tier.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-update-org-unit-tier', methods=['POST'])
@login_required
@role_required(40)
def admin_update_org_unit_tier():
    data = request.get_json()

    try:
        # Extract fields
        org_unit_tier_id = data.get("org_unit_tier_id")
        org_unit_tier_name = data.get("org_unit_tier_name")
        parent_org_unit_tier_id = data.get("parent_org_unit_tier_id")

        # Validate required fields
        if org_unit_tier_id is None or org_unit_tier_name is None or parent_org_unit_tier_id is None:
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = OrganisationUnitTier.update_org_unit_tier(org_unit_tier_id, org_unit_tier_name,
                                                           parent_org_unit_tier_id)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: organisation_unit_tier",
                details=f"Update Organisation Unit Tier, org_unit_tier_id: '{org_unit_tier_id}': "
                        f"org_unit_tier_name: '{org_unit_tier_name}': "
                        f"parent_org_unit_tier_id: '{parent_org_unit_tier_id}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Organisation Unit Tier updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update Organisation Unit Tier.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/check-org-unit-tier/<string:org_unit_tier_name>/<int:parent_org_unit_tier_id>', methods=['GET'])
@login_required
def check_org_unit_tier_exists(org_unit_tier_name, parent_org_unit_tier_id):
    exists = OrganisationUnitTier.org_unit_tier_exists(org_unit_tier_name, parent_org_unit_tier_id)
    return jsonify({"exists": exists})


@app.route('/admin-organisation-unit', methods=['GET', 'POST'])
@login_required
@role_required(39)
def admin_organisation_unit():
    unit_details = OrganisationUnit.get_all_org_unit_details()
    unit_tier_details = OrganisationUnitTier.get_all_org_unit_tier_details()
    return render_template('organisation_unit.html', unit_details=unit_details, unit_tier_details=unit_tier_details)


@app.route('/check-org-unit-name/<string:unit_name>', methods=['GET'])
@login_required
def check_unit_name_exists(unit_name):
    exists = OrganisationUnit.org_unit_name_exists(unit_name)
    return jsonify({"exists": exists})


@app.route('/admin-register-org-unit', methods=['POST'])
@login_required
@role_required(39)
def admin_register_org_unit():
    data = request.get_json()

    try:
        # Extract fields
        unit_name = data.get("unit_name", "").strip()
        parent_unit = data.get("parent_unit", "").strip()
        unit_tier = data.get("unit_tier", "").strip()

        # Validate required fields
        if unit_name is None or parent_unit is None or unit_tier is None:
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = OrganisationUnit.insert_new_org_unit(unit_name=unit_name, parent_unit=parent_unit, unit_tier=unit_tier)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: organisation_unit",
                details=f"Add Organisation Unit, unit_name: '{unit_name}': parent_unit: '{parent_unit}': "
                        f"unit_tier: '{unit_tier}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Organisation Unit added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert Organisation Unit.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-update-org-unit', methods=['POST'])
@login_required
@role_required(39)
def admin_update_org_unit():
    data = request.get_json()

    try:
        # Extract fields
        org_unit_id = data.get("org_unit_id")
        org_unit_name = data.get("org_unit_name")
        parent_unit_id = data.get("parent_unit_id")
        org_unit_tier_id = data.get("org_unit_tier_id")

        # Validate required fields
        if org_unit_id is None or org_unit_name is None or parent_unit_id is None or org_unit_tier_id is None:
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = OrganisationUnit.update_org_unit(org_unit_id, org_unit_name, parent_unit_id, org_unit_tier_id)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: organisation_unit",
                details=f"Update Organisation Unit, org_unit_id: '{org_unit_id}': "
                        f"org_unit_name: '{org_unit_name}': parent_unit_id: '{parent_unit_id}': "
                        f"org_unit_tier_id: '{org_unit_tier_id}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Organisation Unit updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update Organisation Unit.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/check-org-unit/<string:org_unit_name>/<int:parent_unit_id>/<int:org_unit_tier_id>', methods=['GET'])
@login_required
def check_unit_exists(org_unit_name, parent_unit_id, org_unit_tier_id):
    exists = OrganisationUnit.check_unit_exists(org_unit_name, parent_unit_id, org_unit_tier_id)
    return jsonify({"exists": exists})


@app.route('/admin-workflows', methods=['GET', 'POST'])
@login_required
@role_required(46)
def admin_workflows_page():
    workflow_details = Workflow.get_all_workflow_details()
    return render_template('workflows.html', workflow_details=workflow_details)


@app.route('/check-workflow-name/<string:workflowName>', methods=['GET'])
@login_required
def check_workflow_name_exists(workflowName):
    exists = Workflow.workflow_name_exists(workflowName)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-workflow', methods=['POST'])
@login_required
@role_required(7, 8, 9, 10)
def admin_register_new_workflow():
    data = request.get_json()

    try:
        # Extract fields
        workflowName = data.get("workflowName", "").strip()

        # Validate required fields
        if not all([workflowName]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = Workflow.insert_new_workflow(workflow_name=workflowName)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: workflow",
                details=f"Add Workflow, workflow_name: '{workflow_name}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Workflow added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert workflow.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-update-workflows', methods=['POST'])
@login_required
@role_required(7, 8, 9, 10)
def admin_update_workflows():
    data = request.get_json()

    try:
        # Extract fields
        workflow_id = data.get("workflow_id")
        workflow_name = data.get("workflow_name")

        # Validate required fields
        if workflow_id is None or workflow_name is None:
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = Workflow.update_workflow(workflow_id, workflow_name)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: workflow",
                details=f"Update Workflow, workflow_id: '{workflow_id}', workflow_name: '{workflow_name}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Workflow updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update workflow.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-role-workflow-breakdown', methods=['GET', 'POST'])
@login_required
@role_required(41)
def admin_role_workflow_breakdown():
    role_workflow_breakdown_details = Workflow.get_all_role_workflow_breakdown_details()
    role_details = Role.get_all_role_details()
    workflow_breakdown_details = Workflow.get_all_workflow_breakdown_details()
    return render_template('role_workflow_breakdown.html',
                           role_workflow_breakdown_details=role_workflow_breakdown_details, role_details=role_details,
                           workflow_breakdown_details=workflow_breakdown_details)


@app.route('/check-role-workflow-breakdown/<int:role_id>/<int:workflow_breakdown_id>', methods=['GET'])
@login_required
def check_role_workflow_breakdown_exists(role_id, workflow_breakdown_id):
    exists = Workflow.check_role_workflow_breakdown_exists(role_id, workflow_breakdown_id)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-role-workflow-breakdown', methods=['POST'])
@login_required
@role_required(41)
def admin_register_new_role_workflow_breakdown():
    data = request.get_json()

    try:
        # Extract fields
        role_id = data.get("role_id", "").strip()
        workflow_breakdown_id = data.get("workflow_breakdown_id", "").strip()

        # Validate required fields
        if role_id is None or workflow_breakdown_id is None:
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = Workflow.insert_new_role_workflow_breakdown(role_id, workflow_breakdown_id)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: role_workflow_breakdown",
                details=f"Add Role Workflow Breakdown, role_id: '{role_id}': "
                        f"workflow_breakdown_id: '{workflow_breakdown_id}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Breakdown added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert breakdown.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-update-role-workflow-breakdown-role', methods=['POST'])
@login_required
@role_required(41)
def admin_update_role_workflow_breakdown_role():
    data = request.get_json()

    try:
        # Extract fields
        role_workflow_breakdown_id = data.get("role_workflow_breakdown_id")
        role_id = data.get("role_role_workflow_breakdown_id")
        workflow_breakdown_id = data.get("workflow_role_workflow_breakdown_id")

        # Validate required fields
        if role_workflow_breakdown_id is None or role_id is None or workflow_breakdown_id is None:
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = Workflow.update_role_workflow_breakdown(role_workflow_breakdown_id, role_id, workflow_breakdown_id)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: role_workflow_breakdown",
                details=f"Update Role Workflow Breakdown, role_workflow_breakdown_id: '{role_workflow_breakdown_id}': "
                        f"role_id: '{role_id}': workflow_breakdown_id: '{workflow_breakdown_id}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Role updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update user.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-workflow-breakdown', methods=['GET', 'POST'])
@login_required
@role_required(45)
def admin_workflow_breakdown():
    workflow_breakdown_details = WorkflowBreakdown.get_every_workflow_breakdown_details()
    workflow_details = Workflow.get_all_workflow_details()
    return render_template('workflow_breakdown.html',
                           workflow_breakdown_details=workflow_breakdown_details, workflow_details=workflow_details)


@app.route(
    '/check-workflow-breakdown/<string:workflowBreakdownName>/<int:workflow_id>/<int:level_id>/<int:item_menu_id>/<int:is_responsibility_global>/<int:is_workflow_level>',
    methods=['GET'])
@login_required
def check_workflow_breakdown_exists(workflowBreakdownName, workflow_id, level_id, item_menu_id,
                                    is_responsibility_global, is_workflow_level):
    exists = WorkflowBreakdown.workflow_breakdown_exists(workflowBreakdownName, workflow_id, level_id, item_menu_id,
                                                         is_responsibility_global, is_workflow_level)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-workflow-breakdown', methods=['POST'])
@login_required
@role_required(45)
def admin_register_new_workflow_breakdown():
    data = request.get_json()

    try:
        # Extract fields
        workflowBreakdownName = data.get("workflowBreakdownName", "").strip()
        workflow_id = data.get("workflow_id", "").strip()
        level_id = data.get("level_id", "").strip()
        item_menu_id = data.get("item_menu_id", "").strip()
        is_responsibility_global = data.get("is_responsibility_global", "").strip()
        is_workflow_level = data.get("is_workflow_level", "").strip()

        # Validate required fields
        if not all([workflowBreakdownName, workflow_id, level_id, item_menu_id, is_responsibility_global,
                    is_workflow_level]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = WorkflowBreakdown.insert_new_workflow_breakdown(workflowBreakdownName, workflow_id, level_id,
                                                                 item_menu_id, is_responsibility_global,
                                                                 is_workflow_level)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: workflow_breakdown",
                details=f"Add Workflow-Breakdown, workflowBreakdownName: '{workflowBreakdownName}', "
                        f"workflow_id: '{workflow_id}', level_id: '{level_id}', item_menu_id: '{item_menu_id}', "
                        f"is_responsibility_global: '{is_responsibility_global}', "
                        f"is_workflow_level: '{is_workflow_level}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Workflow breakdown added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert workflow breakdown.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-update-workflow-breakdown', methods=['POST'])
@login_required
@role_required(45)
def admin_update_workflow_breakdown():
    data = request.get_json()

    try:
        # Extract fields
        workflowBreakdownIdEdit = data.get("workflowBreakdownIdEdit")
        workflowBreakdownNameEdit = data.get("workflowBreakdownNameEdit")
        workflowEdit = data.get("workflowEdit")
        levelEdit = data.get("levelEdit")
        item_menu_id_edit = data.get("item_menu_id_edit")
        is_responsibility_global_edit = data.get("is_responsibility_global_edit")
        is_workflow_level_edit = data.get("is_workflow_level_edit")

        # Validate required fields
        if workflowBreakdownIdEdit is None or workflowBreakdownNameEdit is None or workflowEdit is None or levelEdit is None or item_menu_id_edit is None or is_responsibility_global_edit is None or is_workflow_level_edit is None:
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = WorkflowBreakdown.update_workflow_breakdown(workflowBreakdownIdEdit, workflowBreakdownNameEdit,
                                                             workflowEdit, levelEdit, item_menu_id_edit,
                                                             is_responsibility_global_edit, is_workflow_level_edit)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: workflow_breakdown",
                details=f"Update Workflow-Breakdown, workflowBreakdownIdEdit: '{workflowBreakdownIdEdit}', "
                        f"workflowBreakdownNameEdit: '{workflowBreakdownNameEdit}', workflowEdit: '{workflowEdit}', "
                        f"levelEdit: '{levelEdit}', item_menu_id_edit: '{item_menu_id_edit}', "
                        f"is_responsibility_global_edit: '{is_responsibility_global_edit}', "
                        f"is_workflow_level_edit: '{is_workflow_level_edit}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Workflow Breakdown updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update workflow breakdown.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new workflow breakdown:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-menu-items', methods=['GET', 'POST'])
@login_required
@role_required(38)
def admin_menu_items():
    menu_item_details = MenuItem.get_all_menu_item_details()
    return render_template('menu_items.html', menu_item_details=menu_item_details)


@app.route('/check-menu-item-name/<string:menuItemName>', methods=['GET'])
@login_required
def check_menu_item_name_exists(menuItemName):
    exists = MenuItem.menu_item_name_exists(menuItemName)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-menu-item', methods=['POST'])
@login_required
def admin_register_new_menu_item():
    data = request.get_json()

    try:
        # Extract fields
        menuItemName = data.get("menuItemName", "").strip()

        # Validate required fields
        if not all([menuItemName]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = MenuItem.insert_new_menu_item(menuItemName=menuItemName)

        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: menu_item",
                details=f"Add Menu Item, menuItemName: '{menuItemName}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Menu Item added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert menu item.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-update-menu-item', methods=['POST'])
@login_required
@role_required(7, 8, 9, 10)
def admin_update_menu_item():
    data = request.get_json()

    try:
        # Extract fields
        edit_menu_item_id = data.get("edit_menu_item_id")
        menu_item_name = data.get("menu_item_name")

        # Validate required fields
        if edit_menu_item_id is None or menu_item_name is None:
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = MenuItem.update_menu_item(edit_menu_item_id, menu_item_name)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: menu_item",
                details=f"Update Menu Item, edit_menu_item_id: '{edit_menu_item_id}': menu_item_name: '{menu_item_name}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Menu Item updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update Menu Item.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/logout')
def logout_page():
    # Cache user info BEFORE logout
    user_id = current_user.id
    username = current_user.username

    logout_user()
    session.clear()  # Clear session to prevent stored data

    Audit.log_audit_trail(
        user_id=user_id,
        action="User Logout",
        details=f"Logout successful for username '{username}'",
        ip_address=request.remote_addr
    )

    flash("You are logged out!", category='info')
    return redirect(url_for("login_page"))
