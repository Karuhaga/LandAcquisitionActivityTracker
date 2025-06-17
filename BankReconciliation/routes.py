from BankReconciliation import app, os, allowed_file
from BankReconciliation.models import (User, FileUploadBatch, FileUpload, FileDelete, BankAccount,
                                       ReconciliationApprovals, WorkflowBreakdown, EmailHelper, Audit, UserSummary,
                                       Role, UserRole, Currency, BankAccountResponsibleUser, OrganisationUnitTier,
                                       OrganisationUnit, Workflow, MenuItem)
from BankReconciliation.forms import LoginForm
from flask import render_template, redirect, url_for, flash, request, jsonify, session, send_from_directory, abort
import re
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime
from BankReconciliation.rbac import role_required
import json
import threading
from BankReconciliation import app
from collections import defaultdict


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


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard_page():
    if not current_user.is_authenticated:
        return redirect(url_for("login_page"))  # Redirect if user is not authenticated

    user_roles = current_user.roles  # Get user roles

    if "Accountant" in user_roles:
        # Fetch key metrics
        unsubmitted_count = FileUpload.unsubmitted_files_num(current_user.id) or 0
        submitted_count = len(FileUpload.get_submitted_reconciliations(current_user.id))

        # Prepare data for the pie chart
        submission_stats_json = json.dumps({
            "submitted": submitted_count,
            "unsubmitted": unsubmitted_count
        })

        return render_template(
            'dashboard_accountant.html',
            user_roles=user_roles,
            unsubmitted_count=unsubmitted_count,
            submitted_count=submitted_count,
            submission_stats_json=submission_stats_json
        )

    elif "Head of Section" in user_roles or "Head of Department" in user_roles:
        # Fetch reconciliations pending approval and approved reconciliations
        approved_reconciliations = len(FileUpload.get_approved_reconciliations(current_user.id) or [])
        pending_reconciliations = len(FileUpload.get_reconciliations_pending_approval(current_user.id) or [])

        # Prepare data for the pie chart
        reconciliation_stats_json = json.dumps({
            "approved": approved_reconciliations,
            "pending": pending_reconciliations
        })

        return render_template(
            'dashboard_approver.html',
            user_roles=user_roles,
            approved_reconciliations_count=approved_reconciliations,
            reconciliations_pending_approval_submitted_count=pending_reconciliations,
            reconciliation_stats_json=reconciliation_stats_json  # Pass the new data for the pie chart
        )

    return render_template('dashboard.html')


@app.route('/submit-reconciliations', methods=['GET', 'POST'])
@login_required
@role_required(1)
# hint: "@role_required" refers to id of workflow_breakdown database table
def submit_reconciliations_page():
    # Fetch bank accounts from the database
    bank_accounts = BankAccount.get_bank_accounts_for_dropdown_menu(current_user.id)
    if bank_accounts is None:
        return jsonify({"error": "No bank account found in the database"}), 500

    num_of_unsubmitted_files = FileUpload.unsubmitted_files_num(current_user.id)
    if num_of_unsubmitted_files is None:
        return jsonify({"error": "Database error while fetching unsubmitted files"}), 500

    uploaded_files = FileUpload.get_uploaded_pending_submission_files_by_user(current_user.id)
    if uploaded_files is None:
        return jsonify({"error": "Database error while fetching uploaded files"}), 500
    return render_template('submit_reconciliations.html',
                           num_of_unsubmitted_files=num_of_unsubmitted_files,
                           uploaded_files=uploaded_files, bank_accounts=bank_accounts)


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


@app.route('/submit_files', methods=['POST'])
@login_required
@role_required(1)
def submit_files():
    """
    Processes the submission of files by updating their submission_status.
    """
    try:
        data = request.get_json()
        files = data.get("files", [])

        if not files:
            return jsonify({"error": "No files provided"}), 400

        max_submission_status = None

        for file in files:
            bank_account_id = file.get("bank_account_id")
            year = file.get("year")
            month = file.get("month")
            file_name = file.get("file_name")

            # Update file status
            updated_file = FileUpload.update_file_submission_status(bank_account_id, year, month, file_name)
            # Update Audit Trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: file_upload",
                details=f"Reconciliation File Submission, Bank Account Id: '{bank_account_id}', Year: '{year}', "
                        f"Month: '{month}', File Name: '{file_name}'",
                ip_address=request.remote_addr
            )
            if updated_file is None:
                return jsonify({"error": "Database error while updating status of file", "type": "danger"}), 500

            # Get batch_id
            batch_id = FileUpload.get_batch_id(bank_account_id, year, month, file_name)
            if batch_id is None:
                return jsonify({"error": "Database error while updating status of file", "type": "danger"}), 500

            # Pick id of file in file upload table
            id_of_file_upload = FileUploadBatch.get_id_of_file_upload(bank_account_id, year, month, file_name)
            if id_of_file_upload is None:
                return jsonify({"error": "Database error while picking id of uploaded file", "type": "danger"}), 500
            # reconciliation_approvals table
            decision = 1
            level = 1
            comment = ""

            submission_status = FileUpload.get_submission_status_of_reconciliation(id_of_file_upload)
            if max_submission_status is None or submission_status > max_submission_status:
                max_submission_status = submission_status

            last_reconciliation_approvals_id = (ReconciliationApprovals.insert_into_reconciliation_approvals
                                                (id_of_file_upload, decision, current_user.id, level, comment))
            if last_reconciliation_approvals_id is None:
                return jsonify({"error": "Database error while writing to reconciliation_approvals table", "type": "danger"}), 500

            # Update batch status
            updated_batch = FileUploadBatch.update_batch_submission_status(batch_id)
            if updated_batch is None:
                return jsonify({"error": "Database error while updating status of batch", "type": "danger"}), 500

        if max_submission_status is None:
            return jsonify({"error": "Could not determine max submission status", "type": "danger"}), 500

        # Store user details before threading
        user_fname = current_user.fname
        user_id = current_user.id

        # Get next approver(s)
        next_approvers = FileUpload.get_next_approver_fname_email(user_id, max_submission_status)

        if not next_approvers:
            return jsonify({"error": "No next approver found"}), 500

        # Send emails in the background with app context
        def send_emails():
            with app.app_context():  # Ensure Flask app context is available in the thread
                for approver in next_approvers:
                    EmailHelper.send_submitted_reconciliations_email(user_fname, approver["Email"], approver["Fname"], files)

        email_thread = threading.Thread(target=send_emails)
        email_thread.start()

        # Immediately return response while emails are being sent
        return jsonify({"message": "Files submitted successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e), "type": "danger"}), 500


@app.route('/send_email_reminders', methods=['GET', 'POST'])
def send_email_reminders():
    with app.app_context():
        initiators_pending_submission_of_reconciliations = FileUpload.initiators_pending_submission_of_reconciliations()

        for initiator_id in initiators_pending_submission_of_reconciliations:
            # Fetch initiator details
            initiator_fname_email = FileUpload.get_user_fname_email(initiator_id)

            if initiator_fname_email:
                # Optionally get their pending reconciliations
                pending_reconciliation_submission_details = FileUpload.pending_reconciliation_submission_details(
                    initiator_id)
                EmailHelper.email_reminder_to_initiator_reconciliations_pending_submission(initiator_fname_email["fname"],
                                                                              initiator_fname_email["email"],
                                                                              pending_reconciliation_submission_details)

        next_approver_ids = FileUpload.get_next_approver_id(initiators_pending_submission_of_reconciliations)

        for approver_id in next_approver_ids:
            # Fetch initiator details
            approver_fname_email = FileUpload.get_user_fname_email(approver_id)

            if approver_fname_email:
                # Optionally get their pending reconciliations
                pending_reconciliation_submission_details_for_approver = FileUpload.pending_reconciliation_submission_details_for_approver(
                    initiator_id)
                EmailHelper.email_reminder_to_approver_reconciliations_pending_submission(approver_fname_email["fname"],
                                                                              approver_fname_email["email"],
                                                                              pending_reconciliation_submission_details_for_approver)

        user_ids = FileUpload.get_all_user_ids()

        for user_id in user_ids:
            user_fname_email = FileUpload.get_user_fname_email(user_id)

            if user_fname_email:
                pending_approval_details = FileUpload.get_reconciliations_pending_approval(user_id)
                if pending_approval_details:
                    EmailHelper.email_reminder_to_approve_submitted_reconciliations(user_fname_email["fname"],
                                                                                          user_fname_email["email"],
                                                                                          pending_approval_details)


@app.route('/submitted-reconciliations', methods=['GET', 'POST'])
@login_required
@role_required(2)
def submitted_reconciliations_page():
    reconciliations = FileUpload.get_submitted_reconciliations(current_user.id)
    return render_template('submitted_reconciliations.html', reconciliations=reconciliations)


@app.route('/approve-reconciliations', methods=['GET', 'POST'])
@login_required
@role_required(3, 4, 5, 6)
def approve_reconciliations_page():
    reconciliations = FileUpload.get_reconciliations_pending_approval(current_user.id)
    return render_template(
        'approve_reconciliations.html', reconciliations=reconciliations)


@app.route('/approved-reconciliations', methods=['GET', 'POST'])
@login_required
@role_required(3, 4, 5, 6)
def approved_reconciliations_page():
    reconciliations = FileUpload.get_approved_reconciliations(current_user.id)
    return render_template('approved_reconciliations.html', reconciliations=reconciliations)


@app.route('/approve-reconciliations-update', methods=['POST'])
@login_required
@role_required(3, 4, 5, 6)
def approve_reconciliations_update():

    try:
        data = request.get_json()
        action = data.get("action")
        comment = data.get("comment", "").strip()
        files = data.get("files", [])
        decision = 2 if action == "approve" else 3
        action_for_email = "approved" if action == "approve" else "rejected"
        initiator_approvals = defaultdict(list)
        max_submission_status = None

        if not files:
            return jsonify({"error": "No files provided"}), 400

        if action not in ["approve", "reject"]:
            return jsonify({"error": "Invalid action selected"}), 400

        for file in files:
            bank_account_id = file.get("bank_account_id")
            year = file.get("year")
            month = file.get("month")
            file_name = file.get("file_name")

            # Update file status
            updated_reconciliation_record = FileUpload.update_file_approval_status(bank_account_id, year, month,
                                                                                   file_name, action)
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: file_upload",
                details=f"Update submission_status of Reconciliation Request, Bank Account Id: '{bank_account_id}', "
                        f"Year '{year}', Month '{month}', File Name '{file_name}', Action '{action}'",
                ip_address=request.remote_addr
            )
            if updated_reconciliation_record is None:
                return jsonify({"error": "Database error while updating status of file_upload table"}), 500

            # Pick id of file in file upload table
            id_of_file_upload = FileUploadBatch.get_id_of_file_upload(bank_account_id, year, month, file_name)
            if id_of_file_upload is None:
                return jsonify({"error": "Database error while picking id of uploaded file"}), 500

            # Pick latest level of reconciliation file from reconciliation_approvals table
            latest_approval_level = (ReconciliationApprovals.get_latest_reconciliation_approval_level
                                           (id_of_file_upload))
            if latest_approval_level is None:
                return jsonify({"error": "Database error while getting latest_approval_level from "
                                         "reconciliation_approvals table"}), 500

            # reconciliation_approvals table
            level = latest_approval_level + 1

            last_reconciliation_approvals_id = (ReconciliationApprovals.insert_into_reconciliation_approvals
                                                (id_of_file_upload, decision, current_user.id, level, comment))
            if last_reconciliation_approvals_id is None:
                return jsonify({"error": "Database error while writing to reconciliation_approvals table"}), 500

            if decision == 0:
                file_upload_id = FileUpload.update_file_approval_status_following_a_rejected_approval(id_of_file_upload)
                # update audit trail
                user_id = current_user.id
                Audit.log_audit_trail(
                    user_id=user_id,
                    action="Update table: file_upload",
                    details=f"Reconciliation Request Rejection, file_upload_id: '{id_of_file_upload}'",
                    ip_address=request.remote_addr
                )
                if file_upload_id is None:
                    return jsonify({"error": "Database error while updating status of file in file_upload table "
                                             "following a rejected request"}), 500

            # get the user id of the initiator of the bank reconciliation
            initiator_id = FileUploadBatch.get_reconciliation_initiator_user_id(bank_account_id, year, month, file_name)
            if not initiator_id:
                continue  # Skip if no initiator found

            initiator_approvals[initiator_id].append({
                "bank_account": bank_account_id,
                "year": year,
                "month": month,
                "file_name": file_name
            })

            submission_status = FileUpload.get_submission_status_of_reconciliation(id_of_file_upload)
            if max_submission_status is None or submission_status > max_submission_status:
                max_submission_status = submission_status

        if max_submission_status is None:
            return jsonify({"error": "Could not determine max submission status", "type": "danger"}), 500

        # Store user details before threading
        user_fname = current_user.fname
        user_id = current_user.id

        # Get initiator's email and first name
        reconciliation_initiator_email_and_fname = FileUploadBatch.get_reconciliation_initiator_email_and_fname(initiator_id)

        if not reconciliation_initiator_email_and_fname:
            return jsonify({"error": "No initiator of reconciliation found"}), 500

        # Send emails in the background with app context
        def send_emails():
            try:
                with app.app_context():
                    for initiator in reconciliation_initiator_email_and_fname:
                        EmailHelper.send_approval_summary_emails(user_fname, initiator["Email"], initiator["Fname"],
                                                                 files, action_for_email)
            except Exception as e:
                app.logger.error(f"Error in email thread 1: {e}")

        email_thread = threading.Thread(target=send_emails, daemon=True)
        email_thread.start()

        # Get next approver(s)
        if action == "approve":
            next_approvers = FileUpload.get_next_approver_fname_email(user_id, max_submission_status)

            if next_approvers:
                def send_emails2():
                    try:
                        with app.app_context():  # Ensure Flask app context is available in the thread
                            for approver in next_approvers:
                                EmailHelper.send_email_notification_to_next_approver(user_fname, approver["Email"],
                                                                                     approver["Fname"], files)
                    except Exception as e:
                        app.logger.error(f"Error in email thread 2: {e}")

                email_thread2 = threading.Thread(target=send_emails2, daemon=True)
                email_thread2.daemon = True
                email_thread2.start()

            if not next_approvers:
                # return jsonify({"error": "No next approver found"}), 500
                pass

        return jsonify({"message": "Reconciliation(s) approved successfully"}), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get-reconciliation-workflow", methods=["GET"])
def get_reconciliation_workflow():
    bank_account = request.args.get("bank_account")
    reconciliation_year = request.args.get("year")
    reconciliation_month = request.args.get("month")
    file_name = request.args.get("file_name")

    # Pick id of file in file upload table
    id_of_file_upload = FileUploadBatch.get_id_of_file_upload(bank_account, reconciliation_year, reconciliation_month, file_name)
    if id_of_file_upload is None:
        return jsonify({"error": "Database error while picking id of uploaded file", "type": "danger"}), 500

    file_upload_id = id_of_file_upload
    if file_upload_id is None:
        return jsonify({"error": "No matching file found", "type": "danger"}), 500

    # Get the latest approval level for this file
    approvals = ReconciliationApprovals.get_reconciliation_approval_levels_of_given_file(file_upload_id)
    if approvals is None:
        return jsonify({"error": "Database error while picking latest reconciliation approval level of given file",
                        "type": "danger"}), 500

    approval_dict = {a[0]: {"decision": a[1], "approver": a[2], "date": a[3], "comment": a[4]} for a in approvals}

    workflow_id = 1
    # Get workflow breakdown for "Reconciliation Approval" (id=1)
    workflow_steps = WorkflowBreakdown.get_workflow_breakdown_for_reconciliation_approval(workflow_id)
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

    return jsonify({"workflow_steps": workflow_list})


@app.route("/download/<filename>")
@login_required
def download_file(filename):
    """Serves files from the uploads directory."""
    try:
        return send_from_directory(app.config["UPLOAD_FOLDER"], filename, as_attachment=True)
    except FileNotFoundError:
        abort(404)


@app.route('/report-reconciliations-pending-submission', methods=['GET', 'POST'])
@login_required
@role_required(7,8,9,10)
def report_reconciliations_pending_submission_page():
    reconciliations = FileUpload.get_reconciliations_pending_submission()
    return render_template('report_reconciliations_pending_submission.html', reconciliations=reconciliations)


@app.route('/report-all-submitted-reconciliations', methods=['GET', 'POST'])
@login_required
@role_required(7,8,9,10)
def report_all_submitted_reconciliations_page():
    reconciliations = FileUpload.get_all_submitted_reconciliations()
    return render_template('report_all_submitted_reconciliations.html', reconciliations=reconciliations)


@app.route('/report-audit-trail', methods=['GET', 'POST'])
@login_required
@role_required(7,8,9,10)
def report_report_audit_trail_page():
    audit_trail_records = Audit.get_all_audit_trail_records()
    return render_template('report_audit_trail.html', audit_trail_records=audit_trail_records)


@app.route('/report-reconciliations-pending-approval', methods=['GET', 'POST'])
@login_required
@role_required(7,8,9,10)
def report_reconciliations_pending_approval_page():
    reconciliations = FileUpload.get_reconciliations_pending_approval_report()
    return render_template('report_reconciliations_pending_approval.html', reconciliations=reconciliations)


@app.route('/report-fully-approved-reconciliations', methods=['GET', 'POST'])
@login_required
@role_required(7,8,9,10)
def report_fully_approved_reconciliations_page():
    reconciliations = FileUpload.get_fully_approved_reconciliations_report()
    return render_template('report_fully_approved_reconciliations.html', reconciliations=reconciliations)


@app.route('/report-rejected-reconciliations', methods=['GET', 'POST'])
@login_required
@role_required(19, 20, 21)
def report_rejected_reconciliations_page():
    reconciliations = FileUpload.get_rejected_reconciliations_report()
    return render_template('report_rejected_reconciliations.html', reconciliations=reconciliations)


@app.route('/admin-users', methods=['GET', 'POST'])
@login_required
@role_required(7,8,9,10)
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
@role_required(7, 8, 9, 10)
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
@role_required(7,8,9,10)
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
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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


@app.route('/admin-banks', methods=['GET', 'POST'])
@login_required
@role_required(7,8,9,10)
def admin_banks():
    bank_details = BankAccount.get_all_bank_details()
    return render_template('banks.html', bank_details=bank_details)


@app.route('/check-bank-name/<string:bankname>', methods=['GET'])
@login_required
def check_bank_name_exists(bankname):
    exists = BankAccount.bank_name_exists(bankname)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-bank', methods=['POST'])
@login_required
@role_required(7, 8, 9, 10)
def admin_register_new_bank():
    data = request.get_json()

    try:
        # Extract fields
        bankname = data.get("bankName", "").strip()

        # Validate required fields
        if not all([bankname]):
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = BankAccount.insert_new_bank(bank_name=bankname)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Insert into table: bank",
                details=f"Add Bank, bank_name: '{bankname}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Bank added successfully."}), 200
        else:
            return jsonify({"error": "Failed to insert bank.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route("/get-bank-details", methods=["GET"])
def get_bank_details():
    bankname = request.args.get("bank_name")
    bankdetails = BankAccount.get_bank_details(bankname)

    if not bankdetails:
        return jsonify({"error": "Bank not found"}), 404

    bank = bankdetails[0]

    # Serialize manually
    bank_data = {
        "id": bank.id,
        "bankname": bank.name
    }
    return jsonify(bank_data)


@app.route('/admin-update-bank', methods=['POST'])
@login_required
@role_required(7, 8, 9, 10)
def admin_update_bank():
    data = request.get_json()

    try:
        # Extract fields
        bank_id = data.get("bank_id")
        bank_name = data.get("bank_name")

        # Validate required fields
        if not bank_id or not bank_name or bank_name.strip() == "":
            return jsonify({"error": "Missing required fields.", "type": "danger"}), 400

        # Insert user into DB (pseudo-function: implement in your model)
        result = BankAccount.update_bank(bank_id, bank_name)
        if result:
            # update audit trail
            user_id = current_user.id
            Audit.log_audit_trail(
                user_id=user_id,
                action="Update table: bank",
                details=f"Update Bank, bank_id: '{bank_id}': bank_name: '{bank_name}'",
                ip_address=request.remote_addr
            )
            return jsonify({"message": "Bank updated successfully."}), 200
        else:
            return jsonify({"error": "Failed to update bank.", "type": "danger"}), 500

    except Exception as e:
        print("Error inserting new bank:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-bank-accounts', methods=['GET', 'POST'])
@login_required
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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


@app.route('/admin-currencies', methods=['GET', 'POST'])
@login_required
@role_required(7, 8, 9, 10)
def admin_currencies():
    currency_details = Currency.get_all_currency_details()
    return render_template('currencies.html', currency_details=currency_details)


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
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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
    bank_acc_responsibility_details = BankAccountResponsibleUser.get_bank_account_responsibility_details(bank_account_name, username)

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
@role_required(7, 8, 9, 10)
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
        print("Error inserting new user:", e)
        return jsonify({"error": "An error occurred while processing the request.", "type": "danger"}), 500


@app.route('/admin-organisation-unit-tier', methods=['GET', 'POST'])
@login_required
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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
        result = OrganisationUnitTier.insert_new_org_unit_tier(unit_tier_name=unit_tier_name, parent_unit_tier=parent_unit_tier)
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
@role_required(7, 8, 9, 10)
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
        result = OrganisationUnitTier.update_org_unit_tier(org_unit_tier_id, org_unit_tier_name, parent_org_unit_tier_id)
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
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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
@role_required(7,8,9,10)
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
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
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
@role_required(7, 8, 9, 10)
def admin_workflow_breakdown():
    workflow_breakdown_details = WorkflowBreakdown.get_every_workflow_breakdown_details()
    workflow_details = Workflow.get_all_workflow_details()
    return render_template('workflow_breakdown.html',
                           workflow_breakdown_details=workflow_breakdown_details, workflow_details=workflow_details)


@app.route('/check-workflow-breakdown/<string:workflowBreakdownName>/<int:workflow_id>/<int:level_id>/<int:item_menu_id>/<int:is_responsibility_global>/<int:is_workflow_level>', methods=['GET'])
@login_required
def check_workflow_breakdown_exists(workflowBreakdownName, workflow_id, level_id, item_menu_id, is_responsibility_global, is_workflow_level):
    exists = WorkflowBreakdown.workflow_breakdown_exists(workflowBreakdownName, workflow_id, level_id, item_menu_id, is_responsibility_global, is_workflow_level)
    return jsonify({"exists": exists})


@app.route('/admin-register-new-workflow-breakdown', methods=['POST'])
@login_required
@role_required(7, 8, 9, 10)
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
        result = WorkflowBreakdown.insert_new_workflow_breakdown(workflowBreakdownName, workflow_id, level_id, item_menu_id, is_responsibility_global, is_workflow_level)
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
@role_required(7, 8, 9, 10)
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
        result = WorkflowBreakdown.update_workflow_breakdown(workflowBreakdownIdEdit, workflowBreakdownNameEdit, workflowEdit, levelEdit, item_menu_id_edit, is_responsibility_global_edit, is_workflow_level_edit)
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
@role_required(7, 8, 9, 10)
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
