# aap.py - merged, cleaned Flask + Web3 app
import os
import json
import random
import smtplib
import time
import pymysql
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pymysql.cursors import DictCursor
from flask import (
    Flask, render_template, request, redirect, send_from_directory,
    url_for, session, flash
)
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from web3 import Web3
from flask import jsonify
import qrcode
from fpdf import FPDF
from PyPDF2 import PdfReader, PdfWriter
import uuid

# ---------- Auth Helper ----------
from functools import wraps
import os

DB_HOST = os.environ.get("DB_HOST", "localhost")
DB_PORT = int(os.environ.get("DB_PORT", "3306"))
DB_USER = os.environ.get("DB_USER", "root")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "Harish05")
DB_NAME = os.environ.get("DB_NAME", "test")


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ---------------------------
# CONFIG - change if needed
# ---------------------------
MYSQL_USER = "root"
MYSQL_PASSWORD = "Harish05"
MYSQL_DB = "test"
WEB3_PROVIDER = "http://127.0.0.1:7545"
PRIVATE_KEY = "0x64f59e37b026084066f8e14ad5bd8179bf2a7335cc020504efa51f38be3b5300"
CONTRACT_ADDRESS = "0x639be80390F9D29F6C86Ca6D1AD6bfbCb27d2b87"
EMAIL_ADDRESS = "landregistry25@gmail.com"
EMAIL_PASSWORD = "qrhmajfovrgvaabo"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'your_secret_key_here')

OTP_EXPIRY = 10 * 60   

UPLOAD_FOLDER = "static/uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# ---------------------------
# APP INIT
# ---------------------------
app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50 MB limit (adjust if needed)


def get_db_connection():
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )

#---------------------------------------------------------------------------------------------------------------------
#                                    VERIFY OPTION
#-----------------------------------------------------------------------------------------------------------------------
# -------------------------------------------------------------------
#  VERIFY LAND - independent verification (no sell or addproperty)
# -------------------------------------------------------------------
@app.route('/verify_land', methods=['GET', 'POST'])
def verify_land():
    if 'user_id' not in session:
        flash("Please log in to verify land.", "warning")
        return redirect(url_for('login'))

    owner_id = session['user_id']
    ownername = session.get('fullname', session.get('username', 'Unknown'))

    if request.method == 'POST':
        location = request.form.get('location', '')
        size = request.form.get('size', '')
        price = request.form.get('price', '')
        land_type = request.form.get('type', '')
        address = request.form.get('address', '')

        aadhar = save_file(request.files.get('aadhar_card'))
        land_map = save_file(request.files.get('land_map'))
        sales_deed = save_file(request.files.get('sales_deed'))
        property_tax = save_file(request.files.get('property_tax_receipts'))
        encum = save_file(request.files.get('encumbrance_certificate'))
        photos = save_file_list(request.files.getlist('land_photos'))
        photos_str = ','.join(photos) if photos else None

        conn = get_db_connection()
        try:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                # Save land (for verification only)
                cursor.execute("""
                    INSERT INTO lands (
                        owner, ownername, location, size, price, type, address,
                        aadhar_card, land_map, sales_deed, property_tax_receipts,
                        encumbrance_certificate, land_photos,
                        verified, onsale, submitted_from
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'no',0,'verify')
                """, (owner_id, ownername, location, size, price, land_type, address,
                      aadhar, land_map, sales_deed, property_tax, encum, photos_str))
                conn.commit()

                cursor.execute("SELECT LAST_INSERT_ID() AS lid")
                lid = cursor.fetchone()['lid']

                # Create verification request
                cursor.execute("""
                    INSERT INTO verificationrequests (landid, userid, status, requestedat)
                    VALUES (%s, %s, 'pending', %s)
                """, (lid, owner_id, datetime.now()))
                conn.commit()

            flash("Your property has been submitted for verification.", "success")
        finally:
            conn.close()

        return redirect(url_for('home'))

    return render_template('verify_land.html', ownername=ownername)

# -----------------------------------------------------------------------------------
#                                AUTH & USER ROUTES
# --------------------------------------------------------------------------------
@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        fullname = request.form.get('fullname', '').strip()
        phone = request.form.get('phone', '').strip()
        email = request.form.get('email', '').strip()
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not (fullname and email and username and password):
            flash("Please fill required fields.")
            return render_template('signin.html')

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id FROM users WHERE username=%s OR email=%s", (username, email))
                existing = cursor.fetchone()
                if existing:
                    flash("Username or Email already registered")
                    return render_template('signin.html')
                # store hashed password in session until user verifies OTP
                hashed_pw = generate_password_hash(password)
                session['signup_info'] = {
                    'fullname': fullname,
                    'phone': phone,
                    'email': email,
                    'username': username,
                    'password': hashed_pw
                }
                otp = str(random.randint(100000, 999999))
                session['otp'] = otp
                send_email(email, "Your OTP Verification Code", f"Your OTP code is {otp}")
                flash("OTP sent to your email")
        finally:
            conn.close()

        return redirect(url_for('otp_verification'))

    return render_template('signin.html')

@app.route('/otp_verification', methods=['GET', 'POST'])
def otp_verification():
    # ensure we have expected session data
    if 'signup_info' not in session or 'otp' not in session:
        flash("Please sign up first")
        return redirect(url_for('signin'))

    if request.method == 'POST':
        entered = request.form.get('otp', '').strip()
        if entered != session.get('otp'):
            flash("Invalid OTP. Please try again.")
            return render_template('otp_verification.html')

        # OTP matched — attempt to create account safely
        info = session.pop('signup_info', None)
        session.pop('otp', None)

        if not info:
            flash("Signup information missing. Please register again.")
            return redirect(url_for('signin'))

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # double-check uniqueness (race-safe check + catch IntegrityError)
                cursor.execute("SELECT id FROM users WHERE username=%s OR email=%s", (info['username'], info['email']))
                existing = cursor.fetchone()
                if existing:
                    # account already exists (someone created it already)
                    # Log them in if it's their account, otherwise inform them
                    cursor.execute("SELECT id, username FROM users WHERE username=%s", (info['username'],))
                    maybe = cursor.fetchone()
                    if maybe:
                        session['username'] = maybe['username']
                        session['user_id'] = maybe['id']
                        flash("Account already exists — logged you in.", "info")
                        return redirect(url_for('home'))
                    else:
                        flash("An account with that email already exists. Please login.", "warning")
                        return redirect(url_for('login'))

                # Insert the new user
                try:
                    cursor.execute("""
                        INSERT INTO users (fullname, phone, email, username, password)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (info['fullname'], info['phone'], info['email'], info['username'], info['password']))
                    conn.commit()
                    # fetch created id
                    cursor.execute("SELECT id FROM users WHERE username=%s", (info['username'],))
                    created = cursor.fetchone()
                    if created:
                        session['username'] = info['username']
                        session['user_id'] = created['id']
                        flash("Account created and logged in.")
                        return redirect(url_for('home'))
                    else:
                        flash("Account created but login failed; please login.", "warning")
                        return redirect(url_for('login'))

                except IntegrityError as ie:
                    # a race: somebody inserted the same username concurrently
                    conn.rollback()
                    flash("An account with that username or email already exists. Please login.", "warning")
                    return redirect(url_for('login'))

        finally:
            conn.close()

    return render_template('otp_verification.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    session.pop('_flashes', None)

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        app.logger.debug("Login attempt for: %s", username)

        conn = get_db_connection()
        try:
            with conn.cursor(pymysql.cursors.DictCursor) as cur:
                cur.execute("SELECT id, username, password, fullname FROM users WHERE username=%s", (username,))
                user = cur.fetchone()
        finally:
            conn.close()

        if not user:
            flash("Invalid username or password", "danger")
            return render_template('login.html')

        # ✅ FIX: use hash comparison, not direct equality
        if check_password_hash(user['password'], password):
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['fullname'] = user.get('fullname') or user['username']
            flash("Login successful!", "success")
            return redirect(url_for('home'))
        else:
            flash("Invalid username or password", "danger")
            return render_template('login.html')

    return render_template('login.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """
    Page where user can either:
      - Request original password emailed to them (UNSAFE - requires plaintext storage)
      - Request OTP to reset password (safer)
    """
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        action = request.form.get('action', 'otp')  # 'original' or 'otp'

        if not email:
            flash("Please enter your email.", "warning")
            return redirect(url_for('forgot_password'))

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, username, password FROM users WHERE email=%s", (email,))
                user = cursor.fetchone()
        finally:
            conn.close()

        if not user:
            flash("Email not found.", "danger")
            return redirect(url_for('forgot_password'))

        # --- OPTION: send original password from DB (UNSAFE) ---
        if action == 'original':
            # WARNING: This assumes the DB stores the original password in plaintext.
            # If your DB stores a hashed password, emailing the hashed value is useless.
            original_password = user.get('password', '')
            # Compose email
            subject = "Your account password"
            body = (
                f"Hello {user.get('username','user')},\n\n"
                "You requested your account password. Below is the password stored in our system:\n\n"
                f"Password: {original_password}\n\n"
                "If you did not request this, please contact support immediately."
            )
            try:
                send_email(email, subject, body)
                flash("Your password has been sent to your email address.", "info")
            except Exception as e:
                # Do not reveal sensitive exception details to users in production
                flash("Failed to send email. Check the server email configuration.", "danger")
            return redirect(url_for('login'))  # assume you have a login route

        # --- OPTION: send OTP for reset (recommended) ---
        else:
            otp = f"{random.randint(100000, 999999)}"
            # store in session for demo; for production store in DB with expiry and single use
            session['reset_otp'] = otp
            session['reset_email'] = email
            session['reset_otp_time'] = int(time.time())
            try:
                send_email(email, "Password Reset OTP", f"Your password reset OTP is: {otp}\n\nIt expires in 10 minutes.")
                flash("An OTP has been sent to your email. Enter it to reset your password.", "info")
                return redirect(url_for('reset_password_otp'))
            except Exception as e:
                flash("Failed to send OTP email. Check email configuration.", "danger")
                return redirect(url_for('forgot_password'))

    # GET
    return render_template('forgot_password.html')

@app.route('/reset_password_otp', methods=['GET', 'POST'])
def reset_password_otp():
    """
    User enters the OTP emailed to them. If correct & not expired, allow setting new password.
    """
    if 'reset_email' not in session or 'reset_otp' not in session:
        flash("Please initiate the password reset flow first.", "warning")
        return redirect(url_for('forgot_password'))

    otp_time = session.get('reset_otp_time', 0)
    if int(time.time()) - int(otp_time) > OTP_EXPIRY:
        # expire
        session.pop('reset_otp', None)
        session.pop('reset_email', None)
        session.pop('reset_otp_time', None)
        flash("OTP expired. Please request a new OTP.", "warning")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        entered = request.form.get('otp', '').strip()
        if entered == session.get('reset_otp'):
            session['reset_verified'] = True
            flash("OTP verified. You can now set a new password.", "success")
            return redirect(url_for('set_new_password'))
        else:
            flash("Invalid OTP. Try again.", "danger")

    return render_template('reset_password_otp.html')

@app.route('/set_new_password', methods=['GET', 'POST'])
def set_new_password():
    """
    After OTP verification, user sets a new password.
    This will update the DB with the new hashed password.
    """
    if 'reset_email' not in session or not session.get('reset_verified'):
        flash("You must verify the OTP first.", "warning")
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm = request.form.get('confirm_password', '').strip()

        if not password:
            flash("Please enter a new password.", "warning")
            return redirect(url_for('set_new_password'))
        if password != confirm:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('set_new_password'))

        hashed = generate_password_hash(password)
        email = session.get('reset_email')

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("UPDATE users SET password=%s WHERE email=%s", (hashed, email))
                conn.commit()
        finally:
            conn.close()

        # cleanup session reset keys
        for k in ['reset_email', 'reset_otp', 'reset_otp_time', 'reset_verified']:
            session.pop(k, None)

        flash("Password changed successfully. Please login with your new password.", "success")
        return redirect(url_for('login'))

    return render_template('set_new_password.html')

@app.route('/forgot_username', methods=['GET', 'POST'])
def forgot_username():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        cursor = conn.cursor()  # ✅ DictCursor already set globally
        cursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cursor.fetchone()
        cursor.close()
        conn.close()
        
        if user:
            send_email(email, "Your Username Retrieval", f"Your username is: {user['username']}")
            flash("An email has been sent with your username.")
        else:
            flash("Email not found.")
        
        return redirect(url_for('login'))
    return render_template('forgot_username.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'user_id' not in session:
        flash('Please log in first.')
        return redirect(url_for('login'))
    user_id = session['user_id']
    if request.method == 'POST':
        confirm = request.form.get('confirm', '')
        if confirm != 'DELETE':
            flash('Type DELETE to confirm.')
            return redirect(url_for('delete_account'))
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT id, username, email FROM users WHERE id=%s", (user_id,))
                u = cursor.fetchone()
                if not u:
                    flash('User not found.')
                    return redirect(url_for('account_details'))
                cursor.execute("INSERT INTO deleted_users (user_id, username, email) VALUES (%s,%s,%s)",
                               (u['id'], u['username'], u['email']))
                cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
                conn.commit()
                session.clear()
                flash("Account deleted.")
                return redirect(url_for('landing'))
        finally:
            conn.close()
    return render_template('delete_account.html')


#-------------------------------------------------------------------------------------------------------
#                              ADMIN   ROUTES
#------------------------------------------------------------------------------------------------------


@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM admin WHERE username=%s", (username,))
                admin = cursor.fetchone()
        finally:
            conn.close()

        if admin and check_password_hash(admin['password'], password):
            session['is_admin'] = True
            session['admin_name'] = admin['name']
            flash("Login successful!", "success")
            return redirect(url_for('admin_dashboard'))
        else:
            flash("Invalid username or password", "danger")

    return render_template('admin_login.html')


@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM land_inspectors")
            inspectors = cursor.fetchall()
    finally:
        conn.close()

    return render_template(
        'admin_dashboard.html',
        admin_name=session.get('admin_name'),
        inspectors=inspectors
    )

@app.route('/admin/create_inspector', methods=['POST'])
def admin_create_inspector():
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    username = request.form.get('username', '').strip()
    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()
    phone = request.form.get('phone', '').strip()
    password = generate_password_hash(request.form.get('password', ''))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("INSERT INTO land_inspectors (username, password, name, email, phone) VALUES (%s,%s,%s,%s,%s)",
                           (username, password, name, email, phone))
            conn.commit()
    finally:
        conn.close()
    flash("Inspector created", "success")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin_delete_inspector/<int:id>', methods=['POST'])
def admin_delete_inspector(id):
    if not session.get('is_admin'):
        return redirect(url_for('admin_login'))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM land_inspectors WHERE id=%s", (id,))
            insp = cursor.fetchone()
            if insp:
                cursor.execute("INSERT INTO deleted_land_inspectors (username, name, email, phone) VALUES (%s,%s,%s,%s)",
                               (insp['username'], insp['name'], insp['email'], insp['phone']))
                cursor.execute("DELETE FROM land_inspectors WHERE id=%s", (id,))
                conn.commit()
    finally:
        conn.close()
    flash("Inspector deleted")
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/contact_messages')
def admin_contact_messages():
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS contact_messages (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    email VARCHAR(100) NOT NULL,
                    subject VARCHAR(255),
                    message TEXT NOT NULL,
                    message_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()
            cursor.execute("SELECT * FROM contact_messages ORDER BY message_time DESC")
            messages = cursor.fetchall()
    finally:
        conn.close()
    return render_template('admin_contact_messages.html', messages=messages, admin_name=session.get('admin_name'))


@app.route('/delete_contact_message/<int:message_id>', methods=['POST'])
def delete_contact_message(message_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("DELETE FROM contact_messages WHERE id = %s", (message_id,))
            conn.commit()
        flash("Message deleted successfully.", "success")
    finally:
        conn.close()
    return redirect(url_for('admin_contact_messages'))


@app.route('/admin/contact_messages/respond/<int:message_id>', methods=['POST'])
def admin_mark_responded(message_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE contact_messages SET responded='yes' WHERE id=%s", (message_id,))
            conn.commit()
    finally:
        conn.close()
    flash("Message marked responded.")
    return redirect(url_for('admin_contact_messages'))



@app.route('/admin_logout')
def admin_logout():
    session.clear()
    flash("You have been logged out successfully.", "info")
    return redirect(url_for('landing'))  # ✅ sends admin to homepage (index.html)

@app.route('/admin')
def admin():
    return redirect(url_for('admin_login'))


#----------------------------------------------------------------------------------------------------
#                          LAND   INSPECTOR  ROUTES
#----------------------------------------------------------------------------------------------------


@app.route('/landinspector_login', methods=['GET', 'POST'])
def landinspector_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("SELECT * FROM land_inspectors WHERE username=%s", (username,))
                inspector = cursor.fetchone()
        finally:
            conn.close()
        if inspector and check_password_hash(inspector['password'], password):
            session['inspector_username'] = inspector['username']
            session['inspector_name'] = inspector['name']
            return redirect(url_for('landinspector_dashboard'))
        flash("Invalid username/password", "danger")
    return render_template('landinspector_login.html')


@app.route('/landinspector_dashboard')
def landinspector_dashboard():
    if 'inspector_username' not in session:
        return redirect(url_for('landinspector_login'))

    conn = get_db_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT 
                    vr.id AS id,
                    vr.landid AS landid,
                    vr.status AS status,
                    u.fullname AS owner,
                    l.location AS location
                FROM verificationrequests vr
                JOIN lands l ON vr.landid = l.id
                JOIN users u ON l.owner = u.id
                WHERE vr.status = 'pending'
            """)
            verification_requests = cursor.fetchall()
    finally:
        conn.close()

    inspector_name = session.get('inspector_username', 'Inspector')
    return render_template(
        'landinspector_dashboard.html',
        verification_requests=verification_requests,
        inspector_name=inspector_name
    )

@app.route('/verify_property/<int:land_id>', methods=['GET', 'POST'])
def verify_property(land_id):
    if 'inspector_username' not in session:
        return redirect(url_for('landinspector_login'))

    conn = get_db_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:

            cursor.execute("""
                SELECT 
                    l.*, 
                    u.fullname AS ownername,
                    u.email,
                    u.username
                FROM lands l
                JOIN users u ON l.owner = u.id
                WHERE l.id=%s
            """, (land_id,))
            land = cursor.fetchone()

            if not land:
                flash("Property not found.", "danger")
                return redirect(url_for('landinspector_dashboard'))

        # Fetch photos
        photos = []
        if land.get("land_photos"):
            photos = [p.strip() for p in land["land_photos"].split(",") if p.strip()]

        # POST (Verify / Reject)
        if request.method == 'POST':
            action = request.form.get('action')
            rejection_reason = request.form.get('rejection_reason', '').strip()

            with conn.cursor(pymysql.cursors.DictCursor) as cursor:

                # ------------------------------------------------------
                # ❌ Reject
                # ------------------------------------------------------
                if action == "reject":
                    cursor.execute("UPDATE lands SET verified='no', onsale=0 WHERE id=%s", (land_id,))
                    cursor.execute("UPDATE verificationrequests SET status='rejected' WHERE landid=%s", (land_id,))
                    msg = f"❌ Your property in {land['location']} has been rejected.<br>Reason: {rejection_reason}"
                    add_notification(land['owner'], message)
                    conn.commit()
                    flash("Property Rejected.", "warning")
                    return redirect(url_for('landinspector_dashboard'))

                # ------------------------------------------------------
                # ✅ Verify + Generate Certificate
                # ------------------------------------------------------
                cursor.execute("UPDATE lands SET verified='yes' WHERE id=%s", (land_id,))
                cursor.execute("UPDATE verificationrequests SET status='verified' WHERE landid=%s", (land_id,))

                # User password for PDF
                user_password = land['username']

                # Generate certificate
                cert_id, cert_filename = generate_certificate_pdf(land, user_password)

                # Save certificate in DB
                cursor.execute("UPDATE lands SET certificate_id=%s WHERE id=%s", (cert_id, land_id))

                cert_url = url_for('uploaded_file', filename=cert_filename)
                verify_url = url_for('verify_certificate', certificate_id=cert_id, _external=True)

                # Send notification
                message = f"""
                🎉 Your property in <b>{land['location']}</b> has been VERIFIED!<br><br>
                📄 <a href='{cert_url}' target='_blank' download>Download Certificate (PDF)</a><br>
                🔍 <a href='{verify_url}' target='_blank'>Verify Certificate Online</a>
                """
                add_notification(land['owner'], message)

                conn.commit()
                flash("Verification completed!", "success")
                return redirect(url_for('landinspector_dashboard'))

    finally:
        conn.close()

    return render_template("verify_property.html", land=land, photos=photos)







@app.route('/inspect/verify/<int:request_id>', methods=['POST'])
def verify_request(request_id):
    if 'inspector_username' not in session:
        return redirect(url_for('landinspector_login'))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE verificationrequests SET status='approved', inspectedby=%s WHERE id=%s",
                           (session['inspector_username'], request_id))
            cursor.execute("SELECT landid FROM verificationrequests WHERE id=%s", (request_id,))
            land = cursor.fetchone()
            if land:
                cursor.execute("SELECT owner, location FROM lands WHERE id=%s", (land['landid'],))
                linfo = cursor.fetchone()
                if linfo:
                    # Notify the owner
                    message = f"Your property in {linfo['location']} has been approved by the Land Inspector."
                    add_notification(linfo['owner'], message)

                cursor.execute("SELECT submitted_from FROM lands WHERE id=%s", (land['landid'],))
                li = cursor.fetchone()
                if li and li.get('submitted_from') == 'sell':
                    cursor.execute("UPDATE lands SET verified='yes', onsale=1 WHERE id=%s", (land['landid'],))
                else:
                    cursor.execute("UPDATE lands SET verified='yes', onsale=0 WHERE id=%s", (land['landid'],))
            conn.commit()
    finally:
        conn.close()
    flash("Property verified.")
    return redirect(url_for('landinspector_dashboard'))


@app.route('/inspect/reject/<int:request_id>', methods=['POST'])
def inspector_reject_request(request_id):
    # make sure inspector is logged in
    if 'inspector_username' not in session:
        return redirect(url_for('landinspector_login'))

    conn = get_db_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            # mark verification request rejected and record inspector
            cursor.execute("""
                UPDATE verificationrequests
                SET status = 'rejected', inspectedby = %s
                WHERE id = %s
            """, (session['inspector_username'], request_id))

            # find landid from verificationrequests
            cursor.execute("SELECT landid FROM verificationrequests WHERE id = %s", (request_id,))
            land_row = cursor.fetchone()
            if land_row and land_row.get('landid'):
                landid = land_row['landid']

                # fetch owner id and location for notification
                cursor.execute("SELECT owner, location FROM lands WHERE id = %s", (landid,))
                linfo = cursor.fetchone()
                if linfo:
                    owner_id = linfo.get('owner')
                    location = linfo.get('location') or 'the property'

                    # update the land as unverified and not for sale
                    cursor.execute("UPDATE lands SET verified = 'no', onsale = 0 WHERE id = %s", (landid,))

                    # add a notification for the owner
                    if owner_id:
                        message = f"Your property in {location} has been rejected by the Land Inspector."
                        add_notification(owner_id, message)

            conn.commit()
    except Exception as e:
        conn.rollback()
        # optionally log e
        flash("An error occurred while rejecting the verification.", "danger")
    finally:
        conn.close()

    flash("Verification rejected.", "info")
    return redirect(url_for('landinspector_dashboard'))

@app.route('/get_land_docs/<int:landid>')
def get_land_docs(landid):
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM lands WHERE id=%s", (landid,))
            land = cursor.fetchone()
    finally:
        conn.close()

    if not land:
        return jsonify({'error': 'No documents found'}), 404

    def file_url(path):
        return url_for('uploaded_file', filename=path) if path else None

    docs = {
        'Aadhar Card': file_url(land.get('aadhar_card')),
        'Land Map': file_url(land.get('land_map')),
        'Sales Deed': file_url(land.get('sales_deed')),
        'Property Tax Receipts': file_url(land.get('property_tax_receipts')),
        'Encumbrance Certificate': file_url(land.get('encumbrance_certificate')),
        'Land Photos': [file_url(p.strip()) for p in (land.get('land_photos') or '').split(',') if p.strip()]
    }

    return jsonify(docs)

@app.route('/landinspector_logout')
def landinspector_logout():
    session.pop('inspector_username', None)
    session.pop('inspector_name', None)
    flash("Logged out")
    return redirect(url_for('landing'))


#----------------------------------------------------------------------------------------
#                          USER   ROUTES
#----------------------------------------------------------------------------------------

@app.route('/sell', methods=['GET', 'POST'])
def sell():
    if 'user_id' not in session:
        flash("Please login first")
        return redirect(url_for('login'))

    # ✅ Automatically get owner info from session
    owner_id = session['user_id']
    ownername = session.get('fullname', session.get('username', 'Unknown'))

    if request.method == 'POST':
        # Owner name comes from session — no need to read from form
        location = request.form.get('location', '')
        size = request.form.get('size', '')
        price = request.form.get('price', '')
        land_type = request.form.get('type', '')
        address = request.form.get('address', '')

        # Handle file uploads safely
        aadhar = save_file(request.files.get('aadhar_card'))
        land_map = save_file(request.files.get('land_map'))
        sales_deed = save_file(request.files.get('sales_deed'))
        property_tax = save_file(request.files.get('property_tax_receipts'))
        encum = save_file(request.files.get('encumbrance_certificate'))
        photos = save_file_list(request.files.getlist('land_photos'))
        photos_str = ','.join(photos) if photos else None

        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                # Insert into lands
                cursor.execute("""
                    INSERT INTO lands (
                        owner, ownername, location, size, price, type, address,
                        aadhar_card, land_map, sales_deed, property_tax_receipts,
                        encumbrance_certificate, land_photos,
                        verified, onsale, submitted_from
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'no',0,'sell')
                """, (owner_id, ownername, location, size, price, land_type, address,
                      aadhar, land_map, sales_deed, property_tax, encum, photos_str))
                conn.commit()

                # Get inserted land ID
                cursor.execute("SELECT LAST_INSERT_ID() AS lid")
                lid = cursor.fetchone()['lid']

                # Create verification request
                cursor.execute("""
                    INSERT INTO verificationrequests (landid, userid, status, requestedat)
                    VALUES (%s, %s, 'pending', %s)
                """, (lid, owner_id, datetime.now()))
                conn.commit()
        finally:
            conn.close()

        flash("Property submitted for verification. It will appear for sale after approval.", "success")
        return redirect(url_for('myproperties'))

    # ✅ Pass owner name to prefill in template
    return render_template('sell.html', ownername=ownername)


@app.route('/sell_land/<int:landid>', methods=['POST'])
def sell_land(landid):
    # your logic here

    if 'user_id' not in session:
        flash("You must be logged in to sell your property.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()


    try:
        cursor = conn.cursor(DictCursor)

        # ✅ Step 1: Check ownership and property
        cursor.execute("SELECT * FROM lands WHERE id = %s AND owner = %s", (landid, user_id))
        land = cursor.fetchone()

        if not land:
            flash("Invalid request — property not found or not owned by you.", "danger")
            return redirect(url_for('myproperties'))

        # ✅ Step 2: Ensure property is verified
        if land['verified'] != 'yes':
            flash("This property is not verified yet. You cannot list it for sale.", "warning")
            return redirect(url_for('property_detail', land_id=landid))

        # ✅ Step 3: Prevent duplicates
        if land['onsale'] == 1:
            flash("This property is already listed for sale.", "info")
            return redirect(url_for('myproperties'))

        # ✅ Step 4: Update onsale = 1
        cursor.execute("UPDATE lands SET onsale = 1 WHERE id = %s", (landid,))
        conn.commit()

        flash("✅ Your property is now listed for sale successfully!", "success")
        return redirect(url_for('myproperties'))

    except Exception as e:
        conn.rollback()
        print("Error in sell_land:", e)
        flash("An error occurred while listing your property for sale.", "danger")
        return redirect(url_for('myproperties'))
    finally:
        cursor.close()
        conn.close()

@app.route('/addproperty', methods=['GET', 'POST'])
def add_property():
    if 'user_id' not in session:
        flash("Please login first")
        return redirect(url_for('login'))

    if request.method == 'POST':
        owner_id = session['user_id']
        ownername = session.get('fullname', '')
        location = request.form.get('location', '')
        size = request.form.get('size', '')
        price = request.form.get('price', '')
        land_type = request.form.get('type', '')
        address = request.form.get('address', '')

        aadhar = save_file(request.files.get('aadhar_card'))
        land_map = save_file(request.files.get('land_map'))
        sales_deed = save_file(request.files.get('sales_deed'))
        property_tax = save_file(request.files.get('property_tax_receipts'))
        encum = save_file(request.files.get('encumbrance_certificate'))
        photos = save_file_list(request.files.getlist('land_photos'))
        photos_str = ','.join(photos) if photos else None

        conn = get_db_connection()
        try:
            with conn.cursor(pymysql.cursors.DictCursor) as cursor:
                # Insert land record
                cursor.execute("""
                    INSERT INTO lands (
                        owner, ownername, location, size, price, type, address,
                        aadhar_card, land_map, sales_deed, property_tax_receipts,
                        encumbrance_certificate, land_photos,
                        verified, onsale, submitted_from
                    )
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'no',0,'addproperty')
                """, (owner_id, ownername, location, size, price, land_type, address,
                      aadhar, land_map, sales_deed, property_tax, encum, photos_str))
                conn.commit()

                # Get the new land ID
                cursor.execute("SELECT LAST_INSERT_ID() AS lid")
                land = cursor.fetchone()
                landid = land['lid']

                # Create verification request automatically
                cursor.execute("""
                    INSERT INTO verificationrequests (landid, userid, status, requestedat)
                    VALUES (%s, %s, 'pending', %s)
                """, (landid, owner_id, datetime.now()))
                conn.commit()
        finally:
            conn.close()

        flash("Property added successfully and pending verification.", "success")
        return redirect(url_for('myproperties'))

    return render_template('add_property.html', ownername=session.get('fullname', ''))

@app.route('/myproperties')
def myproperties():
    if 'user_id' not in session:
        flash("Please login first")
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT id, location, price, type, verified, onsale, submitted_from
                FROM lands WHERE owner=%s
            """, (session['user_id'],))
            props = cursor.fetchall()
    finally:
        conn.close()

    return render_template('myproperties.html', properties=props)

@app.route('/property_detail/<int:land_id>')
def property_detail(land_id):
    conn = get_db_connection()
    try:
        with conn.cursor(DictCursor) as cursor:  # ✅ PyMySQL-compatible cursor
            cursor.execute("SELECT * FROM lands WHERE id = %s", (land_id,))
            land = cursor.fetchone()
    finally:
        conn.close()

    if not land:
        flash("Property not found!", "danger")
        return redirect(url_for('myproperties'))

    # Extract document details
    documents = {
        "Aadhar Card": land.get("aadhar_card"),
        "Land Map": land.get("land_map"),
        "Sales Deed": land.get("sales_deed"),
        "Property Tax Receipts": land.get("property_tax_receipts"),
        "Encumbrance Certificate": land.get("encumbrance_certificate")
    }

    # Split photos (if available)
    photos = []
    if land.get("land_photos"):
        photos = [p.strip() for p in land["land_photos"].split(",") if p.strip()]
    land["photos"] = photos

    return render_template("property_detail.html", land=land, documents=documents)

@app.route('/editproperty/<int:landid>', methods=['GET', 'POST'])
def editproperty(landid):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user_id = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT * FROM lands WHERE id=%s", (landid,))
            land = cursor.fetchone()
            if not land:
                flash("Property not found.")
                return redirect(url_for('myproperties'))
            if land['owner'] != user_id:
                flash("Not authorized.")
                return redirect(url_for('myproperties'))

            if request.method == 'POST':
                location = request.form.get('location', '').strip()
                size = request.form.get('size', '').strip()
                price = request.form.get('price', '').strip()
                land_type = request.form.get('type', '').strip()
                address = request.form.get('address', '').strip()

                aadhar_card = request.files.get('aadhar_card')
                land_map = request.files.get('land_map')
                sales_deed = request.files.get('sales_deed')
                property_tax_receipts = request.files.get('property_tax_receipts')
                encumbrance_certificate = request.files.get('encumbrance_certificate')
                land_photos = request.files.getlist('land_photos') or []

                updates = {}
                if location: updates['location'] = location
                if size: updates['size'] = size
                if price: updates['price'] = price
                if land_type: updates['type'] = land_type
                if address: updates['address'] = address

                # file replacements
                if aadhar_card and aadhar_card.filename:
                    updates['aadhar_card'] = save_file(aadhar_card)
                if land_map and land_map.filename:
                    updates['land_map'] = save_file(land_map)
                if sales_deed and sales_deed.filename:
                    updates['sales_deed'] = save_file(sales_deed)
                if property_tax_receipts and property_tax_receipts.filename:
                    updates['property_tax_receipts'] = save_file(property_tax_receipts)
                if encumbrance_certificate and encumbrance_certificate.filename:
                    updates['encumbrance_certificate'] = save_file(encumbrance_certificate)
                if land_photos:
                    existing_photos = land.get('land_photos') or ''
                    existing_list = [x for x in existing_photos.split(',') if x.strip()]
                    for p in land_photos:
                        if p and p.filename:
                            saved = save_file(p)
                            if saved:
                                existing_list.append(saved)
                    updates['land_photos'] = ','.join(existing_list) if existing_list else None

                # build update statement
                set_parts = []
                params = []
                for k, v in updates.items():
                    if v is not None:
                        set_parts.append(f"{k}=%s")
                        params.append(v)

                # force re-verification if edited
                set_parts.append("verified='no'")
                set_parts.append("onsale=0")
                set_clause = ", ".join(set_parts)
                params.append(landid)
                if set_clause:
                    cursor.execute(f"UPDATE lands SET {set_clause} WHERE id=%s", tuple(params))
                    conn.commit()
                # add verification request
                cursor.execute("INSERT INTO verificationrequests (landid, userid, status, requestedat) VALUES (%s,%s,'pending',%s)",
                               (landid, user_id, datetime.now()))
                conn.commit()
                add_notification(user_id, f"Property (ID: {landid}) edited and sent for re-verification.")
                flash("Property updated and sent for re-verification.")
                return redirect(url_for('myproperties'))
    finally:
        conn.close()
    # GET -> render the edit form
    return render_template('editproperty.html', land=land)

@app.route('/deleteproperty/<int:landid>', methods=['GET', 'POST'])
def deleteproperty(landid):
    if 'user_id' not in session:
        flash("Please log in.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor(DictCursor) as cursor:
            # Check property ownership
            cursor.execute("SELECT owner FROM lands WHERE id=%s", (landid,))
            row = cursor.fetchone()

            if not row:
                flash("Property not found.", "danger")
                return redirect(url_for('myproperties'))

            if str(row['owner']) != str(user_id):
                flash("Not authorized to delete this property.", "danger")
                return redirect(url_for('myproperties'))

            # Delete related records first
            cursor.execute("DELETE FROM verificationrequests WHERE landid=%s", (landid,))
            cursor.execute("DELETE FROM transferrequests WHERE landid=%s", (landid,))
            cursor.execute("DELETE FROM lands WHERE id=%s", (landid,))
            conn.commit()

        flash("Property deleted successfully!", "success")
    finally:
        conn.close()

    return redirect(url_for('myproperties'))

#----------------------------------------------------------------------------------------------
#                        BUY/ MARKET PLACE
#------------------------------------------------------------------------------------------

@app.route('/buy')
def buy():
    if 'user_id' not in session:
        flash("Please log in to view properties.", "warning")
        return redirect(url_for('login'))

    current_user = session['user_id']

    conn = get_db_connection()
    lands_for_sale = []
    try:
        with conn.cursor(DictCursor) as cursor:
            # ✅ Only show verified + onsale = 1
            # ✅ Hide properties owned by the current user
            cursor.execute("""
                SELECT * FROM lands 
                WHERE onsale = 1 
                AND verified = 'yes' 
                AND owner != %s
            """, (current_user,))
            results = cursor.fetchall()

            for land in results:
                land['size'] = land.get('size') or '0'
                land['price'] = land.get('price') or 0
                land['type'] = land.get('type') or 'N/A'
                land['location'] = land.get('location') or 'Unknown'
                land['ownername'] = land.get('ownername') or 'Unknown'
                land['land_photos'] = land.get('land_photos') or ''
                lands_for_sale.append(land)
    finally:
        conn.close()

    return render_template('buy.html', lands=lands_for_sale)

@app.route('/land/<int:landid>')
def landdetail(landid):
    conn = None
    cursor = None

    try:
        # 1️⃣ Open connection and cursor
        conn = get_db_connection()
        cursor = conn.cursor()

        # 2️⃣ Fetch the land record
        cursor.execute("SELECT * FROM lands WHERE id = %s", (landid,))
        land = cursor.fetchone()

        if not land:
            flash("Land not found.", "danger")
            return redirect(url_for('buy'))

        # 3️⃣ Prepare image list
        photo_list = []
        photo = None
        if land.get('land_photos'):
            photo_list = [p.strip() for p in land['land_photos'].split(',') if p.strip()]
            if photo_list:
                photo = photo_list[0]

        # 4️⃣ Return page (✅ don't close connection yet)
        return render_template('landdetail.html', land=land, photos=photo_list, main_photo=photo)

    except Exception as e:
        print("Error in landdetail:", e)
        flash("An error occurred while fetching land details.", "danger")
        return redirect(url_for('buy'))

    finally:
        # ✅ Close safely only if open
        if cursor:
            try:
                cursor.close()
            except Exception:
                pass
        if conn:
            try:
                conn.close()
            except Exception:
                pass
            
@app.route('/requesttransfer/<int:landid>', methods=['POST'])
def requesttransfer(landid):
    if 'user_id' not in session:
        flash("Please log in to buy land.")
        return redirect(url_for('login'))

    buyerid = session['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT id FROM transferrequests 
                WHERE landid=%s AND buyer=%s AND (status='pending' OR status='approved')
            """, (landid, buyerid))
            if cursor.fetchone():
                flash("You already sent a request.")
                return redirect(url_for('buy'))

            cursor.execute("SELECT owner, location FROM lands WHERE id=%s", (landid,))
            land = cursor.fetchone()
            if not land:
                flash("Land not found.")
                return redirect(url_for('buy'))

            sellerid = land['owner']
            location = land['location']

            cursor.execute("""
                INSERT INTO transferrequests (landid, buyer, seller, status, requestedat)
                VALUES (%s, %s, %s, 'pending', %s)
            """, (landid, buyerid, sellerid, datetime.now()))
            conn.commit()

            # Add notification for seller
            # Add notification for seller WITH BUYER PHOTO
            buyerid = session['user_id']

            message = f"A buyer has requested to purchase your property located in {location}."
            add_notification(sellerid, message, sender_id=buyerid)


    finally:
        conn.close()

    flash("Request sent to seller.")
    return redirect(url_for('buy'))

@app.route('/reject_request/<int:request_id>', methods=['POST'])
def reject_request(request_id):
    if 'user_id' not in session:
        flash("Please log in")
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("UPDATE transferrequests SET status='rejected' WHERE id=%s", (request_id,))
            cursor.execute("""
                SELECT tr.buyer, l.location 
                FROM transferrequests tr 
                JOIN lands l ON tr.landid = l.id 
                WHERE tr.id=%s
            """, (request_id,))
            data = cursor.fetchone()
            if data:
                buyerid = data['buyer']
                location = data['location']
                message = f"Your request to purchase the property in {location} has been REJECTED."
                add_notification(buyid, message, sender_id=sellerid)

            conn.commit()
    finally:
        conn.close()

    flash("Request rejected.")
    return redirect(url_for('request_page')) 


#------------------------------------------------------------------------------------------------------
#                               REQUEST ROUTES
#------------------------------------------------------------------------------------------------------

@app.route('/requests')
def request_page():
    if 'user_id' not in session:
        flash("Please login first.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()

    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:

            # ----------------------
            # BUY REQUESTS RECEIVED
            # ----------------------
            cursor.execute("""
                SELECT 
                    tr.id,
                    tr.landid,
                    tr.status,
                    tr.requestedat AS requested_at,
                    u.fullname AS buyer_name,
                    u.email AS buyer_email,
                    u.phone AS buyer_phone,
                    u.profile_photo AS buyer_photo,
                    l.location AS property_location,
                    l.type AS property_type,
                    l.price,
                    l.land_photos
                FROM transferrequests tr
                JOIN users u ON tr.buyer = u.id
                JOIN lands l ON tr.landid = l.id
                WHERE tr.seller = %s
                ORDER BY tr.requestedat DESC
            """, (user_id,))
            received_requests = cursor.fetchall()

            # ----------------------
            # BUY REQUESTS SENT
            # ----------------------
            cursor.execute("""
                SELECT 
                    tr.id,
                    tr.landid,
                    tr.status,
                    tr.requestedat AS requested_at,
                    u.fullname AS seller_name,
                    u.email AS seller_email,
                    u.phone AS seller_phone,
                    u.profile_photo AS seller_photo,
                    l.location AS property_location,
                    l.type AS property_type,
                    l.price,
                    l.land_photos
                FROM transferrequests tr
                JOIN users u ON tr.seller = u.id
                JOIN lands l ON tr.landid = l.id
                WHERE tr.buyer = %s
                ORDER BY tr.requestedat DESC
            """, (user_id,))
            sent_requests = cursor.fetchall()

    finally:
        conn.close()

    return render_template(
        'request_page.html',
        received_requests=received_requests,
        sent_requests=sent_requests
    )

@app.route("/request_details/<int:request_id>")
def request_details(request_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:

            cursor.execute("""
                SELECT 
                    tr.id,
                    tr.status,
                    tr.requestedat,
                    u.fullname,
                    u.email,
                    u.phone,
                    u.profile_photo,
                    l.location,
                    l.type,
                    l.price,
                    l.land_photos
                FROM transferrequests tr
                JOIN users u ON tr.buyer = u.id
                JOIN lands l ON tr.landid = l.id
                WHERE tr.id = %s
            """, (request_id,))
            data = cursor.fetchone()
    finally:
        conn.close()

    if not data:
        flash("Request not found!", "danger")
        return redirect(url_for('request_page'))

    # Format masked phone: only last 3 digits shown
    try:
        raw_phone = data['phone']
        masked = "xxxxxx" + raw_phone[-4:]
    except:
        masked = "Hidden"

    data['masked_phone'] = masked

    # Extract first image
    if data['land_photos']:
        photos = [p.strip() for p in data['land_photos'].split(",") if p.strip()]
        data['main_photo'] = photos[0] if photos else None
    else:
        data['main_photo'] = None

    return render_template("request_details.html", data=data)

@app.route('/delete_request/<int:req_id>')
def delete_request(req_id):
    if 'user_id' not in session:
        flash("Login required!", "danger")
        return redirect(url_for('login'))

    uid = session['user_id']
    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:
            # Allow delete only if user is buyer OR seller
            cursor.execute("""
                DELETE FROM transferrequests
                WHERE id=%s AND (buyer=%s OR seller=%s)
            """, (req_id, uid, uid))
            conn.commit()
    finally:
        conn.close()

    flash("Request deleted successfully!", "success")
    return redirect(url_for('request_page'))



@app.route('/approve_request/<int:request_id>', methods=['POST'])
@login_required
def approve_request(request_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT buyer, landid FROM transferrequests WHERE id=%s", (request_id,))
            req = cur.fetchone()
            if not req:
                flash("Request not found.", "danger")
                return redirect(url_for('request_page'))

            cur.execute("UPDATE transferrequests SET status='approved' WHERE id=%s", (request_id,))
            cur.execute("UPDATE lands SET owner=%s, onsale=0 WHERE id=%s", (req['buyer'], req['landid']))
            conn.commit()
        flash("Request approved and ownership transferred.", "success")
    except Exception:
        conn.rollback()
        flash("Could not approve request.", "danger")
    finally:
        conn.close()
    return redirect(url_for('request_page'))

@app.route('/reject_transfer_request/<int:request_id>', methods=['POST'])
@login_required
def reject_transfer_request(request_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE transferrequests SET status='rejected' WHERE id=%s", (request_id,))
            conn.commit()
        flash("Request rejected.", "info")
    except Exception:
        conn.rollback()
        flash("Could not reject request.", "danger")
    finally:
        conn.close()
    return redirect(url_for('request_page'))


@app.route('/cancel_request/<int:request_id>', methods=['POST'])
@login_required
def cancel_request(request_id):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM transferrequests WHERE id=%s", (request_id,))
            conn.commit()
        flash("Your request was cancelled.", "info")
    except Exception:
        conn.rollback()
        flash("Could not cancel request.", "danger")
    finally:
        conn.close()
    return redirect(url_for('request_page'))

@app.route('/approverequest1/<int:requestid>', methods=['POST'])
def approverequest1(requestid):
    if 'user_id' not in session:
        flash("Please log in")
        return redirect(url_for('login'))

    conn = get_db_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("UPDATE transferrequests SET status='approved' WHERE id=%s", (requestid,))
            cursor.execute("""
                SELECT tr.buyer, l.location
                FROM transferrequests tr
                JOIN lands l ON tr.landid = l.id
                WHERE tr.id=%s
            """, (requestid,))
            data = cursor.fetchone()
            if data:
                buyerid = data['buyer']
                location = data['location']
                message = f"Your request to purchase the property in {location} has been APPROVED."
                add_notification(buyid, message, sender_id=sellerid)

            conn.commit()
    finally:
        conn.close()

    flash("Request approved.")
    return redirect(url_for('request_page'))


#---------------------------------------------------------------------------------------------------------------
#                    NOTIFICATIONS &  PROFILE ROUTES
#--------------------------------------------------------------------------------------------------------------------

@app.route("/notifications")
def notifications():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = get_db_connection()
    with conn.cursor(pymysql.cursors.DictCursor) as cursor:
        cursor.execute("""
            SELECT id, message, created_at, photo 
            FROM notifications
            WHERE userid = %s
            ORDER BY created_at DESC
        """, (user_id,))
        notifications = cursor.fetchall()

    return render_template("notifications.html", notifications=notifications)

@app.route("/get_unseen_notifications")
def get_unseen_notifications():
    if "user_id" not in session:
        return {"count": 0}

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                "SELECT COUNT(*) FROM notifications WHERE user_id=%s AND seen=0",
                (session['user_id'],)
            )
            count = cursor.fetchone()[0]
        return {"count": count}

    finally:
        conn.close()   # VERY IMPORTANT





@app.route('/mark_notifications_seen')
def mark_notifications_seen():
    user_id = session.get('user_id')
    if not user_id:
        return redirect(url_for('login'))
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("UPDATE notifications SET seen=1 WHERE userid=%s", (user_id,))
            conn.commit()
    finally:
        conn.close()
    return '', 204

@app.route('/delete_notification/<int:notification_id>', methods=['POST'])
def delete_notification(notification_id):
    if 'user_id' not in session:
        flash("Please log in.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = get_db_connection()

    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                DELETE FROM notifications 
                WHERE id = %s AND userid = %s
            """, (notification_id, user_id))
            conn.commit()
    finally:
        conn.close()

    flash("Notification deleted.", "info")
    return redirect(url_for('notifications'))

@app.route('/delete_multiple_notifications', methods=['POST'])
def delete_multiple_notifications():
    if 'user_id' not in session:
        flash("Please log in first.", "warning")
        return redirect(url_for('login'))

    delete_ids = request.form.getlist('delete_ids')

    if not delete_ids:
        flash("No notifications selected.", "warning")
        return redirect(url_for('notifications'))

    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            query = "DELETE FROM notifications WHERE userid=%s AND id IN (" + \
                     ",".join(["%s"] * len(delete_ids)) + ")"

            cursor.execute(query, (session['user_id'], *delete_ids))
            conn.commit()

    finally:
        conn.close()

    flash("Selected notifications deleted.", "success")
    return redirect(url_for('notifications'))



@app.route('/edit_profile', methods=['POST'])
def edit_profile():
    if 'username' not in session:
        flash("Please log in.")
        return redirect(url_for('login'))
    username = session['username']
    fullname = request.form.get('fullname', '').strip()
    phone = request.form.get('phone', '').strip()
    email = request.form.get('email', '').strip()
    photo_filename = None
    file = request.files.get('profile_photo')
    if file and allowed_file(file.filename):
        photo_filename = save_file(file)
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            if photo_filename:
                cursor.execute("UPDATE users SET fullname=%s, phone=%s, email=%s, profile_photo=%s WHERE username=%s",
                               (fullname, phone, email, photo_filename, username))
            else:
                cursor.execute("UPDATE users SET fullname=%s, phone=%s, email=%s WHERE username=%s",
                               (fullname, phone, email, username))
            conn.commit()
    finally:
        conn.close()
    flash("Profile updated.")
    return redirect(url_for('account_details'))

@app.route('/account_details')
def account_details():
    if 'username' not in session:
        return redirect(url_for('login'))
    username = session['username']
    conn = get_db_connection()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT fullname, phone, email, username, profile_photo FROM users WHERE username=%s", (username,))
            user = cursor.fetchone()
    finally:
        conn.close()
    if not user:
        flash("User not found.")
        return redirect(url_for('login'))
    return render_template('account_details.html', user=user)

def add_notification(user_id, message, sender_id=None):
    conn = get_db_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:

            # Default sender = user himself
            if sender_id is None:
                sender_id = user_id

            # Fetch sender's profile photo
            cursor.execute("SELECT profile_photo FROM users WHERE id=%s", (sender_id,))
            profile = cursor.fetchone()
            photo = profile['profile_photo'] if profile and profile['profile_photo'] else None

            cursor.execute("""
                INSERT INTO notifications (userid, message, photo)
                VALUES (%s, %s, %s)
            """, (user_id, message, photo))

            conn.commit()

    finally:
        conn.close()




#-----------------------------------------------------------------------------------------------------
#                          MISC  ROUTES
#---------------------------------------------------------------------------------------------------


@app.route('/')
def landing():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/faqs')
def faqs():
    return render_template('faqs.html')

@app.route('/learnmore')
def learnmore():
    return render_template('learnmore.html')

@app.route('/help')
def help_page():
    return render_template('help.html')

@app.route('/shome')
def shome():
    return render_template('shome.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()
        message_time = datetime.now()
        conn = get_db_connection()
        try:
            with conn.cursor() as cursor:
                cursor.execute("INSERT INTO contact_messages (name,email,message,message_time,responded) VALUES (%s,%s,%s,%s,%s)",
               (name, email, message, message_time, 0))

                conn.commit()
        finally:
            conn.close()
        send_email(EMAIL_ADDRESS, f"Contact from {name}", f"Name: {name}\nEmail: {email}\nTime: {message_time}\n\nMessage:\n{message}")
        flash("Message sent. We'll get back to you.")
        return redirect(url_for('contact'))
    return render_template('contact.html')

@app.route('/home')
def home():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('home.html')



# -------------------------------------------------------------------------------------------
#                                         Email helper
# ------------------------------------------------------------------------------------------------
def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        s = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        s.starttls()
        s.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        s.send_message(msg)
        s.quit()
        return True
    except Exception as e:
        app.logger.warning("send_email failed: %s", e)
        return False

#----------------------------------------------------------------------------------------------
#                        UTILS 
#------------------------------------------------------------------------------------------



def save_file(file):
    """Save uploaded file safely and return the filename (stored in DB)."""
    if not file or file.filename == '':
        return None

    # Create unique filename (avoids overwriting)
    ext = os.path.splitext(file.filename)[1]  # e.g. .pdf or .jpg
    unique_name = f"{uuid.uuid4().hex}{ext}"
    filename = secure_filename(unique_name)

    # Ensure upload folder exists
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

    # Save file to upload folder
    path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(path)

    return filename


def save_file_list(file_list):
    files = []
    for f in file_list:
        if f and f.filename != '':
            files.append(save_file(f))
    return files

def allowed_file(filename):
    """
    Allowed extensions for uploads. Adjust to include other types you want.
    """
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory('static/uploads', filename)




def generate_certificate_pdf(land, user_password):
    """Generate an official, QR-secured, password-protected land verification certificate."""

    certificate_id = str(uuid.uuid4())[:8]  # Unique short ID
    cert_filename = f"{certificate_id}.pdf"
    cert_path = os.path.join(app.config['UPLOAD_FOLDER'], cert_filename)

    verify_url = url_for('verify_certificate', certificate_id=certificate_id, _external=True)
    # Save certificate_id in lands table
    


    # ----------------------------------------------------------------------
    # 🧠 Create QR Code with summarized land info
    # ----------------------------------------------------------------------
    qr_data = (
        f"🏡 Digital Land Verification Certificate\n"
        f"-----------------------------------------\n"
        f"Certificate ID: {certificate_id}\n"
        f"Owner: {land['ownername']}\n"
        f"Location: {land['location']}\n"
        f"Type: {land['type']}\n"
        f"Size: {land['size']} sq.ft\n"
        f"Price: Rs. {land['price']}\n"
        f"Verified on: {datetime.now().strftime('%d-%m-%Y %H:%M:%S')}\n"
        f"Verification Link: {verify_url}"
    )

    qr_img = qrcode.make(qr_data)
    qr_temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"qr_{certificate_id}.png")
    qr_img.save(qr_temp_path)

    # ----------------------------------------------------------------------
    # 🧾 Create Certificate PDF Layout
    # ----------------------------------------------------------------------
    pdf = FPDF()
    pdf.add_page()

    # 🔷 Draw blue border
    pdf.set_draw_color(20, 60, 180)
    pdf.set_line_width(1.5)
    pdf.rect(5, 5, 200, 287)

    # 🏛️ Header with logo and title
    logo_path = os.path.join("static", "logo.png")
    if os.path.exists(logo_path):
        pdf.image(logo_path, x=15, y=10, w=25)

    pdf.set_font("Arial", 'B', 20)
    pdf.set_text_color(25, 60, 160)
    pdf.cell(0, 15, "Government of Land Registry Department", ln=True, align='C')
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Digital Land Verification Certificate", ln=True, align='C')
    pdf.ln(10)

    # 🪶 Watermark
    pdf.set_text_color(230, 230, 230)
    pdf.set_font("Arial", 'B', 50)
    pdf.rotate(45, x=30, y=200)
    pdf.text(40, 160, "Land Registry Verified")
    pdf.rotate(0)

    # Reset font
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Arial", size=12)

    pdf.multi_cell(0, 8, txt=(
        "This certificate verifies that the property listed below has been successfully verified "
        "by the authorized Land Inspector under the National Land Registry Digital System."
    ))
    pdf.ln(10)

    # ----------------------------------------------------------------------
    # 🏠 Property Information
    # ----------------------------------------------------------------------
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Property Details", ln=True)
    pdf.set_font("Arial", size=12)

    info_fields = [
        ("Certificate ID", certificate_id),
        ("Owner Name", land['ownername']),
        ("Location", land['location']),
        ("Type", land['type']),
        ("Size", f"{land['size']} sq.ft"),
        ("Price", f"Rs. {land['price']}"),
        ("Verified Date", datetime.now().strftime('%d-%m-%Y %H:%M:%S'))
    ]

    for label, value in info_fields:
        pdf.cell(0, 8, f"{label}: {value}", ln=True)
    pdf.ln(8)

    # ----------------------------------------------------------------------
    # 📄 Documents Submitted
    # ----------------------------------------------------------------------
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Documents Submitted", ln=True)
    pdf.set_font("Arial", size=12)

    doc_fields = [
        ("Aadhar Card", land.get("aadhar_card")),
        ("Land Map", land.get("land_map")),
        ("Sales Deed", land.get("sales_deed")),
        ("Property Tax Receipts", land.get("property_tax_receipts")),
        ("Encumbrance Certificate", land.get("encumbrance_certificate"))
    ]
    for name, path in doc_fields:
        pdf.cell(0, 8, f" {name}: {path if path else 'Not Uploaded'}", ln=True)
    pdf.ln(10)

    # ----------------------------------------------------------------------
    # 🖼️ Land Photos
    # ----------------------------------------------------------------------
    if land.get("land_photos"):
        photos = [p.strip() for p in land["land_photos"].split(",") if p.strip()]
        if photos:
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, "Land Photos", ln=True)
            pdf.ln(5)
            for i, photo in enumerate(photos[:3]):  # Up to 3 images
                photo_path = os.path.join(app.config['UPLOAD_FOLDER'], photo)
                if os.path.exists(photo_path):
                    pdf.image(photo_path, x=10 + (i * 65), y=pdf.get_y(), w=60)
            pdf.ln(65)

    # ----------------------------------------------------------------------
    # 📱 QR Code Verification
    # ----------------------------------------------------------------------
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "QR Code Verification", ln=True)
    pdf.set_font("Arial", size=12)
    pdf.multi_cell(0, 8, txt="Scan the QR code below or visit the verification link to confirm authenticity.")
    pdf.image(qr_temp_path, x=80, w=50)
    pdf.ln(15)

    pdf.cell(0, 8, f"Verification Link: {verify_url}", ln=True)
    pdf.ln(10)

    # ----------------------------------------------------------------------
    # 🖋️ Signature Section
    # ----------------------------------------------------------------------
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(0, 10, "Authorized Signature:", ln=True)
    pdf.cell(0, 10, "Land Inspector, Digital Verification Dept.", ln=True)

    # Save PDF
    pdf.output(cert_path)

    # ----------------------------------------------------------------------
    # 🔒 Password Protection
    # ----------------------------------------------------------------------
    reader = PdfReader(cert_path)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    writer.encrypt(user_password)
    with open(cert_path, "wb") as f:
        writer.write(f)

    # 🧹 Clean up temp QR
    try:
        os.remove(qr_temp_path)
    except:
        pass

    return certificate_id, cert_filename


# ------------------------------------------------------------------------------------------
#                       BLOCK CHAIN UTILS
# ---------------------------------------------------------------------------------------------------
w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER))
account = None
contract = None
try:
    account = w3.eth.account.from_key(PRIVATE_KEY)
    if os.path.exists('compiled_contract.json'):
        with open('compiled_contract.json', 'r') as fh:
            compiled = json.load(fh)
        # This assumes the compilation json structure you provided earlier
        abi = compiled['contracts']['LandRegistry.sol']['LandRegistry']['abi']
        contract = w3.eth.contract(address=CONTRACT_ADDRESS, abi=abi)
    else:
        app.logger.warning("compiled_contract.json not found — Web3 contract unavailable.")
except Exception as e:
    app.logger.warning("Web3 initialization failed: %s", e)
    account = None
    contract = None

def send_contract_transaction(contract_function):
    if not contract_function or account is None:
        raise RuntimeError("Contract or account not configured.")
    nonce = w3.eth.get_transaction_count(account.address)
    txn = contract_function.build_transaction({
        'chainId': 1337,
        'gas': 300000,
        'gasPrice': w3.to_wei('20', 'gwei'),
        'nonce': nonce
    })
    signed = w3.eth.account.sign_transaction(txn, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    return receipt

#----------------------------------------------------------------------------------------------------------
#                                       EXTRA MISC ROUTES
#----------------------------------------------------------------------------------------------------------

@app.route('/land')
def land():
    return redirect(url_for('landinspector_login'))

import uuid
@app.route('/verify_certificate/<string:certificate_id>')
def verify_certificate(certificate_id):
    """Verify a digital certificate by its unique ID."""
    conn = get_db_connection()
    try:
        with conn.cursor(pymysql.cursors.DictCursor) as cursor:
            cursor.execute("""
                SELECT 
                    l.*, 
                    u.fullname AS ownername, 
                    u.email, 
                    u.username
                FROM lands l
                JOIN users u ON l.owner = u.id
                WHERE l.certificate_id = %s
            """, (certificate_id,))
            land = cursor.fetchone()

        if not land:
            return render_template("certificate_invalid.html", certificate_id=certificate_id)

        # Split photo list (comma separated in DB)
        photos = []
        if land.get("land_photos"):
            photos = [p.strip() for p in land["land_photos"].split(",") if p.strip()]

        return render_template(
            "verify_certificate.html",
            land=land,
            photos=photos,
            certificate_id=certificate_id
        )

    finally:
        conn.close()

# ---------------------------
# Run app
# ---------------------------
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    # Debug True for development; set False for production
    app.run(debug=True, host='0.0.0.0', port=5000)
