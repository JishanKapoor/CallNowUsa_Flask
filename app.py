import os
import logging
import re
import pandas as pd
from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user,
    logout_user, current_user, login_required
)
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError
from callnowusa import Client
from datetime import datetime
import pytz
from dateutil import parser
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
from dotenv import load_dotenv
import os

load_dotenv()
toronto_tz = pytz.timezone('America/Toronto')
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
logging.Formatter.converter = lambda *args: datetime.now(toronto_tz).timetuple()
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
account_sid = os.getenv('ACCOUNT_SID')
auth_token = os.getenv('AUTH_TOKEN')
CALLNOWUSA_NUMBER = os.getenv('CALLNOWUSA_NUMBER')

client = Client(account_sid, auth_token, CALLNOWUSA_NUMBER)

if not os.path.exists('instance'):
    os.makedirs('instance')

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'sign-in'
login_manager.login_message = None
logger = logging.getLogger(__name__)
toronto_tz = pytz.timezone('America/Toronto')
logging.Formatter.converter = lambda *args: datetime.now(toronto_tz).timetuple()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    phone_number_id = db.Column(db.Integer, db.ForeignKey('phone_number.id'), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)

class PhoneNumber(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(20), unique=True, nullable=False)

class SentMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    to_number = db.Column(db.String(20), nullable=False)
    body = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(100), default='pending')
    date_sent = db.Column(db.DateTime, default=lambda: datetime.now(toronto_tz))

class SMSForwarding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    from_number = db.Column(db.String(20), nullable=False)
    to_number = db.Column(db.String(20), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(toronto_tz))

class InboxMessage(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    from_number = db.Column(db.String(20), nullable=False)
    body = db.Column(db.Text, nullable=False)
    direction = db.Column(db.String(10), nullable=False)  # INBOX or OUTBOX
    date_sent = db.Column(db.DateTime, nullable=False)
    external_id = db.Column(db.String(100), nullable=True)
    __table_args__ = (db.UniqueConstraint('user_id', 'from_number', 'body', 'date_sent', 'direction', name='uix_inbox_message'),)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/register.html')
def redirect_register_html():
    return redirect(url_for('register'))

@app.route('/sign-in.html')
def redirect_sign_in_html():
    return redirect(url_for('sign-in'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        terms = request.form.get('terms')

        if not terms:
            flash('You must agree to the Terms & Privacy Policy.', 'error')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(email=email, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            if new_user.is_admin:
                return redirect(url_for('admin_panel'))
            return redirect(url_for('select_phone'))
        except IntegrityError:
            db.session.rollback()
            flash('Email already registered (conflict).', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            if user.is_admin:
                return redirect(url_for('admin_panel'))
            if user.phone_number_id:
                return redirect(url_for('dashboard'))
            return redirect(url_for('select_phone'))
        else:
            flash('Invalid email or password', 'error')
            return render_template('sign-in.html')

    return render_template('sign-in.html')

@app.route('/select-phone', methods=['GET', 'POST'])
@login_required
def select_phone():
    if current_user.is_admin:
        return redirect(url_for('admin_panel'))
    if current_user.phone_number_id:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        phone_number_id = request.form.get('phone_number')
        phone_number = db.session.get(PhoneNumber, phone_number_id)
        if phone_number and not User.query.filter_by(phone_number_id=phone_number_id).first():
            current_user.phone_number_id = phone_number_id
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid or already assigned phone number.', 'error')

    assigned_ids = [user.phone_number_id for user in User.query.filter(User.phone_number_id.isnot(None)).all()]
    phone_numbers = PhoneNumber.query.filter(~PhoneNumber.id.in_(assigned_ids)).all()
    if not phone_numbers:
        flash('No available phone numbers. Please contact an administrator.', 'error')
        return render_template('select_phone.html', phone_numbers=[])
    return render_template('select_phone.html', phone_numbers=phone_numbers)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if not current_user.is_authenticated or not current_user.is_admin:
        return render_template('error.html', message="Unauthorized Access"), 401

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add':
            number = request.form.get('number', '').strip()
            if number and not PhoneNumber.query.filter_by(number=number).first():
                new_number = PhoneNumber(number=number)
                db.session.add(new_number)
                db.session.commit()
                flash('Phone number added.', 'success')
            else:
                flash('Invalid or duplicate number.', 'error')
        elif action == 'delete':
            number_id = request.form.get('number_id')
            number = db.session.get(PhoneNumber, number_id)
            if number:
                if not User.query.filter_by(phone_number_id=number_id).first():
                    db.session.delete(number)
                    db.session.commit()
                    flash('Phone number deleted.', 'success')
                else:
                    flash('Cannot delete number in use.', 'error')
            else:
                flash('Number not found.', 'error')
        elif action == 'unassign':
            number_id = request.form.get('number_id')
            user = User.query.filter_by(phone_number_id=number_id).first()
            if user:
                user.phone_number_id = None
                db.session.commit()
                flash('Phone number unassigned.', 'success')
            else:
                flash('Number not assigned.', 'error')

    phone_numbers = PhoneNumber.query.all()
    assigned_numbers = []
    unassigned_numbers = []
    for number in phone_numbers:
        user = User.query.filter_by(phone_number_id=number.id).first()
        if user:
            assigned_numbers.append({'number': number, 'user_email': user.email})
        else:
            unassigned_numbers.append(number)

    return render_template('admin_dashboard.html',
                         assigned_numbers=assigned_numbers,
                         unassigned_numbers=unassigned_numbers)

@app.route('/dashboard')
@login_required
def dashboard():
    if not current_user.is_admin and not current_user.phone_number_id:
        return redirect(url_for('select_phone'))
    logger.debug(f"Rendering dashboard, session flashes: {session.get('_flashes', [])}")
    return render_template('dashboard.html')

@app.route('/send_sms', methods=['POST'])
@login_required
def send_sms():
    if not current_user.is_admin and not current_user.phone_number_id:
        return jsonify({'success': False, 'error': 'Phone number not assigned.'}), 403

    to_number = request.form.get('to_number', '').strip()
    body = request.form.get('message', '').strip()

    if not to_number or not body:
        flash('Phone number and message are required.', 'error')
        logger.debug("Form validation failed: missing phone number or message")
        return jsonify({'success': False, 'error': 'Phone number and message are required.'}), 400

    if re.match(r'^1\d{10}$', to_number):
        to_number = '+' + to_number
    elif not to_number.startswith('+1') and re.match(r'^\d{10}$', to_number):
        to_number = '+1' + to_number
    elif not re.match(r'^\+1\d{10}$', to_number):
        flash('Invalid phone number format.', 'error')
        logger.debug(f"Invalid phone number format: {to_number}")
        return jsonify({'success': False, 'error': 'Invalid phone number: Use +1 followed by 10 digits, 10 digits alone, or 11 digits starting with 1.'}), 400

    new_message = SentMessage(
        user_id=current_user.id,
        to_number=to_number,
        body=body,
        status='pending',
        date_sent=datetime.now(toronto_tz)
    )
    db.session.add(new_message)
    db.session.commit()
    logger.debug(f"Stored message in database with ID: {new_message.id}, status: {new_message.status}")

    external_id = f"outbox_{new_message.id}_{to_number}_{new_message.date_sent.strftime('%Y%m%d%H%M%S')}"

    try:
        logger.debug(f"Sending SMS to {to_number} with body: {body}")
        message = client.messages.create(
            body=body,
            from_=CALLNOWUSA_NUMBER,
            to=to_number
        )
        response = message.fetch()
        logger.debug(f"SMS sent successfully: {response}")

        new_message.status = response.status if hasattr(response, 'status') else 'sent'
        db.session.commit()
        logger.debug(f"Updated message in database with status: {new_message.status}")

        inbox_message = InboxMessage(
            user_id=current_user.id,
            from_number=to_number,
            body=body,
            direction='OUTBOX',
            date_sent=new_message.date_sent,
            external_id=external_id
        )
        db.session.add(inbox_message)
        db.session.commit()
        logger.debug(f"Added sent message to inbox: {body}")

        return jsonify({
            'success': True,
            'message_id': new_message.id,
            'status': new_message.status,
            'external_id': external_id
        })
    except Exception as e:
        logger.error(f"Failed to send SMS: {str(e)}")
        new_message.status = f"error: {str(e)}"
        db.session.commit()
        return jsonify({
            'success': False,
            'message_id': new_message.id,
            'error': str(e),
            'status': new_message.status,
            'external_id': external_id
        }), 500

@app.route('/upload_sms', methods=['POST'])
@login_required
def upload_sms():
    if not current_user.is_admin and not current_user.phone_number_id:
        return redirect(url_for('select_phone'))

    if 'file' not in request.files:
        flash('No file uploaded.', 'error')
        logger.debug("No file uploaded in request.files")
        return redirect(url_for('dashboard'))

    file = request.files['file']
    if not file or not file.filename:
        flash('No file selected.', 'error')
        logger.debug("No file selected or empty filename")
        return redirect(url_for('dashboard'))

    if not file.filename.lower().endswith(('.csv', '.xlsx', '.xls')):
        flash('File must be CSV or Excel (.csv, .xlsx, .xls).', 'error')
        logger.debug(f"Invalid file type: {file.filename}")
        return redirect(url_for('dashboard'))

    try:
        logger.debug(f"Received file: {file.filename}, size: {file.content_length} bytes")
        if file.filename.lower().endswith('.csv'):
            df = pd.read_csv(file, header=0, names=['Phone Number', 'Message'])
        else:
            df = pd.read_excel(file, header=0, names=['Phone Number', 'Message'], engine='openpyxl')

        logger.debug(f"File parsed, rows: {len(df)}")
        if df.shape[1] != 2:
            flash('File must have exactly two columns: Phone Number and Message.', 'error')
            logger.debug("Invalid file structure: incorrect number of columns")
            return redirect(url_for('dashboard'))

        flash("Processing uploaded file...", 'success')
        logger.debug("Processing uploaded file")

        messages = []
        for index, row in df.iterrows():
            message = str(row['Message']).strip() if pd.notna(row['Message']) else ''
            to_number = str(row['Phone Number']).strip() if pd.notna(row['Phone Number']) else ''

            if not message:
                new_message = SentMessage(
                    user_id=current_user.id,
                    to_number=to_number,
                    body=message,
                    status='error: Message is empty'
                )
                db.session.add(new_message)
                logger.debug(f"Row {index}: Message is empty")
                continue

            if not to_number:
                new_message = SentMessage(
                    user_id=current_user.id,
                    to_number=to_number,
                    body=message,
                    status='error: Phone number is empty'
                )
                db.session.add(new_message)
                logger.debug(f"Row {index}: Phone number is empty")
                continue

            if re.match(r'^1\d{10}$', to_number):
                to_number = '+' + to_number
            elif not to_number.startswith('+1') and re.match(r'^\d{10}$', to_number):
                to_number = '+1' + to_number
            elif not re.match(r'^\+1\d{10}$', to_number):
                new_message = SentMessage(
                    user_id=current_user.id,
                    to_number=to_number,
                    body=message,
                    status='error: Invalid phone number format'
                )
                db.session.add(new_message)
                logger.debug(f"Row {index}: Invalid phone number format: {to_number}")
                continue

            new_message = SentMessage(
                user_id=current_user.id,
                to_number=to_number,
                body=message,
                status='pending',
                date_sent=datetime.now(toronto_tz)
            )
            db.session.add(new_message)
            messages.append(new_message)
            logger.debug(f"Row {index}: Added message to database with status: pending")

        db.session.commit()
        logger.debug("Committed all pending messages to database")

        for index, new_message in enumerate(messages):
            try:
                logger.debug(f"Row {index}: Sending SMS to {new_message.to_number} with body: {new_message.body}")
                api_message = client.messages.create(
                    body=new_message.body,
                    from_=CALLNOWUSA_NUMBER,
                    to=new_message.to_number
                )
                response = api_message.fetch()
                logger.debug(f"Row {index}: SMS sent successfully: {response}")

                new_message.status = response.status if hasattr(response, 'status') else 'sent'
                db.session.commit()
                logger.debug(f"Row {index}: Updated message in database with status: {new_message.status}")

                external_id = f"outbox_{new_message.id}_{new_message.to_number}_{new_message.date_sent.strftime('%Y%m%d%H%M%S')}"
                existing = InboxMessage.query.filter_by(
                    user_id=current_user.id,
                    from_number=new_message.to_number,
                    body=new_message.body,
                    date_sent=new_message.date_sent
                ).first()
                if not existing:
                    inbox_message = InboxMessage(
                        user_id=current_user.id,
                        from_number=new_message.to_number,
                        body=new_message.body,
                        direction='OUTBOX',
                        date_sent=new_message.date_sent,
                        external_id=external_id
                    )
                    db.session.add(inbox_message)
                    db.session.commit()
                    logger.debug(f"Row {index}: Added sent message to inbox: {new_message.body}")
            except Exception as e:
                logger.error(f"Row {index}: Failed to send SMS: {str(e)}")
                new_message.status = f"error: {str(e)}"
                db.session.commit()
                logger.debug(f"Row {index}: Updated message in database with status: {new_message.status}")

        flash("File processed successfully. Check View SMS Status for details.", 'success')
        logger.debug("File processed successfully")

    except Exception as e:
        logger.error(f"Failed to process file: {str(e)}")
        flash(f"Failed to process file: {str(e)}", 'error')

    logger.debug(f"Redirecting to dashboard, session flashes: {session.get('_flashes', [])}")
    return redirect(url_for('dashboard'))

@app.route('/view_sms_status')
@login_required
def view_sms_status():
    if not current_user.is_admin and not current_user.phone_number_id:
        return redirect(url_for('select_phone'))

    try:
        messages = SentMessage.query.filter_by(user_id=current_user.id).order_by(SentMessage.date_sent.desc()).limit(20).all()
        sms_list = [
            {
                'to': msg.to_number,
                'body': msg.body,
                'status': msg.status,
                'date_sent': msg.date_sent.strftime('%Y-%m-%d %H:%M:%S')
            }
            for msg in messages
        ]
        logger.debug(f"Successfully fetched {len(sms_list)} messages for user {current_user.id}")
        return render_template('view_sms_status.html', sms_list=sms_list)
    except Exception as e:
        logger.error(f"Failed to fetch SMS statuses: {str(e)}")
        flash(f"Failed to fetch SMS statuses: {str(e)}", 'error')
        return redirect(url_for('dashboard'))

@app.route('/sms_forwarding', methods=['GET', 'POST', 'DELETE'])
@login_required
def sms_forwarding():
    if not current_user.is_admin and not current_user.phone_number_id:
        return redirect(url_for('select_phone'))

    if request.method == 'POST':
        data = request.get_json()
        from_number = data.get('from_number', '').strip()
        to_number = data.get('to_number', '').strip()

        phone_regex = r'^\+1\d{10}$'
        if not (re.match(phone_regex, from_number) and re.match(phone_regex, to_number)):
            logger.debug(f"Invalid phone number format: from={from_number}, to={to_number}")
            return jsonify({'success': False, 'error': 'Both numbers must start with +1 followed by 10 digits.'}), 400

        if SMSForwarding.query.filter_by(user_id=current_user.id, from_number=from_number, to_number=to_number).first():
            logger.debug(f"Duplicate forwarding rule: from={from_number}, to={to_number}")
            return jsonify({'success': False, 'error': 'This forwarding rule already exists.'}), 400

        try:
            logger.debug(f"Calling sms_forward: to_number={from_number}, to_number2={to_number}")
            message = client.sms_forward(
                to_number=from_number,
                to_number2=to_number,
                from_=CALLNOWUSA_NUMBER
            )
            response = message.fetch()
            logger.debug(f"sms_forward response: {response}")

            new_forwarding = SMSForwarding(
                user_id=current_user.id,
                from_number=from_number,
                to_number=to_number
            )
            db.session.add(new_forwarding)
            db.session.commit()
            logger.debug(f"Saved forwarding rule: from={from_number}, to={to_number}")
            flash('Forwarding rule added successfully.', 'success')
            return jsonify({'success': True})

        except Exception as e:
            logger.error(f"Failed to set up SMS forwarding: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'error': f"Failed to set up forwarding: {str(e)}"}), 500

    elif request.method == 'DELETE':
        data = request.get_json()
        from_number = data.get('from_number', '').strip()
        to_number = data.get('to_number', '').strip()

        forwarding = SMSForwarding.query.filter_by(
            user_id=current_user.id,
            from_number=from_number,
            to_number=to_number
        ).first()

        if not forwarding:
            logger.debug(f"Forwarding rule not found: from={from_number}, to={to_number}")
            return jsonify({'success': False, 'error': 'Forwarding rule not found.'}), 404

        try:
            logger.debug(f"Calling sms_forward_stop: to_number={from_number}, to_number2={to_number}")
            message = client.sms_forward_stop(
                to_number=from_number,
                to_number2=to_number,
                from_=CALLNOWUSA_NUMBER
            )
            response = message.fetch()
            logger.debug(f"sms_forward_stop response: {response}")

            db.session.delete(forwarding)
            db.session.commit()
            logger.debug(f"Deleted forwarding rule: from={from_number}, to={to_number}")
            return jsonify({'success': True})

        except Exception as e:
            logger.error(f"Failed to stop SMS forwarding: {str(e)}")
            db.session.rollback()
            return jsonify({'success': False, 'error': f"Failed to stop forwarding: {str(e)}"}), 500

    else:
        try:
            forwardings = SMSForwarding.query.filter_by(user_id=current_user.id).order_by(SMSForwarding.created_at.desc()).all()
            forwarding_list = [
                {
                    'from_number': f.from_number,
                    'to_number': f.to_number,
                    'created_at': f.created_at.strftime('%Y-%m-%d %H:%M:%S')
                }
                for f in forwardings
            ]
            logger.debug(f"Fetched {len(forwarding_list)} forwarding rules for user {current_user.id}")
            return render_template('sms_forwarding.html', forwarding_list=forwarding_list)
        except Exception as e:
            logger.error(f"Failed to fetch forwarding rules: {str(e)}")
            return redirect(url_for('dashboard'))

@app.route('/inbox', methods=['GET'])
@login_required
def inbox():
    if not current_user.is_admin and not current_user.phone_number_id:
        flash('No phone number assigned. Please select a phone number.', 'error')
        return redirect(url_for('select_phone'))

    try:
        phone_number = db.session.get(PhoneNumber, current_user.phone_number_id)
        if not phone_number:
            logger.error(f"No phone number found for phone_number_id: {current_user.phone_number_id}")
            flash('Assigned phone number not found. Please contact an administrator.', 'error')
            return redirect(url_for('select_phone'))

        # Fetch messages from database
        inbox_messages = InboxMessage.query.filter_by(user_id=current_user.id).all()
        inbox_data = {}

        for msg in inbox_messages:
            number = msg.from_number
            if number not in inbox_data:
                inbox_data[number] = []
            inbox_data[number].append({
                'id': msg.id,
                'from_number': number,
                'body': msg.body,
                'direction': msg.direction,
                'date_sent': msg.date_sent.strftime('%Y-%m-%d %H:%M:%S'),
                'raw_date_sent': msg.date_sent,
                'external_id': msg.external_id
            })

        # Sort messages within each number by date_sent (ascending, so latest at bottom)
        for number in inbox_data:
            inbox_data[number].sort(key=lambda x: x['raw_date_sent'])
            logger.debug(f"Sorted messages for {number}: {len(inbox_data[number])} messages")

        # Sort numbers by the most recent message (descending, so latest at top)
        sorted_inbox = dict(sorted(
            inbox_data.items(),
            key=lambda x: x[1][-1]['raw_date_sent'] if x[1] else datetime.min.replace(tzinfo=toronto_tz),
            reverse=True
        ))
        logger.debug(f"Sorted phone numbers: {list(sorted_inbox.keys())}")

        logger.debug(f"Fetched {len(inbox_messages)} inbox messages for user {current_user.id}")
        return render_template('inbox.html', inbox_data=sorted_inbox)
    except Exception as e:
        logger.error(f"Failed to fetch inbox messages: {str(e)}")
        flash(f"Error fetching inbox messages: {str(e)}", 'error')
        return redirect(url_for('dashboard'))

@app.route('/refresh_inbox', methods=['GET'])
@login_required
def refresh_inbox():
    if not current_user.is_admin and not current_user.phone_number_id:
        return jsonify({'success': False, 'error': 'No phone number assigned.'}), 403

    try:
        phone_number = db.session.get(PhoneNumber, current_user.phone_number_id)
        if not phone_number:
            logger.error(f"No phone number found for phone_number_id: {current_user.phone_number_id}")
            return jsonify({'success': False, 'error': 'Assigned phone number not found.'}), 400

        logger.debug(f"Checking inbox for number: {phone_number.number}")
        inbox_response = client.check_inbox(from_=phone_number.number)
        new_messages = inbox_response.fetch()
        logger.debug(f"Inbox API response: {new_messages}")

        messages = []
        # Handle API response: status is a string like "[+number:\"body\" sent/received timestamp], ..."
        if isinstance(new_messages.get('status'), str):
            # Split by '], [' to separate messages, handling first and last brackets
            message_strings = new_messages['status'].strip('[]').split('], [')
            for msg_str in message_strings:
                msg_str = msg_str.strip()
                # Regex to match: +number:"body" sent/received timestamp
                match = re.match(r'(\+\d{11}):"(.+?)"\s+(sent|received)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})', msg_str, re.IGNORECASE)
                if match:
                    from_number = match.group(1)
                    body = match.group(2)
                    direction = 'OUTBOX' if match.group(3).lower() == 'sent' else 'INBOX'
                    date_sent = parser.parse(match.group(4)).replace(tzinfo=pytz.UTC).astimezone(toronto_tz)
                    messages.append({
                        'from_number': from_number,
                        'body': body,
                        'direction': direction,
                        'date_sent': date_sent,
                        'sid': new_messages.get('sid', '')
                    })
                else:
                    logger.warning(f"Failed to parse message string: {msg_str}")
        else:
            logger.warning(f"Unexpected status format in API response: {new_messages.get('status')}")

        # Store new messages in database
        for msg in messages:
            from_number = msg['from_number'].strip()
            body = msg['body'].strip()
            direction = msg['direction']
            date_sent = msg['date_sent']
            external_id = msg['sid'] or f"{direction.lower()}_{from_number}_{date_sent.strftime('%Y%m%d%H%M%S')}"

            existing = InboxMessage.query.filter_by(
                user_id=current_user.id,
                from_number=from_number,
                body=body,
                date_sent=date_sent,
                direction=direction
            ).first()
            if existing:
                # Update external_id if it has changed
                if existing.external_id != external_id:
                    existing.external_id = external_id
                    db.session.commit()
                    logger.debug(f"Updated external_id for existing {direction} message from {from_number}: {body}")
                else:
                    logger.debug(f"Skipped duplicate {direction} message from {from_number}: {body}")
            else:
                inbox_message = InboxMessage(
                    user_id=current_user.id,
                    from_number=from_number,
                    body=body,
                    direction=direction,
                    date_sent=date_sent,
                    external_id=external_id
                )
                try:
                    db.session.add(inbox_message)
                    db.session.commit()
                    logger.debug(f"Added new {direction} message from {from_number}: {body}")
                except IntegrityError:
                    db.session.rollback()
                    logger.debug(f"IntegrityError on {direction} message from {from_number}: {body}, likely duplicate")

        # Fetch all messages from database to display
        inbox_messages = InboxMessage.query.filter_by(user_id=current_user.id).all()
        inbox_data = {}

        for msg in inbox_messages:
            number = msg.from_number
            if number not in inbox_data:
                inbox_data[number] = []
            inbox_data[number].append({
                'id': msg.id,
                'from_number': number,
                'body': msg.body,
                'direction': msg.direction,
                'date_sent': msg.date_sent.strftime('%Y-%m-%d %H:%M:%S'),
                'raw_date_sent': msg.date_sent,
                'external_id': msg.external_id
            })

        # Sort messages within each number by date_sent (ascending, so latest at bottom)
        for number in inbox_data:
            inbox_data[number].sort(key=lambda x: x['raw_date_sent'])
            logger.debug(f"Sorted messages for {number}: {len(inbox_data[number])} messages")

        # Sort numbers by the most recent message (descending, so latest at top)
        sorted_inbox = dict(sorted(
            inbox_data.items(),
            key=lambda x: x[1][-1]['raw_date_sent'] if x[1] else datetime.min.replace(tzinfo=toronto_tz),
            reverse=True
        ))
        logger.debug(f"Sorted phone numbers: {list(sorted_inbox.keys())}")

        logger.debug(f"Fetched {len(inbox_messages)} inbox messages for user {current_user.id}")
        rendered_html = render_template('inbox.html', inbox_data=sorted_inbox)
        return jsonify({
            'success': True,
            'html': rendered_html
        })
    except Exception as e:
        logger.error(f"Failed to refresh inbox: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('register'))

@login_manager.unauthorized_handler
def unauthorized_callback():
    return render_template('error.html', message="Unauthorized Access"), 401

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', message="Page Not Found"), 404

@app.errorhandler(401)
def unauthorized(e):
    return render_template('error.html', message="Unauthorized Access"), 401

@app.errorhandler(Exception)
def handle_exception(e):
    logger.error(f"Unhandled exception: {str(e)}")
    return render_template('error.html', message="Internal Server Error"), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(email='admin@gmail.com').first():
            admin = User(
                email=os.getenv('ADMIN_EMAIL'),
                password=generate_password_hash(os.getenv('ADMIN_PASSWORD'), method='pbkdf2:sha256'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
    app.run(host='0.0.0.0', port=8000, debug=True)
