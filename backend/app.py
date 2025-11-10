# app.py
# Complete Flask backend for Scholarvault with admin-restricted scholarship management, notice functionality, email notifications using Flask-Mail, and missed reminders improvement

# --- Imports ---
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from datetime import datetime, timedelta
from time import sleep
import os
import jwt
import json
import base64
from functools import wraps
from apscheduler.schedulers.background import BackgroundScheduler
from werkzeug.utils import secure_filename
from flask_cors import CORS
from flask import send_file
import pytz
from sqlalchemy import select  # Added missing import

# --- Configuration ---
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'a-very-secret-key-12345'  # Change in production
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:project@localhost:5432/scholarvaultdb'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET = os.environ.get('JWT_SECRET') or 'jwt-secret-key-12345'  # Change in production
    # Email configuration for Flask-Mail
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'scholarvault25@gmail.com'  # Replace with your email
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or 'lgkv zxrm rvup whcj'  # Replace with your app password
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER') or 'scholarvault25@gmail.com'

# --- Flask App Setup ---
app = Flask(__name__)
CORS(app)  # Allow frontend to communicate with backend
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
mail = Mail(app)  # Initialize Flask-Mail

# Initialize scheduler for background tasks
scheduler = BackgroundScheduler()
scheduler.start()

# --- Database Models ---
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    gender = db.Column(db.String(10), nullable=False)
    state = db.Column(db.String(50), nullable=False)
    education_level = db.Column(db.String(50), nullable=False)
    field_of_study = db.Column(db.String(50), nullable=False)
    institution = db.Column(db.String(100), nullable=False)
    enrollment_year = db.Column(db.Integer, nullable=False)
    cgpa = db.Column(db.Float, nullable=False)
    twelfth_percentage = db.Column(db.Float, nullable=False)
    competitive_exams = db.Column(db.JSON)
    category = db.Column(db.String(10), nullable=False)
    family_income = db.Column(db.String(20), nullable=False)
    special_categories = db.Column(db.JSON)
    documents = db.relationship('Document', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.email}>'

class Admin(db.Model):
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    notices = db.relationship('Notice', backref='admin', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class Scholarship(db.Model):
    __tablename__ = 'scholarships'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    organization = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    deadline = db.Column(db.Date, nullable=True)
    category = db.Column(db.String(50), nullable=True)
    criteria = db.Column(db.JSON)
    cgpa = db.Column(db.Float, nullable=True)
    twelfth_marks = db.Column(db.Float, nullable=True)
    gender = db.Column(db.String(10), nullable=True)
    income = db.Column(db.String(20), nullable=True)
    special_category = db.Column(db.String(50), nullable=True)
    about_the_program = db.Column(db.Text, nullable=True)  # For "About the Program" section
    eligibility = db.Column(db.Text, nullable=True)        # For "Eligibility" section
    benefits = db.Column(db.Text, nullable=True)           # For "Benefits" section
    application_link = db.Column(db.String(200), nullable=True)

class Notice(db.Model):
    __tablename__ = 'notices'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=True)

class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # Fixed foreign key reference
    filename = db.Column(db.String(255), nullable=False)
    filepath = db.Column(db.String(255), nullable=False)
    document_type = db.Column(db.String(100), nullable=True)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f'<Document {self.filename}>'

class AdminLoginLog(db.Model):
    __tablename__ = 'admin_login_logs'
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey('admins.id'), nullable=True)
    username_attempt = db.Column(db.String(50), nullable=False)
    success = db.Column(db.Boolean, default=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class ReminderLog(db.Model):
    __tablename__ = 'reminder_logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scholarship_type = db.Column(db.String(20), nullable=False)  # 'admin' or 'provider'
    scholarship_id = db.Column(db.Integer, nullable=False)  # ID from either scholarships or provider_scholarships
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)

# --- Database Models ---
# Existing models (User, Admin, Scholarship, Notice, Document, AdminLoginLog, ReminderLog) remain unchanged

class ScholarshipProvider(db.Model):
    __tablename__ = 'scholarship_providers'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    organization = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(15), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    id_proof_path = db.Column(db.String(200), nullable=True)  # Column to store ID proof filepath
    scholarships = db.relationship('ProviderScholarship', backref='provider', lazy=True)

    def set_password(self, password):
        self.password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password_hash, password)

class ProviderScholarship(db.Model):
    __tablename__ = 'provider_scholarships'
    id = db.Column(db.Integer, primary_key=True)
    provider_id = db.Column(db.Integer, db.ForeignKey('scholarship_providers.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    deadline = db.Column(db.Date, nullable=True)
    eligibility_criteria = db.Column(db.JSON, nullable=False)  # e.g., {"cgpa": 7.5, "gender": "female"}
    required_documents = db.Column(db.JSON, nullable=False)   # e.g., ["marksheet", "income_certificate"]
    is_approved = db.Column(db.Boolean, default=False)
    applications = db.relationship('ScholarshipApplication', backref='scholarship', lazy=True)
    about_the_program = db.Column(db.Text, nullable=True)
    eligibility = db.Column(db.Text, nullable=True)
    benefits = db.Column(db.Text, nullable=True)
    application_link = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"<ProviderScholarship id={self.id} name={self.name}>"

class ScholarshipApplication(db.Model):
    __tablename__ = 'scholarship_applications'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scholarship_id = db.Column(db.Integer, db.ForeignKey('provider_scholarships.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # 'pending', 'accepted', 'rejected'
    applied_at = db.Column(db.DateTime, default=datetime.utcnow)
    documents = db.Column(db.JSON, nullable=True)  # List of uploaded document filepaths
    name = db.Column(db.String(100), nullable=False)
    dob = db.Column(db.Date, nullable=False)
    email = db.Column(db.String(120), nullable=False)
    institution = db.Column(db.String(100), nullable=False)
    course = db.Column(db.String(50), nullable=False)
    year_of_study = db.Column(db.Integer, nullable=False)
    cgpa = db.Column(db.Float, nullable=False)
    family_income = db.Column(db.String(20), nullable=False)
    income_certificate = db.Column(db.String(200), nullable=False)  # Filepath to income certificate
    reason_for_applying = db.Column(db.Text, nullable=False)
    student_id_card = db.Column(db.String(255), nullable=True)  # New column
    previous_scholarships = db.Column(db.JSON, nullable=True)  # List of previous scholarshipss

    def __repr__(self):
        return f"<ScholarshipApplication id={self.id} user_id={self.user_id} scholarship_id={self.scholarship_id} status={self.status}>"

# --- Helper Functions ---
# --- Helper Functions ---
def generate_token(id, role):
    current_time = datetime.now(pytz.UTC)
    timestamp = current_time.timestamp()
    
    # Cap timestamps to prevent overflow
    if timestamp > 2**31:
        print(f"Warning: Timestamp {timestamp} exceeds 32-bit limit, capping at max safe value")
        timestamp = 2**31 - 1
    
    exp_time = current_time + timedelta(hours=24)
    exp_timestamp = exp_time.timestamp()
    if exp_timestamp > 2**31:
        print(f"Warning: Exp timestamp {exp_timestamp} exceeds 32-bit limit, capping")
        exp_timestamp = 2**31 - 1

    payload = {
        f"{role}_id": id,
        'exp': int(exp_timestamp),
        'role': role,
        'iat': int(timestamp)
    }

    token = jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')
    print(f"Generated token: {token[:20]}... with payload: {payload}")
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            print("Token is missing!")
            return jsonify({"status": "error", "message": "Token is missing"}), 401

        if not token.startswith('Bearer '):
            print("Invalid Authorization header format!")
            return jsonify({"status": "error", "message": "Invalid Authorization header format"}), 401

        token = token.split(" ")[1]

        try:
            data = jwt.decode(token, app.config['JWT_SECRET'], algorithms=["HS256"], options={"verify_exp": True})
            print(f"Decoded token data: {data}")

            # OPTIONAL: Handle timestamp safely (only if you NEED to use 'iat')
            if 'iat' in data:
                try:
                    iat = int(data['iat'])
                    if iat > 2**31:  # Prevent overflow
                        print(f"Warning: 'iat' value too large: {iat}")
                        iat = 2**31 - 1
                    issued_at = datetime.fromtimestamp(iat)
                    print(f"Issued at: {issued_at}")
                except Exception as time_err:
                    print(f"Error parsing iat timestamp: {str(time_err)}")
                    issued_at = None  # Or skip using it

            role = data.get('role')
            current_user = current_admin = current_provider = None

            if role == 'user':
                current_user = db.session.execute(select(User).where(User.id == data.get('user_id'))).scalar_one_or_none()
                print(f"Current user: {current_user}")
            elif role == 'admin':
                current_admin = db.session.execute(select(Admin).where(Admin.id == data.get('admin_id'))).scalar_one_or_none()
                print(f"Current admin: {current_admin}")
            elif role == 'provider':
                current_provider = db.session.execute(select(ScholarshipProvider).where(ScholarshipProvider.id == data.get('provider_id'))).scalar_one_or_none()
                print(f"Current provider: {current_provider}")
            else:
                print("Invalid role in token!")
                return jsonify({"status": "error", "message": "Invalid role"}), 401

            if not (current_user or current_admin or current_provider):
                print("User, Admin, or Provider not found!")
                return jsonify({"status": "error", "message": "Invalid or expired user"}), 401

            return f(current_user, current_admin, current_provider, *args, **kwargs)

        except jwt.ExpiredSignatureError:
            print("Token has expired!")
            return jsonify({"status": "error", "message": "Token has expired"}), 401
        except jwt.InvalidTokenError as e:
            print(f"Invalid token error: {str(e)}")
            return jsonify({"status": "error", "message": "Invalid token", "error": str(e)}), 401
        except Exception as e:
            print(f"Token decode error: {str(e)}")
            return jsonify({"status": "error", "message": "Token is invalid", "error": str(e)}), 401

    return decorated
def match_criteria(user_info, scholarship):
    print(f"Checking {scholarship.name}:")
    if scholarship.cgpa and user_info.get('cgpa', 0) < scholarship.cgpa:
        print(f"  CGPA failed: {user_info.get('cgpa', 0)} < {scholarship.cgpa}")
        return False
    print(f"  CGPA passed: {user_info.get('cgpa', 0)} >= {scholarship.cgpa}")
    if scholarship.twelfth_marks and user_info.get('twelfth_percentage', 0) < scholarship.twelfth_marks:
        print(f"  Twelfth marks failed: {user_info.get('twelfth_percentage', 0)} < {scholarship.twelfth_marks}")
        return False
    print(f"  Twelfth marks passed: {user_info.get('twelfth_percentage', 0)} >= {scholarship.twelfth_marks}")
    if scholarship.gender and user_info.get('gender', '').lower() != scholarship.gender.lower() and scholarship.gender.lower() != 'all':
        print(f"  Gender failed: {user_info.get('gender', '')} != {scholarship.gender}")
        return False
    print(f"  Gender passed: {user_info.get('gender', '')} == {scholarship.gender}")
    if scholarship.income and user_info.get('family_income'):
        income_ranges = {
            'below-1l': lambda x: x in ['below-1l'],
            '1l-3l': lambda x: x in ['1l-3l'],  # Added exact match
            'below-3l': lambda x: x in ['below-1l', '1l-3l'],
            '3l-6l': lambda x: x in ['3l-6l'],
            'above-6l': lambda x: x in ['above-6l']
        }
        if not income_ranges.get(scholarship.income, lambda x: False)(user_info['family_income']):
            print(f"  Income failed: {user_info['family_income']} not in range for {scholarship.income}")
            return False
    print(f"  Income passed: {user_info['family_income']} in range for {scholarship.income}")
    if scholarship.special_category and user_info.get('special_categories'):
        if 'minority' in scholarship.special_category.lower() and 'minority' in [cat.lower() for cat in user_info.get('special_categories', [])]:
            print(f"  Special category passed (lenient): {scholarship.special_category} matches {user_info.get('special_categories')}")
        elif scholarship.special_category.lower() not in [cat.lower() for cat in user_info.get('special_categories', [])]:
            print(f"  Special category failed: {scholarship.special_category} not in {user_info.get('special_categories')}")
            return False
    print(f"  Special category passed: {scholarship.special_category} matches {user_info.get('special_categories')}")
    if scholarship.criteria:
        for key, criterion in scholarship.criteria.items():
            if key not in user_info:
                print(f"  Criteria key {key} not in user_info")
                return False
            user_value = user_info[key]
            print(f"  Checking criteria {key}: user_value={user_value}, criterion={criterion}")
            if isinstance(criterion, dict):
                if 'min' in criterion and user_value < criterion['min']:
                    print(f"  Criteria {key} min failed: {user_value} < {criterion['min']}")
                    return False
                if 'max' in criterion and user_value > criterion['max']:
                    print(f"  Criteria {key} max failed: {user_value} > {criterion['max']}")
                    return False
            elif isinstance(criterion, list):
                if isinstance(user_value, list):
                    if not any(val in criterion for val in user_value):
                        print(f"  Criteria {key} list failed: {user_value} not in {criterion}")
                        return False
                else:
                    if user_value not in criterion:
                        print(f"  Criteria {key} value failed: {user_value} not in {criterion}")
                        return False
            elif isinstance(criterion, bool):
                if isinstance(user_value, list):
                    if criterion and not user_value:
                        print(f"  Criteria {key} bool failed: empty list with True criterion")
                        return False
                    if not criterion and user_value:
                        print(f"  Criteria {key} bool failed: non-empty list with False criterion")
                        return False
                else:
                    if user_value != criterion:
                        print(f"  Criteria {key} bool failed: {user_value} != {criterion}")
                        return False
            else:
                if isinstance(user_value, (int, float)) and isinstance(criterion, (int, float)):
                    if user_value < criterion:
                        print(f"  Criteria {key} numeric failed: {user_value} < {criterion}")
                        return False
                elif user_value.lower() != criterion.lower() if isinstance(user_value, str) and isinstance(criterion, str) else user_value != criterion:
                    print(f"  Criteria {key} string failed: {user_value} != {criterion}")
                    return False
            print(f"  Criteria {key} passed: {user_value} matches {criterion}")
    print(f"Match criteria passed for {scholarship.name}")
    return True

def get_eligible_scholarships_for_user(current_user, current_date):
    user = User.query.get(current_user.id)
    if not user:
        return None

    user_info = {
        'full_name': user.full_name,
        'username': user.username,
        'email': user.email,
        'phone': user.phone,
        'dob': user.dob.isoformat(),
        'gender': user.gender,
        'state': user.state,
        'education_level': user.education_level,
        'field_of_study': user.field_of_study,
        'institution': user.institution,
        'enrollment_year': user.enrollment_year,
        'cgpa': user.cgpa,
        'twelfth_percentage': user.twelfth_percentage,
        'competitive_exams': user.competitive_exams or [],
        'category': user.category,
        'family_income': user.family_income,
        'special_categories': user.special_categories or []
    }

    # Fetch admin scholarships
    admin_scholarships = Scholarship.query.all()
    eligible_scholarships = []

    for scholarship in admin_scholarships:
        if match_criteria(user_info, scholarship) and (not scholarship.deadline or scholarship.deadline >= current_date):
            eligible_scholarships.append({
                "id": scholarship.id,
                "type": "admin",
                "name": scholarship.name,
                "organization": scholarship.organization,
                "amount": float(scholarship.amount),
                "deadline": scholarship.deadline.isoformat() if scholarship.deadline else None,
                "category": scholarship.category,
                "education_level": scholarship.criteria.get('education_level', 'Not specified') if scholarship.criteria else 'Not specified',
                "description": scholarship.description,
                "gender": scholarship.gender,
                "special_category": scholarship.special_category,
                "cgpa": scholarship.cgpa,
                "twelfth_marks": scholarship.twelfth_marks,
                "criteria": scholarship.criteria,
                "about_the_program": scholarship.about_the_program,
                "eligibility": scholarship.eligibility,
                "benefits": scholarship.benefits,
                "application_link": scholarship.application_link
            })

    # Fetch provider scholarships
    provider_scholarships = db.session.query(ProviderScholarship, ScholarshipProvider).\
        join(ScholarshipProvider, ProviderScholarship.provider_id == ScholarshipProvider.id).\
        filter(ProviderScholarship.is_approved == True).all()

    for scholarship, provider in provider_scholarships:
        if match_provider_criteria(user_info, scholarship) and (not scholarship.deadline or scholarship.deadline >= current_date):
            eligible_scholarships.append({
                "id": scholarship.id,
                "type": "provider",
                "name": scholarship.name,
                "organization": provider.name,
                "description": scholarship.description,
                "amount": float(scholarship.amount),
                "deadline": scholarship.deadline.isoformat() if scholarship.deadline else None,
                "required_documents": scholarship.required_documents,
                "eligibility_criteria": scholarship.eligibility_criteria,
                "about_the_program": scholarship.about_the_program,
                "eligibility": scholarship.eligibility,
                "benefits": scholarship.benefits,
                "application_link": scholarship.application_link
            })

    return eligible_scholarships

def get_eligible_scholarships_by_category(current_user, category_name, current_date):
    user = User.query.get(current_user.id)
    if not user:
        return None

    user_info = {
        'full_name': user.full_name,
        'username': user.username,
        'email': user.email,
        'phone': user.phone,
        'dob': user.dob.isoformat(),
        'gender': user.gender,
        'state': user.state,
        'education_level': user.education_level,
        'field_of_study': user.field_of_study,
        'institution': user.institution,
        'enrollment_year': user.enrollment_year,
        'cgpa': user.cgpa,
        'twelfth_percentage': user.twelfth_percentage,
        'competitive_exams': user.competitive_exams or [],
        'category': user.category,
        'family_income': user.family_income,
        'special_categories': user.special_categories or []
    }

    if category_name == "Provider Scholarships":
        scholarships = db.session.query(ProviderScholarship, ScholarshipProvider).\
            join(ScholarshipProvider, ProviderScholarship.provider_id == ScholarshipProvider.id).\
            filter(ProviderScholarship.is_approved == True).all()
        eligible_scholarships = []
        for scholarship, provider in scholarships:
            if match_provider_criteria(user_info, scholarship) and (not scholarship.deadline or scholarship.deadline >= current_date):
                eligible_scholarships.append({
                    "id": scholarship.id,
                    "type": "provider",
                    "name": scholarship.name,
                    "organization": provider.name,
                    "description": scholarship.description,
                    "amount": float(scholarship.amount),
                    "deadline": scholarship.deadline.isoformat() if scholarship.deadline else None,
                    "required_documents": scholarship.required_documents,
                    "eligibility_criteria": scholarship.eligibility_criteria,
                    "about_the_program": scholarship.about_the_program,
                    "eligibility": scholarship.eligibility,
                    "benefits": scholarship.benefits,
                    "application_link": scholarship.application_link
                })
    else:
        scholarships = Scholarship.query.all()
        eligible_scholarships = []
        for scholarship in scholarships:
            print(f"Evaluating {scholarship.name}: cgpa={scholarship.cgpa}, twelfth_marks={scholarship.twelfth_marks}, gender={scholarship.gender}, income={scholarship.income}, special_category={scholarship.special_category}, criteria={scholarship.criteria}")
            if match_criteria(user_info, scholarship):
                print(f"Match criteria passed for {scholarship.name}")
                if not scholarship.deadline or scholarship.deadline >= current_date:
                    print(f"Deadline check passed for {scholarship.name}")
                    scholarship_data = {
                        "id": scholarship.id,
                        "type": "admin",
                        "name": scholarship.name,
                        "organization": scholarship.organization,
                        "amount": float(scholarship.amount),
                        "deadline": scholarship.deadline.isoformat() if scholarship.deadline else None,
                        "category": scholarship.category,
                        "education_level": scholarship.criteria.get('education_level', 'Not specified') if scholarship.criteria else 'Not specified',
                        "description": scholarship.description,
                        "gender": scholarship.gender,
                        "special_category": scholarship.special_category,
                        "cgpa": scholarship.cgpa,
                        "twelfth_marks": scholarship.twelfth_marks,
                        "criteria": scholarship.criteria,
                        "about_the_program": scholarship.about_the_program,
                        "eligibility": scholarship.eligibility,
                        "benefits": scholarship.benefits,
                        "application_link": scholarship.application_link
                    }
                    print(f"Categorizing {scholarship.name} for {category_name}: {categorize_scholarship(scholarship_data, category_name, user_info)}")
                    if categorize_scholarship(scholarship_data, category_name, user_info):
                        print(f"Scholarship {scholarship.name} added to eligible list")
                        eligible_scholarships.append(scholarship_data)
            else:
                print(f"Match criteria failed for {scholarship.name}")
    print(f"Final eligible scholarships: {[s['name'] for s in eligible_scholarships]}")
    return eligible_scholarships
# New match_provider_criteria for ProviderScholarship
def match_provider_criteria(user_info, scholarship):
    criteria = scholarship.eligibility_criteria
    if 'cgpa' in criteria and user_info.get('cgpa', 0) < criteria['cgpa']:
        return False
    if 'twelfth_percentage' in criteria and user_info.get('twelfth_percentage', 0) < criteria['twelfth_percentage']:
        return False
    if 'gender' in criteria and user_info.get('gender') != criteria['gender'] and criteria['gender'] != 'all':
        return False
    if 'family_income' in criteria and user_info.get('family_income') != criteria['family_income']:
        return False
    if 'special_categories' in criteria and not any(cat in user_info.get('special_categories', []) for cat in criteria['special_categories']):
        return False
    return True

def categorize_scholarship(scholarship, category_name, user_info=None):
    if category_name == "For Girls":
        return scholarship.get('gender') == 'female' or scholarship.get('eligibility_criteria', {}).get('gender') == 'female'
    elif category_name == "Sports Talent":
        return scholarship.get('special_category') == 'sports' or (
            scholarship.get('criteria', {}).get('competitive_exams', []) and 'sports' in scholarship['criteria']['competitive_exams']
        ) or (
            scholarship.get('eligibility_criteria', {}).get('special_categories', []) and 'sports' in scholarship['eligibility_criteria']['special_categories']
        )
    elif category_name == "SC/ST/OBC/DNT":
        return scholarship.get('special_category') in ['sc', 'st', 'obc', 'dnt'] or (
            user_info and user_info.get('category') in ['sc', 'st', 'obc', 'dnt']
        ) or (
            scholarship.get('eligibility_criteria', {}).get('special_categories', []) and any(cat in ['sc', 'st', 'obc', 'dnt'] for cat in scholarship['eligibility_criteria']['special_categories'])
        )
    elif category_name == "Minorities":
        return scholarship.get('special_category') == 'minority' or (
            scholarship.get('eligibility_criteria', {}).get('special_categories', []) and 'minority' in scholarship['eligibility_criteria']['special_categories']
        )
    elif category_name == "Merit Based":
        return bool(scholarship.get('cgpa') or scholarship.get('twelfth_marks') or scholarship.get('eligibility_criteria', {}).get('cgpa'))
    elif category_name == "Provider Scholarships":
        return scholarship.get('source') == 'provider'  # Still useful if you keep this category
    return False

# --- Email Notification Functions ---
def check_and_send_deadline_reminders():
    with app.app_context():
        users = User.query.all()
        today = datetime.now(pytz.UTC).date()
        reminder_window_start = today + timedelta(days=6)
        reminder_window_end = today + timedelta(days=8)

        for user in users:
            user_info = {
                'full_name': user.full_name,
                'username': user.username,
                'email': user.email,
                'phone': user.phone,
                'dob': user.dob.isoformat(),
                'gender': user.gender,
                'state': user.state,
                'education_level': user.education_level,
                'field_of_study': user.field_of_study,
                'institution': user.institution,
                'enrollment_year': user.enrollment_year,
                'cgpa': user.cgpa,
                'twelfth_percentage': user.twelfth_percentage,
                'competitive_exams': user.competitive_exams or [],
                'category': user.category,
                'family_income': user.family_income,
                'special_categories': user.special_categories or []
            }

            admin_scholarships = Scholarship.query.filter(
                Scholarship.deadline >= reminder_window_start,
                Scholarship.deadline <= reminder_window_end
            ).all()
            provider_scholarships = ProviderScholarship.query.filter(
                ProviderScholarship.deadline >= reminder_window_start,
                ProviderScholarship.deadline <= reminder_window_end,
                ProviderScholarship.is_approved == True
            ).all()

            scholarships_to_remind = []
            for scholarship in admin_scholarships:
                if match_criteria(user_info, scholarship):
                    if not ReminderLog.query.filter_by(
                        user_id=user.id,
                        scholarship_type='admin',
                        scholarship_id=scholarship.id
                    ).first():
                        scholarships_to_remind.append(('admin', scholarship))

            for scholarship in provider_scholarships:
                if match_provider_criteria(user_info, scholarship):
                    if not ReminderLog.query.filter_by(
                        user_id=user.id,
                        scholarship_type='provider',
                        scholarship_id=scholarship.id
                    ).first():
                        scholarships_to_remind.append(('provider', scholarship))

            if scholarships_to_remind:
                subject = "Scholarvault: Scholarship Deadline Reminders"
                body = f"Dear {user.full_name},\n\n" + \
                       "This is a reminder that the following scholarships you are eligible for have deadlines approaching in 6 to 8 days:\n\n" + \
                       "\n".join([f"- {s.name}: Deadline on {s.deadline.strftime('%Y-%m-%d')} (in {(s.deadline - today).days} days), Amount: ₹{float(s.amount)}" for _, s in scholarships_to_remind]) + \
                       "\n\nPlease ensure you apply before the deadlines.\n\nBest regards,\nScholarvault Team"
                msg = Message(subject=subject, recipients=[user.email], body=body)
                try:
                    mail.send(msg)
                    for scholarship_type, scholarship in scholarships_to_remind:
                        reminder_log = ReminderLog(
                            user_id=user.id,
                            scholarship_type=scholarship_type,
                            scholarship_id=scholarship.id
                        )
                        db.session.add(reminder_log)
                    db.session.commit()
                except Exception as e:
                    db.session.rollback()
                    app.logger.error(f"Failed to send email: {str(e)}")

# Schedule the reminder task to run daily
scheduler.add_job(check_and_send_deadline_reminders, 'interval', days=1)

# --- Routes ---
@app.route('/test-reminders', methods=['GET'])
def test_reminders():
    check_and_send_deadline_reminders()
    return jsonify({"status": "success", "message": "Reminder check triggered"}), 200

@app.route('/login', methods=['POST'])
def student_login():
    try:
        data = request.get_json()
        if not data or 'email' not in data or 'password' not in data:
            return jsonify({"status": "error", "message": "Missing email or password"}), 400

        email = data.get('email')
        password = data.get('password')

        sleep(1)  # Simulate delay (optional, remove in production)
        user = User.query.filter_by(email=email).first()

        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404

        if not user.check_password(password):
            return jsonify({"status": "error", "message": "Invalid email or password"}), 401

        token = generate_token(user.id, 'user')
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "data": {
                "user_id": user.id,
                "email": user.email,
                "username": user.username,
                "token": token
            }
        }), 200
    except Exception as e:
        app.logger.error(f"Login error: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500

@app.route('/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"status": "error", "message": "Missing username or password"}), 400

    username = data.get('username')
    password = data.get('password')

    sleep(1)
    admin = Admin.query.filter_by(username=username).first()
    log = AdminLoginLog(username_attempt=username, success=False)

    if admin and admin.check_password(password):
        token = generate_token(admin.id, 'admin')
        log.admin_id = admin.id
        log.success = True
        db.session.add(log)
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "data": {
                "admin_id": admin.id,
                "username": admin.username,
                "token": token
            }
        }), 200
    else:
        db.session.add(log)
        db.session.commit()
        return jsonify({"status": "error", "message": "Invalid username or password"}), 401

@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    required_fields = [
        'full_name', 'password', 'email', 'phone', 'dob', 'gender', 'state',
        'education_level', 'field_of_study', 'institution', 'enrollment_year',
        'cgpa', 'twelfth_percentage', 'category', 'family_income'
    ]
    
    if not data or not all(field in data for field in required_fields):
        return jsonify({"status": "error", "message": "Missing required fields"}), 400
    # Validate phone number (must start with +91 for Indian nationality)
    phone = data['phone']
    if not phone.startswith('+91'):
        return jsonify({"status": "error", "message": "Only Indian students are eligible. Phone number must start with +91."}), 400

    # Validate state (restrict to Indian states)
    indian_states = [
        "Andhra Pradesh", "Arunachal Pradesh", "Assam", "Bihar", "Chhattisgarh", "Goa", "Gujarat", 
        "Haryana", "Himachal Pradesh", "Jharkhand", "Karnataka", "Kerala", "Madhya Pradesh", 
        "Maharashtra", "Manipur", "Meghalaya", "Mizoram", "Nagaland", "Odisha", "Punjab", 
        "Rajasthan", "Sikkim", "Tamil Nadu", "Telangana", "Tripura", "Uttar Pradesh", 
        "Uttarakhand", "West Bengal", "Andaman and Nicobar Islands", "Chandigarh", 
        "Dadra and Nagar Haveli and Daman and Diu", "Delhi", "Jammu and Kashmir", "Ladakh", 
        "Lakshadweep", "Puducherry"
    ]
    if data['state'] not in indian_states:
        return jsonify({"status": "error", "message": "State must be a valid Indian state."}), 400

    username = ''.join(data['full_name'].lower().split())
    if User.query.filter_by(username=username).first():
        counter = 1
        while User.query.filter_by(username=f"{username}{counter}").first():
            counter += 1
        username = f"{username}{counter}"

    if User.query.filter_by(email=data['email']).first():
        return jsonify({"status": "error", "message": "Email already exists"}), 409

    try:
        new_user = User(
            full_name=data['full_name'],
            username=username,
            email=data['email'],
            phone=data['phone'],
            dob=datetime.strptime(data['dob'], '%Y-%m-%d').date(),
            gender=data['gender'],
            state=data['state'],
            education_level=data['education_level'],
            field_of_study=data['field_of_study'],
            institution=data['institution'],
            enrollment_year=int(data['enrollment_year']),
            cgpa=float(data['cgpa']),
            twelfth_percentage=float(data['twelfth_percentage']),
            competitive_exams=data.get('competitive_exams', []),
            category=data['category'],
            family_income=data['family_income'],
            special_categories=data.get('special_categories', [])
        )
        new_user.set_password(data['password'])
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": "User created successfully",
            "data": {
                "user_id": new_user.id,
                "username": new_user.username,
                "email": new_user.email
            }
        }), 201
    except ValueError as e:
        return jsonify({"status": "error", "message": f"Invalid data format: {str(e)}"}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500

@app.route('/provider/signup', methods=['POST'])
def provider_signup():
    if not request.form or not all(field in request.form for field in ['name', 'email', 'password', 'organization', 'phone']):
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    if 'idProof' not in request.files:
        return jsonify({"status": "error", "message": "ID Proof is required"}), 400

    id_proof = request.files['idProof']
    if id_proof.filename == '':
        return jsonify({"status": "error", "message": "No ID Proof file selected"}), 400

    # Validate file type
    allowed_extensions = {'pdf', 'jpg', 'jpeg', 'png'}
    if not ('.' in id_proof.filename and id_proof.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
        return jsonify({"status": "error", "message": "Invalid file type. Allowed: PDF, JPG, JPEG, PNG"}), 400

    # Validate file size (5MB limit)
    if id_proof.content_length > 5 * 1024 * 1024:
        return jsonify({"status": "error", "message": "File size exceeds 5MB limit"}), 400

    if ScholarshipProvider.query.filter_by(email=request.form['email']).first():
        return jsonify({"status": "error", "message": "Email already exists"}), 409

    try:
        # Save the ID proof file
        upload_dir = os.path.join('uploads', 'provider_id_proofs')
        os.makedirs(upload_dir, exist_ok=True)
        filename = secure_filename(id_proof.filename)
        filepath = os.path.join(upload_dir, f"{request.form['email']}_{filename}")
        id_proof.save(filepath)

        # Create new provider
        new_provider = ScholarshipProvider(
            name=request.form['name'],
            email=request.form['email'],
            organization=request.form['organization'],
            phone=request.form['phone'],
            id_proof_path=filepath  # Store the filepath in the database
        )
        new_provider.set_password(request.form['password'])

        db.session.add(new_provider)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Scholarship Provider registered successfully. ID proof uploaded.",
            "data": {"provider_id": new_provider.id, "email": new_provider.email}
        }), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Signup error: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500

@app.route('/provider/login', methods=['POST'])
def provider_login():
    data = request.get_json()
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({"status": "error", "message": "Missing email or password"}), 400

    provider = ScholarshipProvider.query.filter_by(email=data['email']).first()
    if provider and provider.check_password(data['password']):
        token = generate_token(provider.id, 'provider')
        return jsonify({
            "status": "success",
            "message": "Login successful",
            "data": {"provider_id": provider.id, "email": provider.email, "token": token}
        }), 200
    return jsonify({"status": "error", "message": "Invalid email or password"}), 401

@app.route('/provider/scholarships', methods=['POST'])
@token_required
def add_provider_scholarship(current_user, current_admin, current_provider):
    if not current_provider:
        return jsonify({"status": "error", "message": "Unauthorized: Provider access required"}), 403

    data = request.get_json()
    required_fields = ['name', 'description', 'amount', 'eligibility_criteria', 'required_documents']
    if not data or not all(field in data for field in required_fields):
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    try:
        new_scholarship = ProviderScholarship(
            provider_id=current_provider.id,
            name=data['name'],
            description=data['description'],
            amount=float(data['amount']),
            deadline=datetime.strptime(data.get('deadline'), '%Y-%m-%d').date() if data.get('deadline') else None,
            eligibility_criteria=data['eligibility_criteria'],
            required_documents=data['required_documents'],
            about_the_program=data.get('about_the_program'),
            eligibility=data.get('eligibility'),
            benefits=data.get('benefits'),
            application_link=data.get('application_link')
        )
        db.session.add(new_scholarship)
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": "Scholarship submitted for approval",
            "data": {"scholarship_id": new_scholarship.id, "name": new_scholarship.name}
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500

@app.route('/scholarships/providers/<int:scholarship_id>/requirements', methods=['GET'])
@token_required
def get_scholarship_requirements(current_user, current_admin, current_provider, scholarship_id):
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized: User access required"}), 403

    scholarship = ProviderScholarship.query.get_or_404(scholarship_id)
    return jsonify({
        "status": "success",
        "message": "Scholarship requirements retrieved",
        "data": {
            "scholarship_id": scholarship.id,
            "name": scholarship.name,
            "description": scholarship.description,
            "amount": float(scholarship.amount),
            "deadline": scholarship.deadline.isoformat() if scholarship.deadline else None,
            "required_documents": scholarship.required_documents,
            "eligibility_criteria": scholarship.eligibility_criteria,
            "about_the_program": scholarship.about_the_program,
            "eligibility": scholarship.eligibility,
            "benefits": scholarship.benefits,
            "application_link": scholarship.application_link
        }
    }), 200

@app.route('/admin/provider_scholarships', methods=['GET'])
@token_required
def get_pending_provider_scholarships(current_user, current_admin, current_provider):
    if not current_admin:
        return jsonify({"status": "error", "message": "Unauthorized: Admin access required"}), 403

    # Join ProviderScholarship with ScholarshipProvider to get provider details
    scholarships = db.session.query(ProviderScholarship, ScholarshipProvider).\
        join(ScholarshipProvider, ProviderScholarship.provider_id == ScholarshipProvider.id).\
        filter(ProviderScholarship.is_approved == False).all()

    data = []
    for scholarship, provider in scholarships:
        scholarship_data = {
            "id": scholarship.id,
            "provider_id": scholarship.provider_id,
            "provider_name": provider.name,  # Include provider's name for clarity
            "provider_email": provider.email,  # Include provider's email
            "name": scholarship.name,
            "description": scholarship.description,
            "amount": float(scholarship.amount),
            "deadline": scholarship.deadline.isoformat() if scholarship.deadline else None,
            "eligibility_criteria": scholarship.eligibility_criteria,
            "required_documents": scholarship.required_documents,
            "id_proof_url": f"/admin/provider_id_proof/{provider.id}" if provider.id_proof_path else None  # URL to download ID proof
        }
        data.append(scholarship_data)

    return jsonify({
        "status": "success",
        "message": "Pending scholarships retrieved with provider ID proof details",
        "data": data
    }), 200
@app.route('/admin/provider_scholarship_details/<int:scholarship_id>', methods=['GET'])
@token_required
def get_provider_scholarship_details(current_user, current_admin, current_provider, scholarship_id):
    if not current_admin:
        return jsonify({"status": "error", "message": "Unauthorized: Admin access required"}), 403

    scholarship = ProviderScholarship.query.get_or_404(scholarship_id)
    provider = ScholarshipProvider.query.get_or_404(scholarship.provider_id)

    details = {
        "id": scholarship.id,
        "name": scholarship.name,
        "provider_name": provider.name,
        "about_the_program": scholarship.about_the_program or "No details provided",  # Assuming this field exists
        "eligibility_criteria": scholarship.eligibility_criteria or "No criteria provided",
        "benefits": scholarship.benefits or "No benefits specified",  # Assuming this field exists
        "amount": float(scholarship.amount),
        "deadline": scholarship.deadline.isoformat() if scholarship.deadline else None,
        "required_documents": scholarship.required_documents
    }

    return jsonify({
        "status": "success",
        "message": "Scholarship details retrieved successfully",
        "data": details
    }), 200
# New endpoint to serve the ID proof file
@app.route('/admin/provider_id_proof/<int:provider_id>', methods=['GET'])
@token_required
def get_provider_id_proof(current_user, current_admin, current_provider, provider_id):
    if not current_admin:
        return jsonify({"status": "error", "message": "Unauthorized: Admin access required"}), 403

    provider = ScholarshipProvider.query.get_or_404(provider_id)
    if not provider.id_proof_path or not os.path.exists(provider.id_proof_path):
        return jsonify({"status": "error", "message": "ID proof not found"}), 404

    try:
        return send_file(
            provider.id_proof_path,
            as_attachment=True,
            download_name=os.path.basename(provider.id_proof_path),
            mimetype='application/octet-stream'
        )
    except Exception as e:
        app.logger.error(f"Failed to serve ID proof: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500

@app.route('/admin/provider_scholarships/<int:scholarship_id>/status', methods=['POST'])
@token_required
def update_provider_scholarship_status(current_user, current_admin, current_provider, scholarship_id):
    if not current_admin:
        return jsonify({"status": "error", "message": "Unauthorized: Admin access required"}), 403

    scholarship = ProviderScholarship.query.get_or_404(scholarship_id)

    # Extract action from request (approve or reject)
    data = request.get_json()
    action = data.get("action")  # Expecting "approve" or "reject"

    if action == "approve":
        if scholarship.is_approved:
            return jsonify({"status": "error", "message": "Scholarship already approved"}), 400
        scholarship.is_approved = True
        scholarship.is_rejected = False  # Ensure it's not marked as rejected
        message = "Scholarship approved"
    
    elif action == "reject":
        if scholarship.is_rejected:
            return jsonify({"status": "error", "message": "Scholarship already rejected"}), 400
        scholarship.is_approved = False  # Ensure it's not marked as approved
        scholarship.is_rejected = True
        message = "Scholarship rejected"

    else:
        return jsonify({"status": "error", "message": "Invalid action"}), 400

    db.session.commit()
    return jsonify({"status": "success", "message": message}), 200

@app.route('/scholarships/providers/<int:scholarship_id>/apply', methods=['POST'])
@token_required
def apply_for_scholarship(current_user, current_admin, current_provider, scholarship_id):
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized: User access required"}), 403

    scholarship = ProviderScholarship.query.get_or_404(scholarship_id)
    if not scholarship.is_approved:
        return jsonify({"status": "error", "message": "Scholarship not approved yet"}), 400

    user = User.query.get(current_user.id)
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    if not request.form or 'application_data' not in request.form:
        return jsonify({"status": "error", "message": "Missing application data"}), 400

    try:
        # Parse application data
        application_data = json.loads(request.form['application_data'])
        required_fields = ['reason_for_applying', 'course', 'year_of_study']
        if not all(field in application_data for field in required_fields):
            return jsonify({"status": "error", "message": "Missing required application fields"}), 400

        # Get existing documents from database
        user_docs = Document.query.filter_by(user_id=current_user.id).all()
        existing_doc_paths = {doc.filename.split('.')[0].lower(): doc.filepath for doc in user_docs}

        # Handle file uploads
        required_docs = [doc.lower() for doc in scholarship.required_documents]
        uploaded_files = request.files.getlist('documents')
        income_certificate = request.files.get('income_certificate')
        student_id_card = request.files.get('student_id_card')
        uploaded_doc_paths = []

        upload_dir = os.path.join('uploads', str(current_user.id))
        os.makedirs(upload_dir, exist_ok=True)

        # Process income certificate
        income_cert_path = existing_doc_paths.get('income_cert')
        if income_certificate and income_certificate.filename:
            income_cert_filename = secure_filename(income_certificate.filename)
            income_cert_filepath = os.path.join(upload_dir, f"income_cert_{income_cert_filename}")
            if 'income_cert' not in existing_doc_paths or income_certificate.filename != list(existing_doc_paths.keys())[list(existing_doc_paths.values()).index(income_cert_path)]:
                income_certificate.save(income_cert_filepath)
                income_cert_path = income_cert_filepath
                uploaded_doc_paths.append(income_cert_filepath)
        elif 'income_cert' not in existing_doc_paths:
            return jsonify({"status": "error", "message": "Family income certificate is required"}), 400

        # Process student ID card
        student_id_path = existing_doc_paths.get('student_id')
        if student_id_card and student_id_card.filename:
            student_id_filename = secure_filename(student_id_card.filename)
            student_id_filepath = os.path.join(upload_dir, f"student_id_{student_id_filename}")
            if 'student_id' not in existing_doc_paths or student_id_card.filename != list(existing_doc_paths.keys())[list(existing_doc_paths.values()).index(student_id_path)]:
                student_id_card.save(student_id_filepath)
                student_id_path = student_id_filepath
                uploaded_doc_paths.append(student_id_filepath)
        elif 'student_id' not in existing_doc_paths:
            return jsonify({"status": "error", "message": "Student ID card is required"}), 400

        # Process other uploaded documents
        for file in uploaded_files:
            if file and file.filename:
                filename = secure_filename(file.filename)
                doc_name = filename.split('.')[0].lower()
                filepath = os.path.join(upload_dir, filename)
                if doc_name not in existing_doc_paths or file.filename != list(existing_doc_paths.keys())[list(existing_doc_paths.values()).index(existing_doc_paths.get(doc_name))]:
                    file.save(filepath)
                    uploaded_doc_paths.append(filepath)

        # Combine existing and uploaded documents
        all_doc_paths = list(existing_doc_paths.values()) + uploaded_doc_paths
        provided_doc_names = {os.path.basename(path).split('.')[0].lower() for path in all_doc_paths}

        # Verify required documents (including student ID card)
        required_docs.append('student_id')  # Add student ID card as a required document
        missing_docs = [req_doc for req_doc in required_docs if req_doc not in provided_doc_names]
        if missing_docs:
            return jsonify({
                "status": "error",
                "message": f"Missing required documents: {', '.join(missing_docs)}"
            }), 400

        # Save new documents to database
        for filepath in uploaded_doc_paths:
            filename = os.path.basename(filepath)
            doc = Document(user_id=current_user.id, filename=filename, filepath=filepath)
            db.session.add(doc)

        # Create application
        application = ScholarshipApplication(
            user_id=current_user.id,
            scholarship_id=scholarship_id,
            documents=all_doc_paths,
            name=user.full_name,
            dob=user.dob,
            email=user.email,
            institution=user.institution,
            course=application_data['course'],
            year_of_study=application_data['year_of_study'],
            cgpa=user.cgpa,
            family_income=user.family_income,
            income_certificate=income_cert_path,
            student_id_card=student_id_path,
            reason_for_applying=application_data['reason_for_applying'],
            previous_scholarships=application_data.get('previous_scholarships', [])
        )
        
        db.session.add(application)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Application submitted",
            "data": {
                "application_id": application.id,
                "included_documents": all_doc_paths,
                "application_data": {
                    "name": application.name,
                    "dob": application.dob.isoformat(),
                    "email": application.email,
                    "institution": application.institution,
                    "course": application.course,
                    "year_of_study": application.year_of_study,
                    "cgpa": application.cgpa,
                    "family_income": application.family_income,
                    "income_certificate": application.income_certificate,
                    "student_id_card": application.student_id_card,
                    "reason_for_applying": application.reason_for_applying,
                    "previous_scholarships": application.previous_scholarships
                }
            }
        }), 201

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Application error: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500
@app.route('/provider/applications', methods=['GET'])
@token_required
def get_provider_applications(current_user, current_admin, current_provider):
    if not current_provider:
        return jsonify({"status": "error", "message": "Unauthorized: Provider access required"}), 403

    applications = ScholarshipApplication.query.join(
        ProviderScholarship, ScholarshipApplication.scholarship_id == ProviderScholarship.id
    ).filter(ProviderScholarship.provider_id == current_provider.id).all()

    data = [{
        "id": app.id,
        "user_id": app.user_id,
        "scholarship_id": app.scholarship_id,
        "status": app.status,
        "applied_at": app.applied_at.isoformat(),
        "documents": app.documents
    } for app in applications]
    return jsonify({"status": "success", "message": "Applications retrieved", "data": data}), 200
@app.route('/provider/my_scholarships', methods=['GET'])
@token_required
def get_provider_own_scholarships(current_user, current_admin, current_provider):
    if not current_provider:
        return jsonify({"status": "error", "message": "Unauthorized: Provider access required"}), 403

    scholarships = ProviderScholarship.query.filter_by(provider_id=current_provider.id).all()
    
    data = [{
        "id": s.id,
        "name": s.name,
        "description": s.description,
        "amount": float(s.amount),
        "deadline": s.deadline.isoformat() if s.deadline else None,
        "eligibility_criteria": s.eligibility_criteria,
        "required_documents": s.required_documents,
        "is_approved": s.is_approved,
        "about_the_program": s.about_the_program,
        "eligibility": s.eligibility,
        "benefits": s.benefits,
        "application_link": s.application_link
    } for s in scholarships]

    return jsonify({
        "status": "success",
        "message": "Your scholarships retrieved",
        "data": data
    }), 200
@app.route('/provider/applications/<int:application_id>', methods=['GET'])
@token_required
def get_application_details(current_user, current_admin, current_provider, application_id):
    if not current_provider:
        return jsonify({"status": "error", "message": "Unauthorized: Provider access required"}), 403

    application = ScholarshipApplication.query.get_or_404(application_id)
    scholarship = ProviderScholarship.query.get(application.scholarship_id)
    if scholarship.provider_id != current_provider.id:
        return jsonify({"status": "error", "message": "Unauthorized: Not your scholarship"}), 403

    data = {
        "id": application.id,
        "user_id": application.user_id,
        "scholarship_id": application.scholarship_id,
        "status": application.status,
        "applied_at": application.applied_at.isoformat(),
        "documents": application.documents,
        "name": application.name,
        "dob": application.dob.isoformat(),
        "email": application.email,
        "institution": application.institution,
        "course": application.course,
        "year_of_study": application.year_of_study,
        "cgpa": application.cgpa,
        "family_income": application.family_income,
        "income_certificate": application.income_certificate,
        "reason_for_applying": application.reason_for_applying,
        "previous_scholarships": application.previous_scholarships
    }
    
    return jsonify({
        "status": "success",
        "message": "Application details retrieved",
        "data": data
    }), 200

@app.route('/provider/applications/<int:application_id>/review', methods=['POST'])
@token_required
def review_application(current_user, current_admin, current_provider, application_id):
    if not current_provider:
        return jsonify({"status": "error", "message": "Unauthorized: Provider access required"}), 403

    application = ScholarshipApplication.query.get_or_404(application_id)
    scholarship = ProviderScholarship.query.get(application.scholarship_id)
    if scholarship.provider_id != current_provider.id:
        return jsonify({"status": "error", "message": "Unauthorized: Not your scholarship"}), 403

    data = request.get_json()
    status = data.get('status')  # 'accepted' or 'rejected'
    if status not in ['accepted', 'rejected']:
        return jsonify({"status": "error", "message": "Invalid status"}), 400

    application.status = status
    db.session.commit()
    return jsonify({"status": "success", "message": f"Application {status}"}), 200


# --- Routes ---
# --- Routes ---

# Replace all category-specific routes with this single parameterized route
@app.route('/scholarships/<category>', methods=['GET'])
@token_required
def get_scholarships_by_category_single(current_user, current_admin, current_provider, category):
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized: User access required"}), 403
    category_map = {
        'forgirls': "For Girls",
        'sportstalent': "Sports Talent",
        'scstobcdnt': "SC/ST/OBC/DNT",
        'minorities': "Minorities",
        'meritbased': "Merit Based",
        'providers': "Provider Scholarships"
    }
    if category not in category_map:
        return jsonify({"status": "error", "message": "Invalid category"}), 400
    current_date = datetime.now(pytz.UTC).date()
    eligible_scholarships = get_eligible_scholarships_by_category(current_user, category_map[category], current_date)
    
    if eligible_scholarships is None:
        return jsonify({"status": "error", "message": "User not found"}), 404
    if not eligible_scholarships:
        return jsonify({"status": "success", "message": "Nothing to show"}), 200
    
    return jsonify({
        "status": "success",
        "message": f"Eligible {category} scholarships retrieved",
        "data": eligible_scholarships
    }), 200
@app.route('/scholarships/all', methods=['GET'])
@token_required
def get_all_eligible_scholarships(current_user, current_admin, current_provider):
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized: User access required"}), 403

    current_date = datetime.now(pytz.UTC).date()
    eligible_scholarships = get_eligible_scholarships_for_user(current_user, current_date)

    if eligible_scholarships is None:
        return jsonify({"status": "error", "message": "User not found"}), 404
    if not eligible_scholarships:
        return jsonify({"status": "success", "message": "Nothing to show"}), 200

    return jsonify({
        "status": "success",
        "message": "Eligible scholarships retrieved",
        "data": eligible_scholarships
    }), 200

@app.route('/scholarships', methods=['POST'])
@token_required
def add_scholarship(current_user, current_admin, current_provider):
    if not current_admin:
        return jsonify({"status": "error", "message": "Unauthorized: Admin access required"}), 403

    data = request.get_json()
    required_fields = ['name', 'amount']
    if not data or not all(field in data for field in required_fields):
        return jsonify({"status": "error", "message": "Missing required fields"}), 400

    try:
        new_scholarship = Scholarship(
            name=data['name'],
            organization=data.get('organization'),
            description=data.get('description'),
            amount=float(data['amount']),
            deadline=datetime.strptime(data.get('deadline', ''), '%Y-%m-%d').date() if data.get('deadline') else None,
            category=data.get('category'),
            cgpa=float(data.get('cgpa')) if data.get('cgpa') else None,
            twelfth_marks=float(data.get('twelfth_marks')) if data.get('twelfth_marks') else None,
            gender=data.get('gender'),
            income=data.get('income'),
            special_category=data.get('special_category'),
            criteria=data.get('criteria'),
            about_the_program=data.get('about_the_program'),
            eligibility=data.get('eligibility'),
            benefits=data.get('benefits'),
            application_link=data.get('application_link')
        )
        db.session.add(new_scholarship)
        db.session.flush()

        notice_title = f"New Scholarship Added: {new_scholarship.name}"
        latest_deadline = new_scholarship.deadline.strftime('%Y-%m-%d') if new_scholarship.deadline else 'N/A'
        notice_content = f"A new scholarship '{new_scholarship.name}' has been added by {current_admin.username}. Amount: {new_scholarship.amount}, Deadline: {latest_deadline}."
        new_notice = Notice(
            title=notice_title,
            content=notice_content,
            admin_id=current_admin.id
        )
        db.session.add(new_notice)

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Scholarship and notice added successfully",
            "data": {
                "id": new_scholarship.id,
                "name": new_scholarship.name,
                "organization": new_scholarship.organization,
                "description": new_scholarship.description,
                "amount": float(new_scholarship.amount),
                "deadline": new_scholarship.deadline.isoformat() if new_scholarship.deadline else None,
                "category": new_scholarship.category,
                "cgpa": new_scholarship.cgpa,
                "twelfth_marks": new_scholarship.twelfth_marks,
                "gender": new_scholarship.gender,
                "income": new_scholarship.income,
                "special_category": new_scholarship.special_category,
                "criteria": new_scholarship.criteria,
                "about_the_program": new_scholarship.about_the_program,
                "eligibility": new_scholarship.eligibility,
                "benefits": new_scholarship.benefits,
                "application_link": new_scholarship.application_link
            }
        }), 201
    except ValueError as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Invalid data format: {str(e)}"}), 400
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500

@app.route('/scholarships/<int:scholarship_id>', methods=['GET'])
@token_required
def get_scholarship_details(current_user, current_admin, current_provider, scholarship_id):
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized: User access required"}), 403

    # Get the scholarship type from the query parameter
    scholarship_type = request.args.get('type', 'admin').lower()
    app.logger.info(f"Fetching scholarship ID {scholarship_id} with type {scholarship_type}")

    # Validate scholarship type
    if scholarship_type not in ['admin', 'provider']:
        return jsonify({"status": "error", "message": "Invalid scholarship type"}), 400

    # Fetch the scholarship based on the type
    try:
        if scholarship_type == 'provider':
            scholarship = ProviderScholarship.query.get(scholarship_id)
            if not scholarship:
                return jsonify({"status": "error", "message": "Provider scholarship not found"}), 404
            if not scholarship.is_approved:
                return jsonify({"status": "error", "message": "Provider scholarship not approved"}), 403
            provider = ScholarshipProvider.query.get(scholarship.provider_id)
            scholarship_details = {
                "id": scholarship.id,
                "type": "provider",
                "name": scholarship.name,
                "organization": provider.name if provider else "Unknown Provider",
                "description": scholarship.description,
                "amount": float(scholarship.amount),
                "deadline": scholarship.deadline.isoformat() if scholarship.deadline else None,
                "required_documents": scholarship.required_documents or [],
                "eligibility_criteria": scholarship.eligibility_criteria or {},
                "about_the_program": scholarship.about_the_program or "No details provided",
                "eligibility": scholarship.eligibility or "No eligibility criteria specified",
                "benefits": scholarship.benefits or "No benefits specified",
                "application_link": scholarship.application_link or ""
            }
        else:  # admin
            scholarship = Scholarship.query.get(scholarship_id)
            if not scholarship:
                return jsonify({"status": "error", "message": "Scholarship not found"}), 404
            scholarship_details = {
                "id": scholarship.id,
                "type": "admin",
                "name": scholarship.name,
                "organization": scholarship.organization or "ScholarVault",
                "description": scholarship.description or "No description available",
                "amount": float(scholarship.amount),
                "deadline": scholarship.deadline.isoformat() if scholarship.deadline else None,
                "category": scholarship.category or "General",
                "criteria": scholarship.criteria or {},
                "required_documents": [],  # Assuming admin scholarships don't specify documents; adjust if needed
                "about_the_program": scholarship.about_the_program or "No details provided",
                "eligibility": scholarship.eligibility or "No eligibility criteria specified",
                "benefits": scholarship.benefits or "No benefits specified",
                "application_link": scholarship.application_link or ""
            }

        return jsonify({
            "status": "success",
            "message": "Scholarship details retrieved",
            "data": scholarship_details
        }), 200
    except Exception as e:
        app.logger.error(f"Error fetching scholarship details: {str(e)}")
        return jsonify({"status": "error", "message": "Server error while fetching scholarship details"}), 500
@app.route('/admin/notices', methods=['POST'])
@token_required
def add_notice(current_user, current_admin, current_provider):
    print(f"Add notice - Current admin: {current_admin}")  # Debug log
    if not current_admin:
        return jsonify({"status": "error", "message": "Unauthorized: Admin access required"}), 403

    data = request.get_json()
    if not data or 'title' not in data or 'content' not in data:
        return jsonify({"status": "error", "message": "Title and content are required"}), 400

    title = data['title']
    content = data['content']

    new_notice = Notice(
        title=title,
        content=content,
        admin_id=current_admin.id
    )

    try:
        db.session.add(new_notice)
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": "Notice added successfully",
            "data": {
                "id": new_notice.id,
                "title": new_notice.title,
                "content": new_notice.content,
                "created_at": new_notice.created_at.isoformat(),
                "admin_id": new_notice.admin_id
            }
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Failed to add notice: {str(e)}"}), 500

@app.route('/admin/notices/<int:notice_id>', methods=['DELETE'])
@token_required
def delete_notice(current_user, current_admin, current_provider, notice_id):
    print(f"Delete notice - Current admin: {current_admin}")  # Debug log
    if not current_admin:
        return jsonify({"status": "error", "message": "Unauthorized: Admin access required"}), 403

    notice = Notice.query.get_or_404(notice_id)
    print(f"Notice admin_id: {notice.admin_id}, Current admin id: {current_admin.id}")  # Debug log
    if notice.admin_id != current_admin.id:
        return jsonify({"status": "error", "message": "Unauthorized: You can only delete your own notices"}), 403

    try:
        db.session.delete(notice)
        db.session.commit()
        return jsonify({
            "status": "success",
            "message": "Notice deleted successfully"
        }), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": f"Failed to delete notice: {str(e)}"}), 500
@app.route('/notices', methods=['GET'])
def get_notices():
    try:
        notices = Notice.query.order_by(Notice.created_at.desc()).all()
        notices_data = [
            {
                "id": notice.id,
                "title": notice.title,
                "content": notice.content,
                "created_at": notice.created_at.isoformat(),
                "admin_id": notice.admin_id
            }
            for notice in notices
        ]
        return jsonify({
            "status": "success",
            "message": "Notices retrieved successfully",
            "data": notices_data
        }), 200
    except Exception as e:
        return jsonify({"status": "error", "message": f"Failed to retrieve notices: {str(e)}"}), 500
@app.route('/upload_document', methods=['POST'])
@token_required
def upload_document(current_user, current_admin, current_provider):
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized: User access required"}), 403

    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file"}), 400

    allowed_extensions = {'pdf', 'doc', 'docx', 'png', 'jpg', 'jpeg'}
    if not ('.' in file.filename and file.filename.rsplit('.', 1)[1].lower() in allowed_extensions):
        return jsonify({"status": "error", "message": "File type not allowed"}), 400

    filename = secure_filename(file.filename)
    upload_dir = os.path.join('uploads', str(current_user.id))
    os.makedirs(upload_dir, exist_ok=True)
    filepath = os.path.join(upload_dir, filename)

    if os.path.exists(filepath):
        return jsonify({"status": "error", "message": "File already exists"}), 400

    try:
        file.save(filepath)
    except Exception as e:
        app.logger.error(f"Failed to save file: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to save file"}), 500

    # Get document type from the request
    document_type = request.form.get('document_type', 'Unknown')

    try:
        doc = Document(
            user_id=current_user.id,
            filename=filename,
            filepath=filepath,
            document_type=document_type  # Save document type
        )
        db.session.add(doc)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Database error: {str(e)}")
        return jsonify({"status": "error", "message": "Failed to save document details"}), 500

    return jsonify({
        "status": "success",
        "message": "Document uploaded successfully",
        "data": {
            "document_id": doc.id,
            "filename": doc.filename,
            "upload_date": doc.upload_date.isoformat(),
            "filepath": doc.filepath,
            "document_type": doc.document_type
        }
    }), 201
@app.route('/delete_document/<int:document_id>', methods=['DELETE'])
@token_required
def delete_document(current_user, current_admin, current_provider, document_id):
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized: User access required"}), 403

    try:
        # Fetch the document
        document = Document.query.get_or_404(document_id)

        # Ensure the document belongs to the current user
        if document.user_id != current_user.id:
            return jsonify({"status": "error", "message": "Unauthorized: You can only delete your own documents"}), 403

        # Delete the file from the filesystem
        if os.path.exists(document.filepath):
            os.remove(document.filepath)
        else:
            app.logger.warning(f"File not found on disk: {document.filepath}")

        # Delete the document record from the database
        db.session.delete(document)
        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Document deleted successfully"
        }), 200

    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Failed to delete document: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500
    
@app.route('/user/documents', methods=['GET'])
@token_required
def get_user_documents(current_user, current_admin, current_provider):
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized: User access required"}), 403

    try:
        documents = Document.query.filter_by(user_id=current_user.id).all()
        
        if not documents:
            return jsonify({
                "status": "success",
                "message": "No documents found",
                "data": []
            }), 200

        documents_data = [
            {
                "id": doc.id,
                "filename": doc.filename,
                "upload_date": doc.upload_date.isoformat(),
                "download_url": f"/download_document/{doc.id}",
                "document_type": doc.document_type  # Include document type
            }
            for doc in documents
        ]

        return jsonify({
            "status": "success",
            "message": "Documents retrieved successfully",
            "data": documents_data
        }), 200

    except Exception as e:
        app.logger.error(f"Failed to retrieve documents: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500
@app.route('/user/profile', methods=['GET'])
@token_required
def get_user_profile(current_user, current_admin, current_provider):
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized: User access required"}), 403

    user = User.query.get(current_user.id)
    if not user:
        return jsonify({"status": "error", "message": "User not found"}), 404

    return jsonify({
        "status": "success",
        "data": {
            "name": user.full_name,
            "dob": user.dob.isoformat() if user.dob else None,
            "email": user.email,
            "institution": user.institution,
            "cgpa": user.cgpa,
            "family_income": user.family_income,
            "phone": user.phone 
        }
    }), 200
@app.route('/view_document/<int:document_id>')
def view_document(document_id):
    document = Document.query.get_or_404(document_id)

    # Optional: security check if user must be logged in to view
    # if 'user_id' not in session or document.user_id != session['user_id']:
    #     return "Unauthorized", 403

    return send_file(
        document.filepath,
        as_attachment=False,
        download_name=document.filename,
        mimetype='application/octet-stream'  # or use correct mime type if needed
    )

@app.route('/download_document/<int:document_id>', methods=['GET'])
@token_required
def download_document(current_user, current_admin, current_provider, document_id):
    if not current_user:
        return jsonify({"status": "error", "message": "Unauthorized: User access required"}), 403

    try:
        # Fetch the document
        document = Document.query.get_or_404(document_id)
        
        # Ensure the document belongs to the current user
        if document.user_id != current_user.id:
            return jsonify({"status": "error", "message": "Unauthorized: You can only download your own documents"}), 403

        # Send the file for download
        return send_file(
            document.filepath,
            as_attachment=True,
            download_name=document.filename,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        app.logger.error(f"Failed to download document: {str(e)}")
        return jsonify({"status": "error", "message": f"Server error: {str(e)}"}), 500



# --- Run the App ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # This will create the new tables
    app.run(debug=True)