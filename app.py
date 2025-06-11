from flask import Flask, render_template, request, redirect, url_for, flash, send_file, g, session, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, IntegerField, SelectField, TextAreaField, DateField, SubmitField, PasswordField, FileField
from wtforms.validators import DataRequired, NumberRange, Email, ValidationError, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_caching import Cache
from datetime import datetime, timedelta, date
import os
import requests
from email.mime.text import MIMEText
import smtplib
import json
from uuid import uuid4
from sqlalchemy.sql import text
import re
from flask_socketio import SocketIO, emit
from werkzeug.utils import secure_filename
from flask_paginate import Pagination, get_page_args
import logging
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
from flask_restful import Api, Resource
from functools import wraps
from flask import session as flask_session
from dotenv import load_dotenv
import pytz
from wtforms.validators import DataRequired
from flask_migrate import Migrate

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__, template_folder='templates', static_folder='static')
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', str(uuid4()))  # Secure random key
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('SQLALCHEMY_DATABASE_URI', 'sqlite:///construction.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['CACHE_TYPE'] = 'redis' if os.environ.get('REDIS_URL') else 'simple'
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static/uploads')
app.config['ALLOWED_EXTENSIONS'] = {'.pdf', '.png', '.jpg', '.jpeg'}
app.config['ALLOWED_MIME_TYPES'] = {'application/pdf', 'image/png', 'image/jpeg'}
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB
app.config['SQLALCHEMY_ECHO'] = False  # Disable query logging in production

# Initialize extensions
db = SQLAlchemy(app)
cache = Cache(app)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager()
login_manager.init_app(app)
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
login_manager.login_view = 'login'
api = Api(app)
migrate = Migrate(app, db)  # Moved after app definition

# Timezone for IST
IST = pytz.timezone('Asia/Kolkata')

# Custom filter for strftime
@app.template_filter('strftime')
def strftime_filter(value, format='%Y-%m-%d %H:%M'):
    if isinstance(value, str):
        try:
            value = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return value
    return value.strftime(format) if value else ''

# Database Models
class Company(db.Model):
    __tablename__ = 'companies'
    company_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    users = db.relationship('User', backref='company', lazy=True)
    employees = db.relationship('Employee', backref='company', lazy=True)
    orders = db.relationship('Order', backref='company', lazy=True)
    incidents = db.relationship('Incident', backref='company', lazy=True)
    subcontractors = db.relationship('Subcontractor', backref='company', lazy=True)
    payments = db.relationship('Payment', backref='company', lazy=True)
    daily_reports = db.relationship('DailyReport', backref='company', lazy=True)
    equipment = db.relationship('Equipment', backref='company', lazy=True)
    weather = db.relationship('Weather', backref='company', lazy=True)
    blueprints = db.relationship('Blueprint', backref='company', lazy=True)
    blueprint_comments = db.relationship('BlueprintComment', backref='company', lazy=True)
    tasks = db.relationship('Task', backref='company', lazy=True)
    timesheets = db.relationship('Timesheet', backref='company', lazy=True)
    inventory = db.relationship('Inventory', backref='company', lazy=True)
    safety_audits = db.relationship('SafetyAudit', backref='company', lazy=True)
    licenses = db.relationship('License', backref='company', lazy=True)
    inductions = db.relationship('Induction', backref='company', lazy=True)
    permits = db.relationship('Permit', backref='company', lazy=True)
    projects = db.relationship('Project', backref='company', lazy=True)
    documents = db.relationship('Document', backref='company', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='company', lazy=True)
    sites = db.relationship('Site', backref='company', lazy=True)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'), nullable=False)
    role = db.relationship('Role', backref='users', lazy='joined')  # Eager loading
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)

class Role(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)
    permissions = db.relationship('Permission', secondary='role_permissions', backref='roles', lazy='joined')

class Permission(db.Model):
    __tablename__ = 'permissions'
    permission_id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False, unique=True)

class RolePermission(db.Model):
    __tablename__ = 'role_permissions'
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey('permissions.permission_id'), primary_key=True)

class Employee(db.Model):
    __tablename__ = 'employees'
    employee_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)
    phone = db.Column(db.String(20))
    licenses = db.relationship('License', backref='employee', lazy=True)
    inductions = db.relationship('Induction', backref='employee', lazy=True)
    timesheets = db.relationship('Timesheet', backref='employee', lazy=True)
    tasks = db.relationship('Task', backref='employee', lazy=True)
    project_assignments = db.relationship('ProjectAssignment', backref='employee', lazy=True)

class Order(db.Model):
    __tablename__ = 'orders'
    order_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    item = db.Column(db.String(100), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.site_id'), nullable=False)
    site = db.relationship('Site', backref='orders', lazy=True)
    status = db.Column(db.String(20), nullable=False)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicles.vehicle_id'))
    comments = db.Column(db.Text)
    rating = db.Column(db.Integer, default=0)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    vehicle = db.relationship('Vehicle', backref='orders', lazy=True)

class Vehicle(db.Model):
    __tablename__ = 'vehicles'
    vehicle_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)

class Incident(db.Model):
    __tablename__ = 'incidents'
    incident_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100))
    severity = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(20), nullable=False)
    date = db.Column(db.Date, nullable=False)
    reported_by = db.Column(db.String(50), nullable=False)

class Subcontractor(db.Model):
    __tablename__ = 'subcontractors'
    subcontractor_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    agreement_status = db.Column(db.String(20), nullable=False)
    payment_status = db.Column(db.String(20), nullable=False)
    payments = db.relationship('Payment', backref='subcontractor', lazy=True)

class Payment(db.Model):
    __tablename__ = 'payments'
    payment_id = db.Column(db.Integer, primary_key=True)
    subcontractor_id = db.Column(db.Integer, db.ForeignKey('subcontractors.subcontractor_id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    milestone = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), nullable=False)

class DailyReport(db.Model):
    __tablename__ = 'daily_reports'
    report_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.site_id'), nullable=False)
    site = db.relationship('Site', backref='daily_reports', lazy=True)
    date = db.Column(db.Date, nullable=False)
    manpower = db.Column(db.Integer, nullable=False)
    safety_activities = db.Column(db.Text)
    progress_notes = db.Column(db.Text)
    reported_by = db.Column(db.String(50), nullable=False)

class Equipment(db.Model):
    __tablename__ = 'equipment'
    equipment_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Available')
    last_maintenance_date = db.Column(db.Date)
    next_maintenance_date = db.Column(db.Date, nullable=False)
    maintenance_notes = db.Column(db.Text)

class Weather(db.Model):
    __tablename__ = 'weather'
    weather_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.site_id'), nullable=False)
    site = db.relationship('Site', backref='weather', lazy=True)
    date = db.Column(db.Date, nullable=False)
    temperature = db.Column(db.Float, nullable=False)
    condition = db.Column(db.String(100), nullable=False)
    precipitation = db.Column(db.Integer, nullable=False)
    wind_speed = db.Column(db.Float, nullable=False)
    warning = db.Column(db.String(100))

class Blueprint(db.Model):
    __tablename__ = 'blueprints'
    blueprint_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    file_url = db.Column(db.String(255), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.String(50), nullable=False)
    comments = db.relationship('BlueprintComment', backref='blueprint', lazy=True)

class BlueprintComment(db.Model):
    __tablename__ = 'blueprint_comments'
    comment_id = db.Column(db.Integer, primary_key=True)
    blueprint_id = db.Column(db.Integer, db.ForeignKey('blueprints.blueprint_id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    comment_text = db.Column(db.Text, nullable=False)
    commented_at = db.Column(db.DateTime, default=datetime.utcnow)
    commenter = db.Column(db.String(50), nullable=False)

class Task(db.Model):
    __tablename__ = 'tasks'
    task_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    assigned_to = db.Column(db.Integer, db.ForeignKey('employees.employee_id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.project_id'))
    project = db.relationship('Project', backref='tasks', lazy=True)

class Timesheet(db.Model):
    __tablename__ = 'timesheets'
    timesheet_id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.employee_id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    clock_in = db.Column(db.DateTime, nullable=False)
    clock_out = db.Column(db.DateTime)
    break_duration = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    approved_by = db.Column(db.String(50))

class Inventory(db.Model):
    __tablename__ = 'inventory'
    inventory_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    item_name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    reorder_point = db.Column(db.Integer, nullable=False)
    unit_price = db.Column(db.Float)
    location = db.Column(db.String(100))

class SafetyAudit(db.Model):
    __tablename__ = 'safety_audits'
    audit_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.site_id'), nullable=False)
    site = db.relationship('Site', backref='safety_audits', lazy=True)
    audit_date = db.Column(db.Date, nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), nullable=False)

class License(db.Model):
    __tablename__ = 'licenses'
    license_id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.employee_id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    license_type = db.Column(db.String(100), nullable=False)
    issue_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)

class Induction(db.Model):
    __tablename__ = 'inductions'
    induction_id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.employee_id'), nullable=False)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    induction_type = db.Column(db.String(100), nullable=False)
    completion_date = db.Column(db.Date, nullable=False)

class Permit(db.Model):
    __tablename__ = 'permits'
    permit_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    site_id = db.Column(db.Integer, db.ForeignKey('sites.site_id'), nullable=False)
    site = db.relationship('Site', backref='permits', lazy=True)
    permit_type = db.Column(db.String(100), nullable=False)
    issue_date = db.Column(db.Date, nullable=False)
    expiry_date = db.Column(db.Date, nullable=False)

class Site(db.Model):
    __tablename__ = 'sites'
    site_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)

class Project(db.Model):
    __tablename__ = 'projects'
    project_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), nullable=False)
    milestones = db.relationship('Milestone', backref='project', lazy=True)
    assignments = db.relationship('ProjectAssignment', backref='project', lazy=True)

class Milestone(db.Model):
    __tablename__ = 'milestones'
    milestone_id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.project_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    due_date = db.Column(db.Date, nullable=False)
    status = db.Column(db.String(20), nullable=False)

class ProjectAssignment(db.Model):
    __tablename__ = 'project_assignments'
    assignment_id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.project_id'), nullable=False)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.employee_id'), nullable=False)
    role = db.Column(db.String(50), nullable=False)

class Document(db.Model):
    __tablename__ = 'documents'
    document_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    title = db.Column(db.String(100), nullable=False)
    file_url = db.Column(db.String(255), nullable=False)
    version = db.Column(db.Integer, nullable=False, default=1)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)
    uploaded_by = db.Column(db.String(50), nullable=False)

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    log_id = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.company_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Forms
class PasswordValidator:
    def __call__(self, form, field):
        password = field.data
        if not re.search(r'[A-Z]', password):
            raise ValidationError('Password must contain at least one uppercase letter.')
        if not re.search(r'[a-z]', password):
            raise ValidationError('Password must contain at least one lowercase letter.')
        if not re.search(r'[0-9]', password):
            raise ValidationError('Password must contain at least one digit.')
        if not re.search(r'[!@#$%^&*]', password):
            raise ValidationError('Password must contain at least one special character.')

class OrderForm(FlaskForm):
    item = StringField('Item', validators=[DataRequired(), Length(max=100)])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=1)])
    site_id = SelectField('Site', coerce=int, validators=[DataRequired()])
    comments = TextAreaField('Comments')
    submit = SubmitField('Submit Order')

class LicenseForm(FlaskForm):
    employee_id = SelectField('Employee', coerce=int, validators=[DataRequired()])
    license_type = StringField('License Type', validators=[DataRequired(), Length(max=100)])
    issue_date = DateField('Issue Date', validators=[DataRequired()])
    expiry_date = DateField('Expiry Date', validators=[DataRequired()])
    submit = SubmitField('Add License')

    def validate_expiry_date(self, field):
        if field.data <= self.issue_date.data:
            raise ValidationError('Expiry date must be after issue date.')

class EmployeeForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=100)])
    role = StringField('Role', validators=[DataRequired(), Length(max=50)])
    phone = StringField('Phone', validators=[Length(max=20)])
    submit = SubmitField('Add Employee')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class CompanyLoginForm(FlaskForm):
    company_name = StringField('Company Name', validators=[DataRequired(), Length(max=100)])
    username = StringField('Username', validators=[DataRequired(), Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegisterForm(FlaskForm):
    company_name = StringField('Company Name', validators=[DataRequired(), Length(max=100)])
    username = StringField('Username', validators=[DataRequired(), Length(max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8), PasswordValidator()])
    role = SelectField('Role', choices=[('user', 'User'), ('admin', 'Admin')], validators=[DataRequired()])
    submit = SubmitField('Register')

class IncidentForm(FlaskForm):
    type = SelectField('Type', choices=[('Incident', 'Incident'), ('Near-Miss', 'Near-Miss'), ('Hazard', 'Hazard')], validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    location = StringField('Location', validators=[Length(max=100)])
    severity = SelectField('Severity', choices=[('Low', 'Low'), ('Medium', 'Medium'), ('High', 'High')], validators=[DataRequired()])
    submit = SubmitField('Report Incident')

class PaymentForm(FlaskForm):
    milestone = StringField('Milestone', validators=[DataRequired(), Length(max=100)])
    amount = IntegerField('Amount', validators=[DataRequired(), NumberRange(min=0)])
    due_date = DateField('Due Date', validators=[DataRequired()])
    submit = SubmitField('Add Payment')

class DailyReportForm(FlaskForm):
    site_id = SelectField('Site', coerce=int, validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    manpower = IntegerField('Manpower', validators=[DataRequired(), NumberRange(min=0)])
    safety_activities = TextAreaField('Safety Activities')
    progress_notes = TextAreaField('Progress Notes')
    submit = SubmitField('Submit Report')

class EquipmentForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(max=100)])
    type = StringField('Type', validators=[DataRequired(), Length(max=50)])
    last_maintenance_date = DateField('Last Maintenance Date')
    next_maintenance_date = DateField('Next Maintenance Date', validators=[DataRequired()])
    status = SelectField('Status', choices=[('Available', 'Available'), ('In Use', 'In Use'), ('Maintenance', 'Maintenance')])
    maintenance_notes = TextAreaField('Maintenance Notes')
    submit = SubmitField('Add Equipment')

class BlueprintForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    file = FileField('File', validators=[DataRequired()])
    submit = SubmitField('Upload Blueprint')

class TaskForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    assigned_to = SelectField('Assigned To', coerce=int, validators=[DataRequired()])
    due_date = DateField('Due Date', validators=[DataRequired()])
    project_id = SelectField('Project', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Add Task')

class TimesheetForm(FlaskForm):
    action = SelectField('Action', choices=[('clock_in', 'Clock In'), ('clock_out', 'Clock Out')], validators=[DataRequired()])
    break_duration = IntegerField('Break Duration (minutes)', default=0, validators=[NumberRange(min=0)])
    submit = SubmitField('Submit')

class InventoryForm(FlaskForm):
    item_name = StringField('Item Name', validators=[DataRequired(), Length(max=100)])
    category = StringField('Category', validators=[DataRequired(), Length(max=50)])
    quantity = IntegerField('Quantity', validators=[DataRequired(), NumberRange(min=0)])
    reorder_point = IntegerField('Reorder Point', validators=[DataRequired(), NumberRange(min=0)])
    unit_price = IntegerField('Unit Price', validators=[NumberRange(min=0)])
    location = StringField('Location', validators=[Length(max=100)])
    submit = SubmitField('Add Item')

class SafetyAuditForm(FlaskForm):
    site_id = SelectField('Site', coerce=int, validators=[DataRequired()])
    audit_date = DateField('Audit Date', validators=[DataRequired()])
    description = TextAreaField('Description', validators=[DataRequired()])
    submit = SubmitField('Schedule Audit')

class InductionForm(FlaskForm):
    employee_id = SelectField('Employee', coerce=int, validators=[DataRequired()])
    induction_type = StringField('Induction Type', validators=[DataRequired(), Length(max=100)])
    completion_date = DateField('Completion Date', validators=[DataRequired()])
    submit = SubmitField('Add Induction')

class PermitForm(FlaskForm):
    site_id = SelectField('Site', coerce=int, validators=[DataRequired()])
    permit_type = StringField('Permit Type', validators=[DataRequired(), Length(max=100)])
    issue_date = DateField('Issue Date', validators=[DataRequired()])
    expiry_date = DateField('Expiry Date', validators=[DataRequired()])
    submit = SubmitField('Add Permit')

class AddCompanyForm(FlaskForm):
    company_name = StringField('Company Name', validators=[DataRequired(), Length(max=100)])
    admin_username = StringField('Admin Username', validators=[DataRequired(), Length(max=50)])
    admin_password = PasswordField('Admin Password', validators=[DataRequired(), Length(min=8), PasswordValidator()])
    submit = SubmitField('Add Company')

class SettingsForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=50)])
    password = PasswordField('New Password', validators=[Length(min=8), PasswordValidator()])
    email = StringField('Email', validators=[Email(), Length(max=100)])
    submit = SubmitField('Update Settings')

class ProjectForm(FlaskForm):
    name = StringField('Project Name', validators=[DataRequired(), Length(max=100)])
    description = TextAreaField('Description')
    start_date = DateField('Start Date', validators=[DataRequired()])
    end_date = DateField('End Date', validators=[DataRequired()])
    status = SelectField('Status', choices=[('Not Started', 'Not Started'), ('In Progress', 'In Progress'), ('Completed', 'Completed')], validators=[DataRequired()])
    submit = SubmitField('Create Project')

class MilestoneForm(FlaskForm):
    name = StringField('Milestone Name', validators=[DataRequired(), Length(max=100)])
    due_date = DateField('Due Date', validators=[DataRequired()])
    status = SelectField('Status', choices=[('Not Started', 'Not Started'), ('In Progress', 'In Progress'), ('Completed', 'Completed')], validators=[DataRequired()])
    submit = SubmitField('Add Milestone')

class ProjectAssignmentForm(FlaskForm):
    employee_id = SelectField('Employee', coerce=int, validators=[DataRequired()])
    role = StringField('Role', validators=[DataRequired(), Length(max=50)])
    submit = SubmitField('Assign Employee')

class DocumentForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired(), Length(max=100)])
    file = FileField('File', validators=[DataRequired()])
    submit = SubmitField('Upload Document')

class ChatForm(FlaskForm):
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send')

class RoleForm(FlaskForm):
    name = StringField('Role Name', validators=[DataRequired(), Length(max=50)])
    permissions = SelectField('Permissions', choices=[], multiple=True, coerce=int, validators=[DataRequired()])
    submit = SubmitField('Create Role')

# RBAC Decorator
def permission_required(permission):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or not current_user.role:
                flash('No role assigned.', 'danger')
                return redirect(url_for('dashboard'))
            if permission not in [p.name for p in current_user.role.permissions]:
                flash('Unauthorized access.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Database initialization function
def init_db():
    with app.app_context():
        db.drop_all()  # Drop all existing tables to avoid conflicts
        db.create_all()  # Create all tables based on current models
        if not Company.query.first():
            default_company = Company(name='Default Company')
            db.session.add(default_company)
            db.session.commit()
            default_role = Role(name='Admin')
            db.session.add(default_role)
            db.session.commit()
            permissions = [
                Permission(name='view_orders'),
                Permission(name='create_orders'),
                Permission(name='edit_orders'),
                Permission(name='view_incidents'),
                Permission(name='create_incidents'),
                Permission(name='manage_users'),
                Permission(name='manage_projects'),
                Permission(name='view_documents'),
                Permission(name='upload_documents'),
            ]
            db.session.add_all(permissions)
            db.session.commit()
            for perm in permissions:
                db.session.add(RolePermission(role_id=default_role.role_id, permission_id=perm.permission_id))
            db.session.commit()
            hashed_password = generate_password_hash('admin123')
            admin_user = User(
                company_id=default_company.company_id,
                username='admin',
                password=hashed_password,
                role_id=default_role.role_id
            )
            db.session.add(admin_user)
            db.session.commit()
        # Create indexes
        with db.engine.connect() as conn:
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_company_id ON orders(company_id)'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_employee_id ON licenses(employee_id)'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_company_id ON tasks(company_id)'))
            conn.execute(text('CREATE INDEX IF NOT EXISTS idx_company_id ON projects(company_id)'))
            conn.commit()

# Utility Functions
@cache.memoize(timeout=60)
def get_notifications_count(company_id):
    today = date.today()
    with db.session() as session:
        counts = session.execute(
            text("""
                SELECT 
                    (SELECT COUNT(*) FROM licenses WHERE company_id = :company_id AND expiry_date <= :future AND expiry_date >= :today) AS expiring_licenses,
                    (SELECT COUNT(*) FROM licenses WHERE company_id = :company_id AND expiry_date < :today) AS expired_licenses,
                    (SELECT COUNT(*) FROM incidents WHERE company_id = :company_id AND status = 'Open') AS open_incidents,
                    (SELECT COUNT(*) FROM equipment WHERE company_id = :company_id AND next_maintenance_date <= :future30) AS equipment_due,
                    (SELECT COUNT(*) FROM inventory WHERE company_id = :company_id AND quantity <= reorder_point) AS low_inventory,
                    (SELECT COUNT(*) FROM payments WHERE company_id = :company_id AND status = 'Pending' AND due_date < :today) AS overdue_payments,
                    (SELECT COUNT(*) FROM safety_audits WHERE company_id = :company_id AND status = 'Scheduled' AND audit_date <= :future30 AND audit_date >= :today) AS upcoming_audits
            """),
            {'company_id': company_id, 'today': today, 'future': today + timedelta(days=60), 'future30': today + timedelta(days=30)}
        ).first()
        return sum(counts) if counts else 0

def send_email_notification(to_email, subject, body):
    smtp_server = os.environ.get('SMTP_SERVER')
    smtp_port = os.environ.get('SMTP_PORT', 587)
    smtp_user = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    if not all([smtp_server, smtp_user, smtp_password]):
        logger.error("SMTP configuration missing")
        return
    msg = MIMEText(body)
    msg['Subject'] = subject
    msg['From'] = smtp_user
    msg['To'] = to_email
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(msg['From'], [msg['To']], msg.as_string())
    except Exception as e:
        logger.error(f"Email error: {e}")

def allowed_file(filename, file):
    ext = os.path.splitext(filename.lower())[1]
    if ext not in app.config['ALLOWED_EXTENSIONS']:
        return False
    content_type = getattr(file, 'content_type', None)
    return content_type in app.config['ALLOWED_MIME_TYPES']

def log_action(action, details=None):
    if current_user.is_authenticated:
        log = AuditLog(
            company_id=current_user.company_id,
            user_id=current_user.id,
            action=action,
            details=json.dumps(details) if details else None
        )
        db.session.add(log)
        db.session.commit()

# Error Handler
@app.errorhandler(Exception)
def handle_error(e):
    logger.error(f"Internal Server Error: {str(e)}", exc_info=True)
    notifications_count = get_notifications_count(current_user.company_id) if current_user.is_authenticated else 0
    return render_template('error.html', error=str(e), notifications_count=notifications_count), 500

# Routes
@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            log_action('login', {'user_id': user.id})
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')
    current_time = datetime.now(IST)
    return render_template('login.html', form=form, current_time=current_time)

@app.route('/company_login', methods=['GET', 'POST'])
@permission_required('create_orders')
def company_login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    form = CompanyLoginForm()
    if form.validate_on_submit():
        company = Company.query.filter_by(name=form.company_name.data).first()
        if not company:
            flash('Company not found.', 'danger')
            return render_template('company_login.html', form=form, notifications_count=0)
        user = User.query.filter_by(username=form.username.data, company_id=company.company_id).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            log_action('company_login', {'username': user.username, 'company': company.name})
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('company_login.html', form=form, notifications_count=0)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('login'))
    form = RegisterForm()
    if form.validate_on_submit():
        company = Company.query.filter_by(name=form.company_name.data).first()
        if not company:
            company = Company(name=form.company_name.data)
            db.session.add(company)
            db.session.commit()
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists.', 'danger')
            return render_template('register.html', form=form, notifications_count=0)
        role = Role.query.filter_by(name=form.role.data.capitalize()).first()
        if not role:
            role = Role(name=form.role.data.capitalize())
            db.session.add(role)
            db.session.commit()
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            company_id=company.company_id,
            username=form.username.data,
            password=hashed_password,
            role_id=role.role_id
        )
        db.session.add(user)
        db.session.commit()
        log_action('register', {'username': user.username, 'company': company.name})
        flash('Registration successful! Please log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, notifications_count=0)

@app.route('/logout')
@login_required
def logout():
    username = current_user.username
    logout_user()
    log_action('logout', {'username': username})
    flash('Logged out successfully!', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        with db.session() as db_session:
            # Comprehensive mock data
            status_counts = [15, 10, 12, 8]  # Pending, Received, In Production, Shipped
            incident_types = [5, 7, 3]  # High, Medium, Low
            task_progress = [66, 34]  # Completed, Remaining
            recent_orders = [
                {'order_id': '001', 'item': 'Concrete Mix', 'status': 'Shipped'},
                {'order_id': '002', 'item': 'Steel Beams', 'status': 'In Production'},
                {'order_id': '003', 'item': 'Tools Kit', 'status': 'Pending'}
            ]
            projects = [
                {'name': 'Office Building', 'status': 'In Progress', 'end_date': '2025-12-01'},
                {'name': 'Warehouse', 'status': 'Not Started', 'end_date': '2026-03-15'},
                {'name': 'Bridge', 'status': 'Planned', 'end_date': '2026-06-30'}
            ]
            weather_data = {'Site A': {'temp': 28, 'condition': 'Sunny'}, 'Site B': {'temp': 22, 'condition': 'Cloudy'}}
            compliance_alerts = [
                {'type': 'License', 'name': 'John Doe', 'expiry_date': '2025-06-15', 'days_remaining': 5},
                {'type': 'Permit', 'name': 'Site A', 'expiry_date': '2025-06-20', 'days_remaining': 10}
            ]

            return render_template('dashboard.html', status_counts=status_counts, incident_types=incident_types,
                                  task_progress=task_progress, recent_orders=recent_orders, projects=projects,
                                  weather_data=weather_data, compliance_alerts=compliance_alerts)
    except Exception as e:
        logger.error(f"Error in dashboard view: {e}", exc_info=True)
        return handle_error(e)

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html', user=current_user)

@app.route('/analytics')
@login_required
def analytics():
    order_trends = db.session.query(
        db.func.strftime('%Y-%m-%d', Order.timestamp).label('order_date'),
        db.func.count()
    ).filter_by(company_id=current_user.company_id).group_by('order_date').order_by('order_date').limit(5).all()
    order_trends_labels = [row[0] for row in order_trends]
    order_trends_data = [row[1] for row in order_trends]

    incident_summary = db.session.query(
        Incident.type,
        db.func.count()
    ).filter_by(company_id=current_user.company_id).group_by(Incident.type).all()
    incident_summary_labels = [row[0] for row in incident_summary]
    incident_summary_data = [row[1] for row in incident_summary]

    return render_template('analytics.html', order_trends={'labels': order_trends_labels, 'data': order_trends_data},
                           incident_summary={'labels': incident_summary_labels, 'data': incident_summary_data})

@app.route('/order_form', methods=['GET', 'POST'])
@login_required
@permission_required('create_orders')
def order_form():
    form = OrderForm()
    form.site_id.choices = [(s.site_id, s.name) for s in Site.query.filter_by(company_id=current_user.company_id).all()]
    if form.validate_on_submit():
        order = Order(
            company_id=current_user.company_id,
            item=form.item.data,
            quantity=form.quantity.data,
            site_id=form.site_id.data,
            status='Pending',
            comments=form.comments.data
        )
        db.session.add(order)
        db.session.commit()
        socketio.emit('new_order', {'order_id': order.order_id, 'item': order.item, 'site_id': order.site_id})
        log_action('create_order', {'order_id': order.order_id})
        flash('Order submitted successfully!', 'success')
        return redirect(url_for('order_form'))
    return render_template('order_form.html', form=form)

@app.route('/orders')
@login_required
@permission_required('view_orders')
def orders():
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Order.query.filter_by(company_id=current_user.company_id).count()
    orders = Order.query.filter_by(company_id=current_user.company_id).order_by(Order.timestamp.desc()).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('orders.html', orders=orders, pagination=pagination)

@app.route('/track_orders')
@login_required
@permission_required('view_orders')
def track_orders():
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Order.query.filter_by(company_id=current_user.company_id).count()
    orders = Order.query.filter_by(company_id=current_user.company_id).order_by(Order.timestamp.desc()).offset(offset).limit(per_page).all()
    subcontractors = Subcontractor.query.filter_by(company_id=current_user.company_id).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('track_orders.html', orders=orders, subcontractors=subcontractors, pagination=pagination)

@app.route('/track_order/<int:order_id>')
@login_required
@permission_required('view_orders')
def track_order(order_id):
    order = Order.query.filter_by(order_id=order_id, company_id=current_user.company_id).first()
    if not order:
        flash('Order not found.', 'danger')
        return redirect(url_for('track_orders'))
    vehicle = Vehicle.query.filter_by(vehicle_id=order.vehicle_id, company_id=current_user.company_id).first()
    return render_template('track_order.html', order=order, latitude=vehicle.latitude if vehicle else None,
                           longitude=vehicle.longitude if vehicle else None)

@app.route('/rate_order/<int:order_id>', methods=['GET', 'POST'])
@login_required
@permission_required('edit_orders')
def rate_order(order_id):
    order = Order.query.filter_by(order_id=order_id, company_id=current_user.company_id).first()
    if not order:
        flash('Order not found.', 'danger')
        return redirect(url_for('orders'))
    if request.method == 'POST':
        rating = request.form.get('rating', type=int)
        if not 1 <= rating <= 5:
            flash('Rating must be between 1 and 5.', 'danger')
            return redirect(url_for('rate_order', order_id=order_id))
        order.rating = rating
        db.session.commit()
        log_action('rate_order', {'order_id': order_id, 'rating': rating})
        flash('Order rated successfully!', 'success')
        return redirect(url_for('orders'))
    return render_template('rate_order.html', order=order)

@app.route('/edit_order/<int:order_id>', methods=['GET', 'POST'])
@login_required
@permission_required('edit_orders')
def edit_order(order_id):
    order = Order.query.filter_by(order_id=order_id, company_id=current_user.company_id).first()
    if not order:
        flash('Order not found.', 'danger')
        return redirect(url_for('orders'))
    form = OrderForm(obj=order)
    form.site_id.choices = [(s.site_id, s.name) for s in Site.query.filter_by(company_id=current_user.company_id).all()]
    if form.validate_on_submit():
        order.item = form.item.data
        order.quantity = form.quantity.data
        order.site_id = form.site_id.data
        order.comments = form.comments.data
        db.session.commit()
        log_action('edit_order', {'order_id': order_id})
        flash('Order updated successfully!', 'success')
        return redirect(url_for('orders'))
    return render_template('edit_order.html', form=form, order=order)

@app.route('/cancel_order/<int:order_id>')
@login_required
@permission_required('edit_orders')
def cancel_order(order_id):
    order = Order.query.filter_by(order_id=order_id, company_id=current_user.company_id).first()
    if not order:
        flash('Order not found.', 'danger')
        return redirect(url_for('orders'))
    if order.status != 'Pending':
        flash('Only pending orders can be canceled.', 'danger')
        return redirect(url_for('orders'))
    order.status = 'Canceled'
    db.session.commit()
    socketio.emit('order_canceled', {'order_id': order_id})
    log_action('cancel_order', {'order_id': order_id})
    flash('Order canceled successfully!', 'success')
    return redirect(url_for('orders'))

@app.route('/incidents', methods=['GET', 'POST'])
@login_required
@permission_required('create_incidents')
def incidents():
    form = IncidentForm()
    if form.validate_on_submit():
        incident = Incident(
            company_id=current_user.company_id,
            type=form.type.data,
            description=form.description.data,
            location=form.location.data,
            severity=form.severity.data,
            status='Open',
            date=date.today(),
            reported_by=current_user.username
        )
        db.session.add(incident)
        db.session.commit()
        socketio.emit('new_incident', {'incident_id': incident.incident_id, 'type': incident.type})
        log_action('create_incident', {'incident_id': incident.incident_id})
        flash('Incident reported successfully!', 'success')
        return redirect(url_for('incidents'))
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Incident.query.filter_by(company_id=current_user.company_id).count()
    incidents = Incident.query.filter_by(company_id=current_user.company_id).order_by(Incident.date.desc()).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('incidents.html', form=form, incidents=incidents, pagination=pagination)

@app.route('/subcontractor_portal')
@login_required
def subcontractor_portal():
    subcontractors = Subcontractor.query.filter_by(company_id=current_user.company_id).all()
    return render_template('subcontractor_portal.html', subcontractors=subcontractors)

@app.route('/subcontractor_payments/<int:subcontractor_id>', methods=['GET', 'POST'])
@login_required
def subcontractor_payments(subcontractor_id):
    subcontractor = Subcontractor.query.filter_by(subcontractor_id=subcontractor_id, company_id=current_user.company_id).first()
    if not subcontractor:
        flash('Subcontractor not found.', 'danger')
        return redirect(url_for('subcontractor_portal'))
    form = PaymentForm()
    if form.validate_on_submit():
        payment = Payment(
            subcontractor_id=subcontractor_id,
            company_id=current_user.company_id,
            milestone=form.milestone.data,
            amount=form.amount.data,
            due_date=form.due_date.data,
            status='Pending'
        )
        db.session.add(payment)
        db.session.commit()
        log_action('add_payment', {'payment_id': payment.payment_id})
        flash('Payment milestone added successfully!', 'success')
        return redirect(url_for('subcontractor_payments', subcontractor_id=subcontractor_id))
    if request.method == 'POST' and 'payment_id' in request.form:
        payment_id = request.form.get('payment_id', type=int)
        payment = Payment.query.filter_by(payment_id=payment_id, company_id=current_user.company_id).first()
        if payment:
            payment.status = 'Paid'
            db.session.commit()
            log_action('mark_payment_paid', {'payment_id': payment_id})
            flash('Payment marked as paid!', 'success')
    payments = Payment.query.filter_by(subcontractor_id=subcontractor_id, company_id=current_user.company_id).order_by(Payment.due_date).all()
    return render_template('subcontractor_payments.html', subcontractor=subcontractor, form=form, payments=payments)

@app.route('/insights')
@login_required
def insights():
    status_counts = db.session.query(
        db.func.sum(db.case([(Order.status == 'Pending', 1)], else_=0)),
        db.func.sum(db.case([(Order.status == 'Received', 1)], else_=0)),
        db.func.sum(db.case([(Order.status == 'In Production', 1)], else_=0)),
        db.func.sum(db.case([(Order.status == 'Shipped', 1)], else_=0))
    ).filter_by(company_id=current_user.company_id).first()
    status_counts = [count or 0 for count in status_counts]

    incident_counts = db.session.query(
        db.func.sum(db.case([(Incident.type == 'Incident', 1)], else_=0)),
        db.func.sum(db.case([(Incident.type == 'Near-Miss', 1)], else_=0)),
        db.func.sum(db.case([(Incident.type == 'Hazard', 1)], else_=0))
    ).filter_by(company_id=current_user.company_id).first()
    incident_counts = [count or 0 for count in incident_counts]

    vehicles_on_road = Vehicle.query.filter_by(company_id=current_user.company_id, status='On Road').count()
    vehicles_in_yard = Vehicle.query.filter_by(company_id=current_user.company_id, status='In Yard').count()

    orders_over_time = db.session.query(
        db.func.strftime('%Y-%m-%d', Order.timestamp).label('order_date'),
        db.func.count()
    ).filter_by(company_id=current_user.company_id).group_by('order_date').order_by('order_date').limit(30).all()
    order_dates = [row[0] for row in orders_over_time]
    order_counts = [row[1] for row in orders_over_time]

    severity_counts = db.session.query(
        db.func.sum(db.case([(Incident.severity == 'Low', 1)], else_=0)),
        db.func.sum(db.case([(Incident.severity == 'Medium', 1)], else_=0)),
        db.func.sum(db.case([(Incident.severity == 'High', 1)], else_=0))
    ).filter_by(company_id=current_user.company_id).first()
    severity_counts = [count or 0 for count in severity_counts]

    subcontractor_status_counts = db.session.query(
        db.func.sum(db.case([(Subcontractor.agreement_status == 'Pending', 1)], else_=0)),
        db.func.sum(db.case([(Subcontractor.agreement_status == 'Approved', 1)], else_=0)),
        db.func.sum(db.case([(Subcontractor.agreement_status == 'Rejected', 1)], else_=0))
    ).filter_by(company_id=current_user.company_id).first()
    subcontractor_status_counts = [count or 0 for count in subcontractor_status_counts]

    manpower_trend = DailyReport.query.filter_by(company_id=current_user.company_id).order_by(DailyReport.date).limit(30).all()
    manpower_dates = [report.date.strftime('%Y-%m-%d') for report in manpower_trend]
    manpower_values = [report.manpower for report in manpower_trend]

    total_employees = Employee.query.filter_by(company_id=current_user.company_id).count()
    induction_compliance_rate = (
        (Induction.query.filter_by(company_id=current_user.company_id).distinct(Induction.employee_id).count() / total_employees * 100)
        if total_employees > 0 else 0
    )
    license_compliance_rate = (
        (License.query.filter_by(company_id=current_user.company_id).filter(License.expiry_date >= date.today())
         .distinct(License.employee_id).count() / total_employees * 100)
        if total_employees > 0 else 0
    )

    return render_template('insights.html', status_counts=json.dumps(status_counts), incident_counts=json.dumps(incident_counts),
                           vehicles_on_road=vehicles_on_road, vehicles_in_yard=vehicles_in_yard,
                           order_dates=json.dumps(order_dates), order_counts=json.dumps(order_counts),
                           severity_counts=json.dumps(severity_counts), subcontractor_status_counts=json.dumps(subcontractor_status_counts),
                           manpower_dates=json.dumps(manpower_dates), manpower_values=json.dumps(manpower_values),
                           induction_compliance_rate=induction_compliance_rate, license_compliance_rate=license_compliance_rate)

@app.route('/notifications')
@login_required
def notifications():
    today = date.today()
    expiring_licenses = db.session.query(License, Employee.name).join(Employee).filter(
        License.company_id == current_user.company_id,
        License.expiry_date <= (today + timedelta(days=60)),
        License.expiry_date >= today
    ).order_by(License.expiry_date).all()
    expiring_licenses_data = [
        {
            'license_id': lic[0].license_id,
            'employee_name': lic[1],
            'license_type': lic[0].license_type,
            'expiry_date': lic[0].expiry_date,
            'days_until_expiry': (lic[0].expiry_date - today).days
        } for lic in expiring_licenses
    ]

    expired_licenses = db.session.query(License, Employee.name).join(Employee).filter(
        License.company_id == current_user.company_id,
        License.expiry_date < today
    ).order_by(License.expiry_date).all()
    expired_licenses_data = [
        {
            'license_id': lic[0].license_id,
            'employee_name': lic[1],
            'license_type': lic[0].license_type,
            'expiry_date': lic[0].expiry_date
        } for lic in expired_licenses
    ]

    open_incidents = Incident.query.filter_by(company_id=current_user.company_id, status='Open').order_by(Incident.date.desc()).all()
    equipment_maintenance_due = Equipment.query.filter_by(company_id=current_user.company_id).filter(
        Equipment.next_maintenance_date <= (today + timedelta(days=30))
    ).order_by(Equipment.next_maintenance_date).all()
    low_inventory = Inventory.query.filter_by(company_id=current_user.company_id).filter(
        Inventory.quantity <= Inventory.reorder_point
    ).order_by(Inventory.quantity).all()
    overdue_payments = db.session.query(Payment, Subcontractor.name).join(Subcontractor).filter(
        Payment.company_id == current_user.company_id,
        Payment.due_date < today,
        Payment.status == 'Pending'
    ).order_by(Payment.due_date).all()
    overdue_payments_data = [
        {
            'payment_id': pay[0].payment_id,
            'milestone': pay[0].milestone,
            'amount': pay[0].amount,
            'due_date': pay[0].due_date,
            'company_name': pay[1]
        } for pay in overdue_payments
    ]
    upcoming_audits = SafetyAudit.query.filter_by(company_id=current_user.company_id, status='Scheduled').filter(
        SafetyAudit.audit_date <= (today + timedelta(days=30)),
        SafetyAudit.audit_date >= today
    ).order_by(SafetyAudit.audit_date).all()

    return render_template('notifications.html', expiring_licenses=expiring_licenses_data, expired_licenses=expired_licenses_data,
                           open_incidents=open_incidents, equipment_maintenance_due=equipment_maintenance_due,
                           low_inventory=low_inventory, overdue_payments=overdue_payments_data,
                           upcoming_audits=upcoming_audits)

@app.route('/equipment', methods=['GET', 'POST'])
@login_required
def equipment():
    form = EquipmentForm()
    if form.validate_on_submit():
        equipment = Equipment(
            company_id=current_user.company_id,
            name=form.name.data,
            type=form.type.data,
            last_maintenance_date=form.last_maintenance_date.data,
            next_maintenance_date=form.next_maintenance_date.data,
            status=form.status.data,
            maintenance_notes=form.maintenance_notes.data
        )
        db.session.add(equipment)
        db.session.commit()
        flash('Equipment added successfully!', 'success')
        return redirect(url_for('equipment'))
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Equipment.query.filter_by(company_id=current_user.company_id).count()
    equipment = Equipment.query.filter_by(company_id=current_user.company_id).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    current_time = datetime.now(IST)
    return render_template('equipment.html', form=form, equipment=equipment, pagination=pagination, current_time=current_time)

@app.route('/edit_equipment/<int:equipment_id>', methods=['GET', 'POST'])
@login_required
def edit_equipment(equipment_id):
    equipment = Equipment.query.filter_by(equipment_id=equipment_id, company_id=current_user.company_id).first()
    if not equipment:
        flash('Equipment not found.', 'danger')
        return redirect(url_for('equipment'))
    form = EquipmentForm(obj=equipment)
    if form.validate_on_submit():
        equipment.name = form.name.data
        equipment.type = form.type.data
        equipment.status = form.status.data
        equipment.last_maintenance_date = form.last_maintenance_date.data
        equipment.next_maintenance_date = form.next_maintenance_date.data
        equipment.maintenance_notes = form.maintenance_notes.data
        db.session.commit()
        log_action('edit_equipment', {'equipment_id': equipment_id})
        flash('Equipment updated successfully!', 'success')
        return redirect(url_for('equipment'))
    return render_template('edit_equipment.html', form=form, equipment=equipment)

@app.route('/delete_equipment/<int:equipment_id>')
@login_required
def delete_equipment(equipment_id):
    equipment = Equipment.query.filter_by(equipment_id=equipment_id, company_id=current_user.company_id).first()
    if not equipment:
        flash('Equipment not found.', 'danger')
        return redirect(url_for('equipment'))
    db.session.delete(equipment)
    db.session.commit()
    log_action('delete_equipment', {'equipment_id': equipment_id})
    flash('Equipment deleted successfully!', 'success')
    return redirect(url_for('equipment'))

@app.route('/weather_forecast')
@login_required
def weather_forecast():
    api_key = os.environ.get('OPENWEATHER_API_KEY')
    if api_key:
        sites = Site.query.filter_by(company_id=current_user.company_id).all()
        for site in sites:
            url = f'http://api.openweathermap.org/data/2.5/forecast?lat={site.latitude}&lon={site.longitude}&appid={api_key}&units=metric'
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    for forecast in data['list'][:5]:
                        weather = Weather(
                            company_id=current_user.company_id,
                            site_id=site.site_id,
                            date=datetime.fromtimestamp(forecast['dt']).date(),
                            temperature=forecast['main']['temp'],
                            condition=forecast['weather'][0]['description'],
                            precipitation=int(forecast['pop'] * 100),
                            wind_speed=forecast['wind']['speed'],
                            warning=forecast.get('alerts', [{}])[0].get('description')
                        )
                        db.session.merge(weather)
                    db.session.commit()
            except requests.RequestException as e:
                flash(f'Weather API error for site {site.name}: {e}', 'warning')

    weather_data = {}
    weather_records = Weather.query.filter_by(company_id=current_user.company_id).order_by(Weather.site_id, Weather.date).all()
    for record in weather_records:
        if record.site.name not in weather_data:
            weather_data[record.site.name] = []
        weather_data[record.site.name].append({
            'date': record.date,
            'temp': record.temperature,
            'condition': record.condition,
            'precipitation': record.precipitation,
            'wind_speed': record.wind_speed,
            'warning': record.warning
        })
    return render_template('weather_forecast.html', weather_data=weather_data)

@app.route('/blueprints', methods=['GET', 'POST'])
@login_required
@permission_required('upload_documents')
def blueprints():
    form = BlueprintForm()
    if form.validate_on_submit():
        file = form.file.data
        if not file or not allowed_file(file.filename, file):
            flash('Invalid file type. Allowed: PDF, PNG, JPG.', 'danger')
            return redirect(url_for('blueprints'))
        filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(file_path)
        blueprint = Blueprint(
            company_id=current_user.company_id,
            title=form.title.data,
            file_url=f"uploads/{filename}",
            uploaded_by=current_user.username
        )
        db.session.add(blueprint)
        db.session.commit()
        log_action('upload_blueprint', {'blueprint_id': blueprint.blueprint_id})
        flash('Blueprint uploaded successfully!', 'success')
        return redirect(url_for('blueprints'))
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Blueprint.query.filter_by(company_id=current_user.company_id).count()
    blueprints = Blueprint.query.filter_by(company_id=current_user.company_id).order_by(Blueprint.uploaded_at.desc()).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('blueprints.html', form=form, blueprints=blueprints, pagination=pagination)

@app.route('/view_blueprint/<int:blueprint_id>', methods=['GET', 'POST'])
@login_required
@permission_required('view_documents')
def view_blueprint(blueprint_id):
    blueprint = Blueprint.query.filter_by(blueprint_id=blueprint_id, company_id=current_user.company_id).first()
    if not blueprint:
        flash('Blueprint not found.', 'danger')
        return redirect(url_for('blueprints'))
    if request.method == 'POST':
        comment_text = request.form.get('comment_text')
        if not comment_text:
            flash('Comment text is required.', 'danger')
            return redirect(url_for('view_blueprint', blueprint_id=blueprint_id))
        comment = BlueprintComment(
            blueprint_id=blueprint_id,
            company_id=current_user.company_id,
            comment_text=comment_text,
            commenter=current_user.username
        )
        db.session.add(comment)
        db.session.commit()
        socketio.emit('new_comment', {'blueprint_id': blueprint_id, 'comment': comment_text})
        log_action('add_blueprint_comment', {'blueprint_id': blueprint_id})
        flash('Comment added successfully!', 'success')
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = BlueprintComment.query.filter_by(blueprint_id=blueprint_id, company_id=current_user.company_id).count()
    comments = BlueprintComment.query.filter_by(blueprint_id=blueprint_id, company_id=current_user.company_id).order_by(BlueprintComment.commented_at.desc()).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('view_blueprint.html', blueprint=blueprint, comments=comments, pagination=pagination)

@app.route('/reports', methods=['GET', 'POST'])
@login_required
def reports():
    if request.method == 'POST':
        report_type = request.form.get('report_type')
        start_date = request.form.get('start_date')
        end_date = request.form.get('end_date')
        if not start_date or not end_date:
            flash('Start and end dates are required.', 'danger')
            return redirect(url_for('reports'))
        try:
            start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            if start_date > end_date:
                flash('Start date must be before end date.', 'danger')
                return redirect(url_for('reports'))
        except ValueError:
            flash('Invalid date format.', 'danger')
            return redirect(url_for('reports'))

        if report_type == 'orders':
            orders = Order.query.filter_by(company_id=current_user.company_id).filter(
                Order.timestamp.between(start_date, end_date)
            ).order_by(Order.timestamp).all()
            buffer = BytesIO()
            pdf = canvas.Canvas(buffer, pagesize=letter)
            pdf.setTitle('Order Report')
            pdf.drawString(100, 750, f'Order Report: {start_date} to {end_date}')
            y = 700
            for order in orders:
                text = (f"Order ID: {order.order_id}, Item: {order.item}, Quantity: {order.quantity}, "
                        f"Site: {order.site.name}, Status: {order.status}, Timestamp: {order.timestamp}")
                pdf.drawString(100, y, text)
                y -= 20
                if y < 50:
                    pdf.showPage()
                    y = 750
            pdf.save()
            buffer.seek(0)
            log_action('generate_report', {'type': 'orders', 'start_date': start_date, 'end_date': end_date})
            return send_file(buffer, as_attachment=True, download_name=f'order_report_{datetime.now().strftime("%Y%m%d%H%M%S")}.pdf', mimetype='application/pdf')
        elif report_type == 'incidents':
            incidents = Incident.query.filter_by(company_id=current_user.company_id).filter(
                Incident.date.between(start_date, end_date)
            ).order_by(Incident.date).all()
            buffer = BytesIO()
            pdf = canvas.Canvas(buffer, pagesize=letter)
            pdf.setTitle('Incident Report')
            pdf.drawString(100, 750, f'Incident Report: {start_date} to {end_date}')
            y = 700
            for incident in incidents:
                text = (f"Incident ID: {incident.incident_id}, Type: {incident.type}, Severity: {incident.severity}, "
                        f"Date: {incident.date}, Reported By: {incident.reported_by}")
                pdf.drawString(100, y, text)
                y -= 20
                if y < 50:
                    pdf.showPage()
                    y = 750
            pdf.save()
            buffer.seek(0)
            log_action('generate_report', {'type': 'incidents', 'start_date': start_date, 'end_date': end_date})
            return send_file(buffer, as_attachment=True, download_name=f'incident_report_{datetime.now().strftime("%Y%m%d%H%M%S")}.pdf', mimetype='application/pdf')
    return render_template('reports.html')

@app.route('/mobile')
@login_required
def mobile():
    weather_data = {}
    weather_records = Weather.query.filter_by(company_id=current_user.company_id).order_by(Weather.site_id, Weather.date).all()
    for record in weather_records:
        if record.site.name not in weather_data:
            weather_data[record.site.name] = []
        weather_data[record.site.name].append({
            'date': record.date,
            'temp': record.temperature,
            'condition': record.condition,
            'precipitation': record.precipitation,
            'wind_speed': record.wind_speed,
            'warning': record.warning
        })
    return render_template('mobile.html', weather_data=weather_data)

@app.route('/mobile/report_incident', methods=['GET', 'POST'])
@login_required
@permission_required('create_incidents')
def mobile_report_incident():
    form = IncidentForm()
    if form.validate_on_submit():
        incident = Incident(
            company_id=current_user.company_id,
            type=form.type.data,
            description=form.description.data,
            location=form.location.data,
            severity=form.severity.data,
            status='Open',
            date=date.today(),
            reported_by=current_user.username
        )
        db.session.add(incident)
        db.session.commit()
        socketio.emit('new_incident', {'incident_id': incident.incident_id, 'type': incident.type})
        log_action('create_incident', {'incident_id': incident.incident_id})
        flash('Incident reported successfully!', 'success')
        return redirect(url_for('mobile'))
    return render_template('mobile_report_incident.html', form=form)

@app.route('/mobile/complete_induction', methods=['GET', 'POST'])
@login_required
def mobile_complete_induction():
    form = InductionForm()
    employee = Employee.query.filter_by(email=f"{current_user.username}@example.com", company_id=current_user.company_id).first()
    if not employee:
        flash('Employee not found.', 'danger')
        return redirect(url_for('mobile'))
    form.employee_id.choices = [(employee.employee_id, employee.name)]
    if form.validate_on_submit():
        induction = Induction(
            employee_id=employee.employee_id,
            company_id=current_user.company_id,
            induction_type=form.induction_type.data,
            completion_date=form.completion_date.data
        )
        db.session.add(induction)
        db.session.commit()
        log_action('complete_induction', {'induction_id': induction.induction_id})
        flash('Induction completed successfully!', 'success')
        return redirect(url_for('mobile'))
    return render_template('mobile_complete_induction.html', form=form)

@app.route('/tasks', methods=['GET', 'POST'])
@login_required
def tasks():
    form = TaskForm()
    employees = Employee.query.filter_by(company_id=current_user.company_id).all()
    projects = Project.query.filter_by(company_id=current_user.company_id).all()
    form.assigned_to.choices = [(e.employee_id, e.name) for e in employees]
    form.project_id.choices = [(p.project_id, p.name) for p in projects]
    if form.validate_on_submit():
        task = Task(
            company_id=current_user.company_id,
            title=form.title.data,
            description=form.description.data,
            status='Not Started',
            due_date=form.due_date.data,
            assigned_to=form.assigned_to.data,
            project_id=form.project_id.data
        )
        db.session.add(task)
        db.session.commit()
        socketio.emit('new_task', {'task_id': task.task_id, 'title': task.title})
        log_action('create_task', {'task_id': task.task_id})
        flash('Task added successfully!', 'success')
        return redirect(url_for('tasks'))
    if request.method == 'POST' and 'task_id' in request.form:
        task_id = request.form.get('task_id', type=int)
        status = request.form.get('status')
        task = Task.query.filter_by(task_id=task_id, company_id=current_user.company_id).first()
        if task:
            task.status = status
            db.session.commit()
            socketio.emit('task_updated', {'task_id': task_id, 'status': status})
            log_action('update_task', {'task_id': task_id, 'status': status})
            flash('Task status updated successfully!', 'success')
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Task.query.filter_by(company_id=current_user.company_id).count()
    tasks = db.session.query(Task, Employee.name).join(Employee).filter(
        Task.company_id == current_user.company_id
    ).order_by(Task.due_date).offset(offset).limit(per_page).all()
    task_data = [
        {
            'task_id': task[0].task_id,
            'title': task[0].title,
            'description': task[0].description,
            'status': task[0].status,
            'due_date': task[0].due_date,
            'assigned_to': task[1],
            'created_at': task[0].created_at,
            'project_id': task[0].project_id
        } for task in tasks
    ]
    gantt_labels = [task['title'] for task in task_data]
    gantt_start_dates = [task['created_at'].strftime('%Y-%m-%d') for task in task_data]
    gantt_due_dates = [task['due_date'].strftime('%Y-%m-%d') for task in task_data]
    gantt_colors = ['#28a745' if task['status'] == 'Completed' else '#ffc107' if task['status'] == 'In Progress' else '#dc3545' for task in task_data]
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('tasks.html', form=form, tasks=task_data, employees=employees,
                           gantt_labels=json.dumps(gantt_labels), gantt_start_dates=json.dumps(gantt_start_dates),
                           gantt_due_dates=json.dumps(gantt_due_dates), gantt_colors=json.dumps(gantt_colors),
                           pagination=pagination)

@app.route('/timesheets', methods=['GET', 'POST'])
@login_required
def timesheets():
    form = TimesheetForm()
    employee = Employee.query.filter_by(email=f"{current_user.username}@example.com", company_id=current_user.company_id).first()
    is_clocked_in = False
    if employee:
        is_clocked_in = Timesheet.query.filter_by(employee_id=employee.employee_id, company_id=current_user.company_id, clock_out=None).first() is not None
    if form.validate_on_submit():
        if not employee:
            flash('Employee not found.', 'danger')
            return redirect(url_for('timesheets'))
        if form.action.data == 'clock_in':
            timesheet = Timesheet(
                employee_id=employee.employee_id,
                company_id=current_user.company_id,
                clock_in=datetime.now(IST),
                break_duration=0,
                status='Pending'
            )
            db.session.add(timesheet)
            db.session.commit()
            log_action('clock_in', {'timesheet_id': timesheet.timesheet_id})
            flash('Clocked in successfully!', 'success')
        elif form.action.data == 'clock_out':
            timesheet = Timesheet.query.filter_by(employee_id=employee.employee_id, company_id=current_user.company_id, clock_out=None).first()
            if timesheet:
                timesheet.clock_out = datetime.now(IST)
                timesheet.break_duration = form.break_duration.data
                timesheet.status = 'Pending'
                db.session.commit()
                log_action('clock_out', {'timesheet_id': timesheet.timesheet_id})
                flash('Clocked out successfully!', 'success')
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Timesheet.query.filter_by(company_id=current_user.company_id).count()
    timesheets = db.session.query(Timesheet, Employee.name).join(Employee).filter(
        Timesheet.company_id == current_user.company_id
    ).order_by(Timesheet.clock_in.desc()).offset(offset).limit(per_page).all()
    timesheet_data = [
        {
            'timesheet_id': ts[0].timesheet_id,
            'employee': ts[1],
            'clock_in': ts[0].clock_in,
            'clock_out': ts[0].clock_out,
            'break_duration': ts[0].break_duration,
            'status': ts[0].status,
            'approved_by': ts[0].approved_by or 'N/A'
        } for ts in timesheets
    ]
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('timesheets.html', form=form, timesheets=timesheet_data, is_clocked_in=is_clocked_in,
                           pagination=pagination)

@app.route('/timesheets/approve/<int:timesheet_id>')
@login_required
@permission_required('manage_users')
def approve_timesheet(timesheet_id):
    timesheet = Timesheet.query.filter_by(timesheet_id=timesheet_id, company_id=current_user.company_id).first()
    if timesheet:
        timesheet.status = 'Approved'
        timesheet.approved_by = current_user.username
        db.session.commit()
        log_action('approve_timesheet', {'timesheet_id': timesheet_id})
        flash('Timesheet approved successfully!', 'success')
    return redirect(url_for('timesheets'))

@app.route('/timesheets/reject/<int:timesheet_id>')
@login_required
@permission_required('manage_users')
def reject_timesheet(timesheet_id):
    timesheet = Timesheet.query.filter_by(timesheet_id=timesheet_id, company_id=current_user.company_id).first()
    if timesheet:
        timesheet.status = 'Rejected'
        timesheet.approved_by = current_user.username
        db.session.commit()
        log_action('reject_timesheet', {'timesheet_id': timesheet_id})
        flash('Timesheet rejected successfully!', 'success')
    return redirect(url_for('timesheets'))

@app.route('/inventory', methods=['GET', 'POST'])
@login_required
def inventory():
    form = InventoryForm()
    if form.validate_on_submit():
        inventory = Inventory(
            company_id=current_user.company_id,
            item_name=form.item_name.data,
            category=form.category.data,
            quantity=form.quantity.data,
            reorder_point=form.reorder_point.data,
            unit_price=form.unit_price.data,
            location=form.location.data
        )
        db.session.add(inventory)
        db.session.commit()
        log_action('add_inventory', {'inventory_id': inventory.inventory_id})
        flash('Inventory item added successfully!', 'success')
        return redirect(url_for('inventory'))
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Inventory.query.filter_by(company_id=current_user.company_id).count()
    inventory = Inventory.query.filter_by(company_id=current_user.company_id).order_by(Inventory.item_name).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('inventory.html', form=form, inventory=inventory, pagination=pagination)

@app.route('/edit_inventory/<int:inventory_id>', methods=['GET', 'POST'])
@login_required
def edit_inventory(inventory_id):
    item = Inventory.query.filter_by(inventory_id=inventory_id, company_id=current_user.company_id).first()
    if not item:
        flash('Inventory item not found.', 'danger')
        return redirect(url_for('inventory'))
    form = InventoryForm(obj=item)
    if form.validate_on_submit():
        item.item_name = form.item_name.data
        item.category = form.category.data
        item.quantity = form.quantity.data
        item.reorder_point = form.reorder_point.data
        item.unit_price = form.unit_price.data
        item.location = form.location.data
        db.session.commit()
        log_action('edit_inventory', {'inventory_id': inventory_id})
        flash('Inventory item updated successfully!', 'success')
        return redirect(url_for('inventory'))
    return render_template('edit_inventory.html', form=form, item=item)

@app.route('/delete_inventory/<int:inventory_id>')
@login_required
def delete_inventory(inventory_id):
    item = Inventory.query.filter_by(inventory_id=inventory_id, company_id=current_user.company_id).first()
    if not item:
        flash('Inventory item not found.', 'danger')
        return redirect(url_for('inventory'))
    db.session.delete(item)
    db.session.commit()
    log_action('delete_inventory', {'inventory_id': inventory_id})
    flash('Inventory item deleted successfully!', 'success')
    return redirect(url_for('inventory'))

@app.route('/safety_audits', methods=['GET', 'POST'])
@login_required
def safety_audits():
    form = SafetyAuditForm()
    form.site_id.choices = [(s.site_id, s.name) for s in Site.query.filter_by(company_id=current_user.company_id).all()]
    if form.validate_on_submit():
        audit = SafetyAudit(
            company_id=current_user.company_id,
            site_id=form.site_id.data,
            audit_date=form.audit_date.data,
            description=form.description.data,
            status='Scheduled'
        )
        db.session.add(audit)
        db.session.commit()
        log_action('schedule_audit', {'audit_id': audit.audit_id})
        flash('Safety audit scheduled successfully!', 'success')
        return redirect(url_for('safety_audits'))
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = SafetyAudit.query.filter_by(company_id=current_user.company_id).count()
    audits = SafetyAudit.query.filter_by(company_id=current_user.company_id).order_by(SafetyAudit.audit_date).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('safety_audits.html', form=form, audits=audits, pagination=pagination)

@app.route('/safety_audits/update/<int:audit_id>', methods=['GET', 'POST'])
@login_required
def update_safety_audit(audit_id):
    audit = SafetyAudit.query.filter_by(audit_id=audit_id, company_id=current_user.company_id).first()
    if not audit:
        flash('Audit not found.', 'danger')
        return redirect(url_for('safety_audits'))
    form = SafetyAuditForm(obj=audit)
    form.site_id.choices = [(s.site_id, s.name) for s in Site.query.filter_by(company_id=current_user.company_id).all()]
    if form.validate_on_submit():
        audit.site_id = form.site_id.data
        audit.audit_date = form.audit_date.data
        audit.description = form.description.data
        db.session.commit()
        log_action('update_audit', {'audit_id': audit_id})
        flash('Safety audit updated successfully!', 'success')
        return redirect(url_for('safety_audits'))
    return render_template('update_safety_audit.html', form=form, audit=audit)

@app.route('/admin')
@login_required
@permission_required('manage_users')
def admin():
    form = EmployeeForm()
    user_form = RegisterForm()
    role_form = RoleForm()
    companies = Company.query.all()
    users = User.query.filter_by(company_id=current_user.company_id).all()
    employees = Employee.query.filter_by(company_id=current_user.company_id).all()
    roles = Role.query.all()
    role_form.permissions.choices = [(p.permission_id, p.name) for p in Permission.query.all()]
    return render_template('admin.html', form=form, user_form=user_form, role_form=role_form, companies=companies, users=users,
                           employees=employees, roles=roles)

@app.route('/admin/add_company', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def add_company():
    form = AddCompanyForm()
    if form.validate_on_submit():
        if Company.query.filter_by(name=form.company_name.data).first():
            flash('Company name already exists.', 'danger')
            return redirect(url_for('add_company'))
        company = Company(name=form.company_name.data)
        db.session.add(company)
        db.session.commit()
        if User.query.filter_by(username=form.admin_username.data).first():
            flash('Admin username already exists.', 'danger')
            db.session.delete(company)
            db.session.commit()
            return redirect(url_for('add_company'))
        role = Role.query.filter_by(name='Admin').first()
        hashed_password = generate_password_hash(form.admin_password.data)
        admin_user = User(
            company_id=company.company_id,
            username=form.admin_username.data,
            password=hashed_password,
            role_id=role.role_id
        )
        db.session.add(admin_user)
        db.session.commit()
        log_action('add_company', {'company_id': company.company_id, 'admin_username': admin_user.username})
        flash('Company and admin user added successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('add_company.html', form=form)

@app.route('/admin/add_user', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def add_user():
    form = RegisterForm()
    form.role.choices = [(r.name.lower(), r.name) for r in Role.query.all()]
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('add_user'))
        role = Role.query.filter_by(name=form.role.data.capitalize()).first()
        hashed_password = generate_password_hash(form.password.data)
        user = User(
            company_id=current_user.company_id,
            username=form.username.data,
            password=hashed_password,
            role_id=role.role_id
        )
        db.session.add(user)
        db.session.commit()
        log_action('add_user', {'username': user.username})
        flash('User added successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('add_user.html', form=form)

@app.route('/admin/add_role', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def add_role():
    form = RoleForm()
    form.permissions.choices = [(p.permission_id, p.name) for p in Permission.query.all()]
    if form.validate_on_submit():
        if Role.query.filter_by(name=form.name.data).first():
            flash('Role name already exists.', 'danger')
            return redirect(url_for('add_role'))
        role = Role(name=form.name.data)
        db.session.add(role)
        db.session.commit()
        for perm_id in form.permissions.data:
            permission = Permission.query.get(perm_id)
            if permission:
                db.session.add(RolePermission(role_id=role.role_id, permission_id=perm_id))
        db.session.commit()
        log_action('add_role', {'role_name': role.name})
        flash('Role added successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('add_role.html', form=form)

@app.route('/employee_licenses', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def employee_licenses():
    employee_form = EmployeeForm()
    license_form = LicenseForm()
    employees = Employee.query.filter_by(company_id=current_user.company_id).all()
    license_form.employee_id.choices = [(e.employee_id, e.name) for e in employees]
    if request.method == 'POST':
        form_type = request.form.get('form_type')
        if form_type == 'add_employee' and employee_form.validate_on_submit():
            employee = Employee(
                company_id=current_user.company_id,
                name=employee_form.name.data,
                email=employee_form.email.data,
                role=employee_form.role.data,
                phone=employee_form.phone.data
            )
            db.session.add(employee)
            db.session.commit()
            log_action('add_employee', {'employee_id': employee.employee_id})
            flash('Employee added successfully!', 'success')
            return redirect(url_for('employee_licenses'))
        elif form_type == 'add_license' and license_form.validate_on_submit():
            license = License(
                employee_id=license_form.employee_id.data,
                company_id=current_user.company_id,
                license_type=license_form.license_type.data,
                issue_date=license_form.issue_date.data,
                expiry_date=license_form.expiry_date.data
            )
            db.session.add(license)
            db.session.commit()
            log_action('add_license', {'license_id': license.license_id})
            flash('License added successfully!', 'success')
            return redirect(url_for('employee_licenses'))
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = License.query.filter_by(company_id=current_user.company_id).count()
    licenses = db.session.query(License, Employee.name).join(Employee).filter(
        License.company_id == current_user.company_id
    ).order_by(License.expiry_date).offset(offset).limit(per_page).all()
    license_data = [
        {
            'license_id': lic[0].license_id,
            'employee_name': lic[1],
            'license_type': lic[0].license_type,
            'issue_date': lic[0].issue_date,
            'expiry_date': lic[0].expiry_date,
            'days_until_expiry': (lic[0].expiry_date - date.today()).days,
            'expiry_class': 'text-danger' if (lic[0].expiry_date - date.today()).days <= 30 else 'text-warning' if (lic[0].expiry_date - date.today()).days <= 60 else ''
        } for lic in licenses
    ]
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('employee_licenses.html', employee_form=employee_form, license_form=license_form,
                           licenses=license_data, pagination=pagination)

@app.route('/edit_license/<int:license_id>', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def edit_license(license_id):
    license = License.query.filter_by(license_id=license_id, company_id=current_user.company_id).first()
    if not license:
        flash('License not found.', 'danger')
        return redirect(url_for('employee_licenses'))
    form = LicenseForm(obj=license)
    employees = Employee.query.filter_by(company_id=current_user.company_id).all()
    form.employee_id.choices = [(e.employee_id, e.name) for e in employees]
    if form.validate_on_submit():
        license.employee_id = form.employee_id.data
        license.license_type = form.license_type.data
        license.issue_date = form.issue_date.data
        license.expiry_date = form.expiry_date.data
        db.session.commit()
        log_action('edit_license', {'license_id': license_id})
        flash('License updated successfully!', 'success')
        return redirect(url_for('employee_licenses'))
    return render_template('edit_license.html', form=form, license=license)

@app.route('/delete_license/<int:license_id>')
@login_required
@permission_required('manage_users')
def delete_license(license_id):
    license = License.query.filter_by(license_id=license_id, company_id=current_user.company_id).first()
    if not license:
        flash('License not found.', 'danger')
        return redirect(url_for('employee_licenses'))
    db.session.delete(license)
    db.session.commit()
    log_action('delete_license', {'license_id': license_id})
    flash('License deleted successfully!', 'success')
    return redirect(url_for('employee_licenses'))

@app.route('/edit_employee/<int:employee_id>', methods=['GET', 'POST'])
@login_required
@permission_required('manage_users')
def edit_employee(employee_id):
    employee = Employee.query.filter_by(employee_id=employee_id, company_id=current_user.company_id).first()
    if not employee:
        flash('Employee not found.', 'danger')
        return redirect(url_for('employee_licenses'))
    form = EmployeeForm(obj=employee)
    if form.validate_on_submit():
        employee.name = form.name.data
        employee.email = form.email.data
        employee.role = form.role.data
        employee.phone = form.phone.data
        db.session.commit()
        log_action('edit_employee', {'employee_id': employee_id})
        flash('Employee updated successfully!', 'success')
        return redirect(url_for('employee_licenses'))
    return render_template('edit_employee.html', form=form, employee=employee)

@app.route('/delete_employee/<int:employee_id>')
@login_required
@permission_required('manage_users')
def delete_employee(employee_id):
    employee = Employee.query.filter_by(employee_id=employee_id, company_id=current_user.company_id).first()
    if not employee:
        flash('Employee not found.', 'danger')
        return redirect(url_for('employee_licenses'))
    db.session.delete(employee)
    db.session.commit()
    log_action('delete_employee', {'employee_id': employee_id})
    flash('Employee deleted successfully!', 'success')
    return redirect(url_for('employee_licenses'))

@app.route('/inductions', methods=['GET', 'POST'])
@login_required
def inductions():
    form = InductionForm()
    employees = Employee.query.filter_by(company_id=current_user.company_id).all()
    form.employee_id.choices = [(e.employee_id, e.name) for e in employees]
    if form.validate_on_submit():
        induction = Induction(
            employee_id=form.employee_id.data,
            company_id=current_user.company_id,
            induction_type=form.induction_type.data,
            completion_date=form.completion_date.data
        )
        db.session.add(induction)
        db.session.commit()
        log_action('add_induction', {'induction_id': induction.induction_id})
        flash('Induction added successfully!', 'success')
        return redirect(url_for('inductions'))
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Induction.query.filter_by(company_id=current_user.company_id).count()
    inductions = db.session.query(Induction, Employee.name).join(Employee).filter(
        Induction.company_id == current_user.company_id
    ).order_by(Induction.completion_date.desc()).offset(offset).limit(per_page).all()
    induction_data = [
        {
            'induction_id': ind[0].induction_id,
            'employee_name': ind[1],
            'induction_type': ind[0].induction_type,
            'completion_date': ind[0].completion_date
        } for ind in inductions
    ]
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('inductions.html', form=form, inductions=induction_data, pagination=pagination)

@app.route('/permits', methods=['GET', 'POST'])
@login_required
def permits():
    form = PermitForm()
    form.site_id.choices = [(s.site_id, s.name) for s in Site.query.filter_by(company_id=current_user.company_id).all()]
    if form.validate_on_submit():
        permit = Permit(
            company_id=current_user.company_id,
            site_id=form.site_id.data,
            permit_type=form.permit_type.data,
            issue_date=form.issue_date.data,
            expiry_date=form.expiry_date.data
        )
        db.session.add(permit)
        db.session.commit()
        log_action('add_permit', {'permit_id': permit.permit_id})
        flash('Permit added successfully!', 'success')
        return redirect(url_for('permits'))
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Permit.query.filter_by(company_id=current_user.company_id).count()
    permits = Permit.query.filter_by(company_id=current_user.company_id).order_by(Permit.expiry_date).offset(offset).limit(per_page).all()
    permit_data = [
        {
            'permit_id': p.permit_id,
            'site_id': p.site_id,
            'site_name': p.site.name,
            'permit_type': p.permit_type,
            'issue_date': p.issue_date,
            'expiry_date': p.expiry_date,
            'days_until_expiry': (p.expiry_date - date.today()).days
        } for p in permits
    ]
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('permits.html', form=form, permits=permit_data, pagination=pagination)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    form = SettingsForm(username=current_user.username, email=current_user.email or '')
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).filter(User.id != current_user.id).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('settings'))
        current_user.username = form.username.data
        if form.email.data:
            current_user.email = form.email.data
        if form.password.data:
            current_user.password = generate_password_hash(form.password.data)
        db.session.commit()
        log_action('update_settings', {'username': current_user.username})
        flash('Settings updated successfully!', 'success')
        return redirect(url_for('settings'))
    return render_template('settings.html', form=form)

@app.route('/resource_allocation')
@login_required
def resource_allocation():
    sites = Site.query.filter_by(company_id=current_user.company_id).all()
    resources = []
    for site in sites:
        equipment = Equipment.query.filter_by(company_id=current_user.company_id).filter(
            Equipment.site_id == site.site_id
        ).count()
        labor = Employee.query.join(ProjectAssignment).filter(
            ProjectAssignment.project_id.in_(
                db.session.query(Project.project_id).filter(Project.site_id == site.site_id)
            )
        ).count()
        inventory = Inventory.query.filter_by(company_id=current_user.company_id).filter(
            Inventory.site_id == site.site_id
        ).count()
        resources.append({
            'site': site.name,
            'equipment': f'{equipment} items',
            'labor': f'{labor} workers',
            'materials': f'{inventory} items'
        })
    return render_template('resource_allocation.html', resources=resources)

@app.route('/projects', methods=['GET', 'POST'])
@login_required
@permission_required('manage_projects')
def projects():
    form = ProjectForm()
    if form.validate_on_submit():
        project = Project(
            company_id=current_user.company_id,
            name=form.name.data,
            description=form.description.data,
            start_date=form.start_date.data,
            end_date=form.end_date.data,
            status=form.status.data
        )
        db.session.add(project)
        db.session.commit()
        log_action('create_project', {'project_id': project.project_id})
        flash('Project created successfully!', 'success')
        return redirect(url_for('projects'))
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Project.query.filter_by(company_id=current_user.company_id).count()
    projects = Project.query.filter_by(company_id=current_user.company_id).order_by(Project.start_date).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('projects.html', form=form, projects=projects, pagination=pagination)

@app.route('/project/<int:project_id>', methods=['GET', 'POST'])
@login_required
@permission_required('manage_projects')
def project_detail(project_id):
    project = Project.query.filter_by(project_id=project_id, company_id=current_user.company_id).first()
    if not project:
        flash('Project not found.', 'danger')
        return redirect(url_for('projects'))
    milestone_form = MilestoneForm()
    assignment_form = ProjectAssignmentForm()
    assignment_form.employee_id.choices = [(e.employee_id, e.name) for e in Employee.query.filter_by(company_id=current_user.company_id).all()]
    if request.method == 'POST':
        if 'milestone_form' in request.form and milestone_form.validate_on_submit():
            milestone = Milestone(
                project_id=project_id,
                name=milestone_form.name.data,
                due_date=milestone_form.due_date.data,
                status=milestone_form.status.data
            )
            db.session.add(milestone)
            db.session.commit()
            log_action('add_milestone', {'milestone_id': milestone.milestone_id})
            flash('Milestone added successfully!', 'success')
            return redirect(url_for('project_detail', project_id=project_id))
        elif 'assignment_form' in request.form and assignment_form.validate_on_submit():
            assignment = ProjectAssignment(
                project_id=project_id,
                employee_id=assignment_form.employee_id.data,
                role=assignment_form.role.data
            )
            db.session.add(assignment)
            db.session.commit()
            log_action('add_project_assignment', {'assignment_id': assignment.assignment_id})
            flash('Employee assigned successfully!', 'success')
            return redirect(url_for('project_detail', project_id=project_id))
    milestones = Milestone.query.filter_by(project_id=project_id).all()
    assignments = db.session.query(ProjectAssignment, Employee.name).join(Employee).filter(
        ProjectAssignment.project_id == project_id
    ).all()
    assignment_data = [
        {
            'assignment_id': a[0].assignment_id,
            'employee_name': a[1],
            'role': a[0].role
        } for a in assignments
    ]
    return render_template('project_detail.html', project=project, milestone_form=milestone_form,
                           assignment_form=assignment_form, milestones=milestones, assignments=assignment_data)

@app.route('/documents', methods=['GET', 'POST'])
@login_required
@permission_required('upload_documents')
def documents():
    form = DocumentForm()
    if form.validate_on_submit():
        file = form.file.data
        if not file or not allowed_file(file.filename, file):
            flash('Invalid file type. Allowed: PDF, PNG, JPG.', 'danger')
            return redirect(url_for('documents'))
        filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        file.save(file_path)
        document = Document(
            company_id=current_user.company_id,
            title=form.title.data,
            file_url=f"uploads/{filename}",
            uploaded_by=current_user.username
        )
        db.session.add(document)
        db.session.commit()
        log_action('upload_document', {'document_id': document.document_id})
        flash('Document uploaded successfully!', 'success')
        return redirect(url_for('documents'))
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = Document.query.filter_by(company_id=current_user.company_id).count()
    documents = Document.query.filter_by(company_id=current_user.company_id).order_by(Document.uploaded_at.desc()).offset(offset).limit(per_page).all()
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('documents.html', form=form, documents=documents, pagination=pagination)

@app.route('/document/<int:document_id>')
@login_required
@permission_required('view_documents')
def document_detail(document_id):
    document = Document.query.filter_by(document_id=document_id, company_id=current_user.company_id).first()
    if not document:
        flash('Document not found.', 'danger')
        return redirect(url_for('documents'))
    return render_template('document_detail.html', document=document)

@app.route('/chat', methods=['GET', 'POST'])
@login_required
def chat():
    form = ChatForm()
    if form.validate_on_submit():
        message = {
            'username': current_user.username,
            'text': form.message.data,
            'timestamp': datetime.now(IST).strftime('%Y-%m-%d %H:%M:%S')
        }
        socketio.emit('chat_message', message, namespace='/chat')
        log_action('send_chat_message', {'message': message['text']})
        return redirect(url_for('chat'))
    return render_template('chat.html', form=form)

@app.route('/calendar')
@login_required
def calendar():
    tasks = Task.query.filter_by(company_id=current_user.company_id).all()
    audits = SafetyAudit.query.filter_by(company_id=current_user.company_id).all()
    permits = Permit.query.filter_by(company_id=current_user.company_id).all()
    events = []
    for task in tasks:
        events.append({
            'title': task.title,
            'start': task.due_date.strftime('%Y-%m-%d'),
            'color': '#28a745' if task.status == 'Completed' else '#ffc107' if task.status == 'In Progress' else '#dc3545',
            'url': url_for('tasks')
        })
    for audit in audits:
        events.append({
            'title': f'Audit: {audit.site.name}',
            'start': audit.audit_date.strftime('%Y-%m-%d'),
            'color': '#17a2b8',
            'url': url_for('safety_audits')
        })
    for permit in permits:
        events.append({
            'title': f'Permit: {permit.permit_type}',
            'start': permit.expiry_date.strftime('%Y-%m-%d'),
            'color': '#6c757d',
            'url': url_for('permits')
        })
    return render_template('calendar.html', events=json.dumps(events))

@app.route('/audit_logs')
@login_required
@permission_required('manage_users')
def audit_logs():
    page, per_page, offset = get_page_args(page_parameter='page', per_page_parameter='per_page')
    per_page = 10
    total = AuditLog.query.filter_by(company_id=current_user.company_id).count()
    logs = AuditLog.query.filter_by(company_id=current_user.company_id).order_by(AuditLog.timestamp.desc()).offset(offset).limit(per_page).all()
    log_data = [
        {
            'log_id': log.log_id,
            'user': User.query.get(log.user_id).username if User.query.get(log.user_id) else 'Unknown',
            'action': log.action,
            'details': json.loads(log.details) if log.details else {},
            'timestamp': log.timestamp
        } for log in logs
    ]
    pagination = Pagination(page=page, per_page=per_page, total=total, css_framework='bootstrap5')
    return render_template('audit_logs.html', logs=log_data, pagination=pagination)

@app.route('/set-theme', methods=['POST'])
@login_required
def set_theme():
    data = request.get_json()
    if data and 'theme' in data:
        session['theme'] = data['theme']
        return {'status': 'success'}
    return {'status': 'error'}, 400

@app.route('/favicon.ico')
def favicon():
    try:
        return send_file(os.path.join(app.root_path, 'static', 'favicon.ico'), mimetype='image/vnd.microsoft.icon')
    except FileNotFoundError:
        abort(404)

# API Endpoints
class OrderAPI(Resource):
    @login_required
    @permission_required('view_orders')
    def get(self, order_id=None):
        if order_id:
            order = Order.query.filter_by(order_id=order_id, company_id=current_user.company_id).first()
            if not order:
                return {'error': 'Order not found'}, 404
            return {
                'order_id': order.order_id,
                'item': order.item,
                'quantity': order.quantity,
                'site_id': order.site_id,
                'status': order.status,
                'timestamp': order.timestamp.isoformat()
            }, 200
        orders = Order.query.filter_by(company_id=current_user.company_id).all()
        return [{
            'order_id': o.order_id,
            'item': o.item,
            'quantity': o.quantity,
            'site_id': o.site_id,
            'status': o.status,
            'timestamp': o.timestamp.isoformat()
        } for o in orders], 200

    @login_required
    @permission_required('create_orders')
    def post(self):
        data = request.get_json()
        if not data or 'item' not in data or 'quantity' not in data or 'site_id' not in data:
            return {'error': 'Missing required fields'}, 400
        site = Site.query.filter_by(site_id=data['site_id'], company_id=current_user.company_id).first()
        if not site:
            return {'error': 'Invalid site ID'}, 400
        order = Order(
            company_id=current_user.company_id,
            item=data['item'],
            quantity=data['quantity'],
            site_id=data['site_id'],
            status='Pending',
            comments=data.get('comments')
        )
        db.session.add(order)
        db.session.commit()
        log_action('create_order_api', {'order_id': order.order_id})
        return {'order_id': order.order_id, 'status': 'created'}, 201

api.add_resource(OrderAPI, '/api/orders', '/api/orders/<int:order_id>')

# SocketIO Events
@socketio.on('connect', namespace='/chat')
def chat_connect():
    if current_user.is_authenticated:
        emit('status', {'msg': f'{current_user.username} has connected'}, broadcast=True)

@socketio.on('chat_message', namespace='/chat')
def handle_chat_message(data):
    if current_user.is_authenticated:
        emit('chat_message', data, broadcast=True)

@socketio.on('collaborationUpdate')
def handle_collaboration_update(data):
    emit('collaborationUpdate', data, broadcast=True)

# Context Processor
@app.context_processor
def inject_globals():
    def has_permission(permission_name):
        if not current_user.is_authenticated or not current_user.role:
            return False
        return permission_name in [p.name for p in current_user.role.permissions]
    return {
        'notifications_count': get_notifications_count(current_user.company_id) if current_user.is_authenticated else 0,
        'has_permission': has_permission,
        'current_time': datetime.now(IST)  # Inject current time for all templates
    }

if __name__ == '__main__':
    with app.app_context():
        init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))