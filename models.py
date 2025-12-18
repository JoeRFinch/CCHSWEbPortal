from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))
    role = db.Column(db.String(20), default='volunteer')  # Primary role
    permissions = db.Column(db.Text)  # JSON string of custom permissions
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    time_entries = db.relationship('TimeEntry', backref='user', lazy=True)
    checklist_completions = db.relationship('ChecklistCompletion', backref='user', lazy=True)
    audit_logs = db.relationship('AuditLog', backref='user', lazy=True)
    staff_notes = db.relationship('StaffNote', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_permissions(self):
        """Get user permissions as dictionary"""
        if self.permissions:
            return json.loads(self.permissions)
        return self.get_default_permissions()
    
    def set_permissions(self, perms_dict):
        """Set user permissions from dictionary"""
        self.permissions = json.dumps(perms_dict)
    
    def get_default_permissions(self):
        """Get default permissions based on role"""
        defaults = {
            'admin': {
                'view_dashboard': True,
                'view_animals': True,
                'edit_animals': True,
                'add_animals': True,
                'view_checklists': True,
                'complete_checklists': True,
                'manage_checklists': True,
                'view_time_clock': True,
                'use_time_clock': True,
                'view_all_time_entries': True,
                'view_phone_logs': True,
                'edit_phone_logs': True,
                'view_donations': True,
                'edit_donations': True,
                'view_items_out': True,
                'edit_items_out': True,
                'view_audit_log': True,
                'manage_users': True,
                'manage_locations': True,
                'view_maintenance': True,
                'manage_maintenance': True,
                'view_staff_notes': True,
                'add_staff_notes': True
            },
            'management': {
                'view_dashboard': True,
                'view_animals': True,
                'edit_animals': True,
                'add_animals': True,
                'view_checklists': True,
                'complete_checklists': True,
                'manage_checklists': True,
                'view_time_clock': True,
                'use_time_clock': True,
                'view_all_time_entries': True,
                'view_phone_logs': True,
                'edit_phone_logs': True,
                'view_donations': True,
                'edit_donations': True,
                'view_items_out': True,
                'edit_items_out': True,
                'view_audit_log': True,
                'manage_users': True,
                'manage_locations': True,
                'view_maintenance': True,
                'manage_maintenance': True,
                'view_staff_notes': True,
                'add_staff_notes': True
            },
            'board': {
                'view_dashboard': True,
                'view_animals': True,
                'edit_animals': True,
                'add_animals': True,
                'view_checklists': True,
                'complete_checklists': True,
                'manage_checklists': True,
                'view_time_clock': True,
                'use_time_clock': True,
                'view_all_time_entries': True,
                'view_phone_logs': True,
                'edit_phone_logs': True,
                'view_donations': True,
                'edit_donations': True,
                'view_items_out': True,
                'edit_items_out': True,
                'view_audit_log': True,
                'manage_users': True,
                'manage_locations': True,
                'view_maintenance': True,
                'manage_maintenance': False,
                'view_staff_notes': True,
                'add_staff_notes': True
            },
            'employee': {
                'view_dashboard': True,
                'view_animals': True,
                'edit_animals': True,
                'add_animals': False,
                'view_checklists': True,
                'complete_checklists': True,
                'manage_checklists': False,
                'view_time_clock': True,
                'use_time_clock': True,
                'view_all_time_entries': False,
                'view_phone_logs': True,
                'edit_phone_logs': True,
                'view_donations': True,
                'edit_donations': True,
                'view_items_out': True,
                'edit_items_out': True,
                'view_audit_log': False,
                'manage_users': False,
                'manage_locations': False,
                'view_maintenance': False,
                'manage_maintenance': False,
                'view_staff_notes': True,
                'add_staff_notes': True
            },
            'volunteer': {
                'view_dashboard': True,
                'view_animals': True,
                'edit_animals': False,
                'add_animals': False,
                'view_checklists': True,
                'complete_checklists': True,
                'manage_checklists': False,
                'view_time_clock': True,
                'use_time_clock': True,
                'view_all_time_entries': False,
                'view_phone_logs': True,
                'edit_phone_logs': False,
                'view_donations': True,
                'edit_donations': False,
                'view_items_out': True,
                'edit_items_out': False,
                'view_audit_log': False,
                'manage_users': False,
                'manage_locations': False,
                'view_maintenance': False,
                'manage_maintenance': False,
                'view_staff_notes': True,
                'add_staff_notes': True
            },
            'maintenance': {
                'view_dashboard': True,
                'view_animals': True,
                'edit_animals': False,
                'add_animals': False,
                'view_checklists': True,
                'complete_checklists': True,
                'manage_checklists': False,
                'view_time_clock': True,
                'use_time_clock': True,
                'view_all_time_entries': False,
                'view_phone_logs': False,
                'edit_phone_logs': False,
                'view_donations': False,
                'edit_donations': False,
                'view_items_out': False,
                'edit_items_out': False,
                'view_audit_log': False,
                'manage_users': False,
                'manage_locations': False,
                'view_maintenance': True,
                'manage_maintenance': True,
                'view_staff_notes': True,
                'add_staff_notes': True
            }
        }
        return defaults.get(self.role, defaults['volunteer'])
    
    def has_permission(self, permission_name):
        """Check if user has a specific permission"""
        perms = self.get_permissions()
        return perms.get(permission_name, False)

class TimeEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    clock_in = db.Column(db.DateTime, nullable=False)
    clock_out = db.Column(db.DateTime)
    total_hours = db.Column(db.Float)
    role_type = db.Column(db.String(20))  # 'employee', 'volunteer', 'maintenance'
    notes = db.Column(db.Text)
    
    def calculate_hours(self):
        if self.clock_out:
            delta = self.clock_out - self.clock_in
            self.total_hours = round(delta.total_seconds() / 3600, 2)

class AnimalLocation(db.Model):
    """Manage facility locations for animals"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    location_type = db.Column(db.String(50))  # 'kennel', 'cat_room', 'isolation', 'lobby', 'other'
    capacity = db.Column(db.Integer)
    active = db.Column(db.Boolean, default=True)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to animals
    animals = db.relationship('Animal', backref='location_obj', lazy=True)

class Checklist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    time_period = db.Column(db.String(20))  # 'am', 'pm', 'daily', 'weekly'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Relationships
    items = db.relationship('ChecklistItem', backref='checklist', lazy=True, cascade='all, delete-orphan')
    completions = db.relationship('ChecklistCompletion', backref='checklist', lazy=True)

class ChecklistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    checklist_id = db.Column(db.Integer, db.ForeignKey('checklist.id'), nullable=False)
    task = db.Column(db.String(300), nullable=False)
    order = db.Column(db.Integer, default=0)

class ChecklistCompletion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    checklist_id = db.Column(db.Integer, db.ForeignKey('checklist.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    completed_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    status = db.Column(db.String(20), default='completed')
    
    # Relationships
    items = db.relationship('ChecklistItemCompletion', backref='completion', lazy=True)

class ChecklistItemCompletion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    completion_id = db.Column(db.Integer, db.ForeignKey('checklist_completion.id'), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey('checklist_item.id'), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)
    
    # Relationships
    item = db.relationship('ChecklistItem', backref='completions')

class Animal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    species = db.Column(db.String(50))
    breed = db.Column(db.String(100))
    age = db.Column(db.String(50))
    sex = db.Column(db.String(20))
    intake_date = db.Column(db.DateTime, default=datetime.utcnow)
    intake_reason = db.Column(db.Text)
    location_id = db.Column(db.Integer, db.ForeignKey('animal_location.id'))  # NEW: FK to locations
    location = db.Column(db.String(100))  # DEPRECATED: Keep for migration
    medical_notes = db.Column(db.Text)
    behavioral_notes = db.Column(db.Text)
    special_needs = db.Column(db.Text)
    status = db.Column(db.String(50), default='available')
    
    # Foster dates
    foster_out_date = db.Column(db.DateTime)
    foster_return_date = db.Column(db.DateTime)
    foster_name = db.Column(db.String(200))
    foster_contact = db.Column(db.String(200))
    
    # Adoption info
    adopted_date = db.Column(db.DateTime)
    adopter_name = db.Column(db.String(200))
    adopter_contact = db.Column(db.String(200))
    
    # Vet visits
    vet_visits = db.relationship('VetVisit', backref='animal', lazy=True, cascade='all, delete-orphan')

class VetVisit(db.Model):
    """Track veterinary visits for animals"""
    id = db.Column(db.Integer, primary_key=True)
    animal_id = db.Column(db.Integer, db.ForeignKey('animal.id'), nullable=False)
    visit_date = db.Column(db.DateTime, nullable=False)
    vet_name = db.Column(db.String(200))
    reason = db.Column(db.Text)
    diagnosis = db.Column(db.Text)
    treatment = db.Column(db.Text)
    medications = db.Column(db.Text)
    follow_up_needed = db.Column(db.Boolean, default=False)
    follow_up_date = db.Column(db.DateTime)
    cost = db.Column(db.Float)
    notes = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PhoneLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    caller_name = db.Column(db.String(200))
    caller_phone = db.Column(db.String(50))
    issue = db.Column(db.Text, nullable=False)
    action_taken = db.Column(db.Text)
    follow_up_needed = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(50), default='open')
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='phone_logs')

class Donation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    donor_name = db.Column(db.String(200))
    donor_contact = db.Column(db.String(200))
    donation_type = db.Column(db.String(50))
    amount = db.Column(db.Float)
    item_description = db.Column(db.Text)
    notes = db.Column(db.Text)
    status = db.Column(db.String(50), default='received')
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    creator = db.relationship('User', foreign_keys=[created_by], backref='donations')

class ItemOut(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_name = db.Column(db.String(200), nullable=False)
    quantity = db.Column(db.Integer)
    reason = db.Column(db.String(100))
    recipient = db.Column(db.String(200))
    animal_id = db.Column(db.Integer, db.ForeignKey('animal.id'))
    notes = db.Column(db.Text)
    status = db.Column(db.String(50), default='logged')
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class MaintenanceTicket(db.Model):
    """Maintenance and project tracking"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    priority = db.Column(db.String(20), default='medium')  # 'low', 'medium', 'high', 'urgent'
    status = db.Column(db.String(20), default='open')  # 'open', 'in_progress', 'completed', 'on_hold'
    category = db.Column(db.String(50))  # 'plumbing', 'electrical', 'hvac', 'general', 'equipment'
    location = db.Column(db.String(100))
    assigned_to = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    due_date = db.Column(db.DateTime)
    estimated_cost = db.Column(db.Float)
    actual_cost = db.Column(db.Float)
    notes = db.Column(db.Text)
    
    # Relationships
    assignee = db.relationship('User', foreign_keys=[assigned_to], backref='assigned_tickets')
    creator = db.relationship('User', foreign_keys=[created_by], backref='created_tickets')

class StaffNote(db.Model):
    """Internal communication notes for management visibility"""
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200))
    content = db.Column(db.Text, nullable=False)
    priority = db.Column(db.String(20), default='normal')  # 'low', 'normal', 'high', 'urgent'
    category = db.Column(db.String(50))  # 'general', 'animal_care', 'facility', 'staff', 'other'
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    action = db.Column(db.String(100), nullable=False)
    table_name = db.Column(db.String(100))
    record_id = db.Column(db.Integer)
    old_value = db.Column(db.Text)  # JSON string
    new_value = db.Column(db.Text)  # JSON string
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(50))
    
    def get_old_value_dict(self):
        """Parse old value from JSON"""
        if self.old_value:
            try:
                return json.loads(self.old_value)
            except:
                return {}
        return {}
    
    def get_new_value_dict(self):
        """Parse new value from JSON"""
        if self.new_value:
            try:
                return json.loads(self.new_value)
            except:
                return {}
        return {}