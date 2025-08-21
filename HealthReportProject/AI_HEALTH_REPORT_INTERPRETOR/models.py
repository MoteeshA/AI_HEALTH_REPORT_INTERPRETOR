from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime

db = SQLAlchemy()

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    reports = db.relationship('HealthReport', backref='user', lazy=True)

class HealthReport(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_uploaded = db.Column(db.DateTime, default=datetime.utcnow)

    # Medical data
    hemoglobin = db.Column(db.Float)
    wbc = db.Column(db.Float)
    platelets = db.Column(db.Float)

    # Raw and AI-processed content
    raw_text = db.Column(db.Text)
    summary = db.Column(db.Text)  # AI-generated summary
    recommendations = db.Column(db.Text)  # Natural remedy suggestions
