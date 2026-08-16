from datetime import datetime
from app import db

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(50), nullable=False)
    environment = db.Column(db.String(50), nullable=True) # e.g., Production, Staging
    criticality = db.Column(db.String(50), nullable=True) # e.g., High, Medium, Low
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    scan_targets = db.relationship('ScanTarget', backref='asset', lazy=True)
    findings = db.relationship('Finding', backref='asset', lazy=True)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False)  # 'internal' or 'external' (context label only now)
    status = db.Column(db.String(50), default='queued')  # queued, running, completed — derived from engine sub-statuses
    # Legacy single-engine fields kept for backward compat with old rows
    progress = db.Column(db.String(255), nullable=True)
    progress_percent = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)
    celery_task_id = db.Column(db.String(255), nullable=True)   # parent dispatch task ID
    openvas_task_id = db.Column(db.String(255), nullable=True)  # legacy, now on ScanEngine
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    scan_targets = db.relationship('ScanTarget', backref='scan', lazy=True)
    findings = db.relationship('Finding', backref='scan', lazy=True)
    engines = db.relationship('ScanEngine', backref='scan', lazy=True)

class ScanEngine(db.Model):
    """
    Tracks one engine's execution per scan.
    A scan always creates two rows: one for 'nuclei', one for 'openvas'.
    Each row is updated independently — failures in one never affect the other.
    """
    __tablename__ = 'scan_engine'

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    engine = db.Column(db.String(20), nullable=False)       # 'nuclei' or 'openvas'
    status = db.Column(db.String(20), default='queued')     # queued | running | completed | failed
    progress = db.Column(db.Text, nullable=True)            # human-readable current step
    progress_pct = db.Column(db.Integer, default=0)         # 0–100
    error_message = db.Column(db.Text, nullable=True)       # populated only on failure
    celery_task_id = db.Column(db.String(255), nullable=True)   # sub-task ID
    openvas_task_id = db.Column(db.String(255), nullable=True)  # openvas task id (openvas only)
    started_at = db.Column(db.DateTime, nullable=True)
    finished_at = db.Column(db.DateTime, nullable=True)

class ScanTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    engine = db.Column(db.String(20), nullable=True)        # 'nuclei' or 'openvas'; NULL = legacy row
    severity = db.Column(db.String(50), nullable=False)     # Critical, High, Medium, Low, Informational
    cve = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)
    recommendation = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False)  # internal, external
    status = db.Column(db.String(50), default='offline')  # online, offline
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(100), nullable=False)  # Executive Summary, Technical Findings, etc.
    format = db.Column(db.String(20), nullable=False)  # pdf, csv
    status = db.Column(db.String(50), default='generating')  # generating, completed, failed
    file_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
