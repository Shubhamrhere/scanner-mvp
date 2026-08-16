from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response, jsonify
import csv
import io
import pdfkit
from models import Asset, Scan, ScanTarget, Finding, Agent, Report, ScanEngine
from app import db

from datetime import datetime

bp = Blueprint('main', __name__)

@bp.route('/assets')
def assets():
    all_assets = Asset.query.order_by(Asset.created_at.desc()).all()
    return render_template('assets.html', assets=all_assets)

@bp.route('/assets/new', methods=['GET', 'POST'])
def new_asset():
    if request.method == 'POST':
        hostname = request.form.get('hostname', '').strip()
        ip_address = request.form.get('ip_address', '').strip()
        environment = request.form.get('environment')
        criticality = request.form.get('criticality')
        
        if not hostname and not ip_address:
            flash('You must provide either a hostname or an IP address.', 'error')
            return render_template('asset_form.html')
            
        import ipaddress
        import re
        
        if ip_address:
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                flash('Invalid IP Address format.', 'error')
                return render_template('asset_form.html')
                
        if hostname:
            if len(hostname) > 255:
                flash('Hostname too long.', 'error')
                return render_template('asset_form.html')
            allowed = re.compile(r"(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
            host_to_check = hostname[:-1] if hostname.endswith('.') else hostname
            if not all(allowed.match(x) for x in host_to_check.split(".")):
                flash('Invalid Hostname format.', 'error')
                return render_template('asset_form.html')
        
        asset = Asset(hostname=hostname, ip_address=ip_address, environment=environment, criticality=criticality)
        db.session.add(asset)
        db.session.commit()
        flash('Asset created successfully.', 'success')
        return redirect(url_for('main.assets'))
    return render_template('asset_form.html')

@bp.route('/agents')
def agents():
    all_agents = Agent.query.order_by(Agent.last_seen.desc()).all()
    return render_template('agents.html', agents=all_agents)

@bp.route('/scans')
def scans():
    all_scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template('scans.html', scans=all_scans)

@bp.route('/scans/new', methods=['GET', 'POST'])
def new_scan():
    if request.method == 'POST':
        scan_type = request.form.get('type')
        asset_ids = request.form.getlist('asset_ids')
        
        if not asset_ids:
            return redirect(url_for('main.new_scan'))
            
        scan = Scan(type=scan_type, status='queued')
        db.session.add(scan)
        db.session.flush()
        
        for asset_id in asset_ids:
            target = ScanTarget(scan_id=scan.id, asset_id=asset_id)
            db.session.add(target)
            
        db.session.commit()
        
        from tasks import execute_scan
        task = execute_scan.delay(scan.id, scan_type, [int(a) for a in asset_ids])
        scan.celery_task_id = task.id
        db.session.commit()
        
        return redirect(url_for('main.scans'))
        
    all_assets = Asset.query.all()
    return render_template('scan_form.html', assets=all_assets)

@bp.route('/scans/<int:id>')
def scan_detail(id):
    scan = Scan.query.get_or_404(id)
    return render_template('scan_detail.html', scan=scan)

@bp.route('/scans/<int:id>/cancel', methods=['POST'])
def cancel_scan(id):
    scan = Scan.query.get_or_404(id)
    if scan.status in ['queued', 'running']:
        if scan.celery_task_id:
            from celery.app.control import Control
            from tasks import celery
            Control(celery).revoke(scan.celery_task_id, terminate=True, signal='SIGTERM')
            
        # Cancel any running OpenVAS engine tasks
        for se in scan.engines:
            if se.engine == 'openvas' and se.openvas_task_id:
                try:
                    from gvm.connections import UnixSocketConnection
                    from gvm.protocols.gmp import Gmp
                    from gvm.transforms import EtreeTransform
                    connection = UnixSocketConnection(path="/run/gvmd/gvmd.sock")
                    transform = EtreeTransform()
                    with Gmp(connection=connection, transform=transform) as gmp:
                        gmp.authenticate('admin', 'admin')
                        gmp.stop_task(se.openvas_task_id)
                except Exception as e:
                    print(f"Failed to stop OpenVAS task: {e}")
                    
        scan.status = 'completed'
        scan.progress = 'Scan cancelled by user.'
        scan.end_time = datetime.utcnow()
        db.session.commit()
        flash('Scan cancelled successfully.', 'info')
    else:
        flash('Scan cannot be cancelled in its current state.', 'error')
        
    return redirect(url_for('main.scan_detail', id=scan.id))

@bp.route('/findings')
def findings():
    all_findings = Finding.query.order_by(Finding.created_at.desc()).all()
    return render_template('findings.html', findings=all_findings)

@bp.route('/reports')
def reports():
    all_reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('reports.html', reports=all_reports)

@bp.route('/reports/generate', methods=['POST'])
def generate_report():
    report_format = request.form.get('format', 'csv')
    scan_id = request.form.get('scan_id')
    
    query = Finding.query.order_by(Finding.created_at.desc())
    if scan_id:
        query = query.filter_by(scan_id=scan_id)
    findings = query.all()
    
    report_type = f'Scan {scan_id} Findings' if scan_id else 'Technical Findings'
    report = Report(type=report_type, format=report_format, status='completed')
    db.session.add(report)
    db.session.commit()
    
    if report_format == 'csv':
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['ID', 'Engine', 'Asset ID', 'Severity', 'CVE', 'Description', 'Recommendation', 'Created At'])
        for f in findings:
            cw.writerow([f.id, f.engine or 'legacy', f.asset_id, f.severity, f.cve, f.description, f.recommendation, f.created_at])
            
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = f"attachment; filename=report_{report.id}.csv"
        output.headers["Content-type"] = "text/csv"
        return output
        
    elif report_format == 'pdf':
        html = render_template('findings_pdf.html', findings=findings)
        try:
            pdf = pdfkit.from_string(html, False)
            output = make_response(pdf)
            output.headers["Content-Disposition"] = f"attachment; filename=report_{report.id}.pdf"
            output.headers["Content-type"] = "application/pdf"
            return output
        except Exception as e:
            flash(f"PDF generation failed: {e}")
            return redirect(url_for('main.reports'))
            
    return redirect(url_for('main.reports'))

# ---------------------------------------------------------------------------
# API endpoints for per-engine status polling and findings
# ---------------------------------------------------------------------------

@bp.route('/api/scans/<int:id>/status')
def api_scan_status(id):
    """
    Returns per-engine status and progress for a scan.
    Used by the scan detail page for live polling.
    """
    scan = Scan.query.get_or_404(id)
    engines = ScanEngine.query.filter_by(scan_id=id).all()

    engine_data = {}
    for se in engines:
        nuclei_count = Finding.query.filter_by(scan_id=id, engine=se.engine).count()
        engine_data[se.engine] = {
            'status': se.status,
            'progress': se.progress or '',
            'progress_pct': se.progress_pct or 0,
            'error_message': se.error_message,
            'findings_count': nuclei_count,
            'started_at': se.started_at.isoformat() if se.started_at else None,
            'finished_at': se.finished_at.isoformat() if se.finished_at else None,
        }

    # If no engine rows exist yet (legacy scans), return empty engine data
    return jsonify({
        'scan_id': id,
        'overall_status': scan.status,
        'engines': engine_data,
    })


@bp.route('/api/scans/<int:id>/findings')
def api_scan_findings(id):
    """
    Returns findings separated by engine.
    Used by the scan detail page to render two independent findings sections.
    """
    scan = Scan.query.get_or_404(id)

    def finding_dict(f):
        return {
            'id': f.id,
            'severity': f.severity,
            'cve': f.cve or '',
            'description': f.description or '',
            'recommendation': f.recommendation or '',
            'asset': f.asset.hostname or f.asset.ip_address if f.asset else str(f.asset_id),
            'created_at': f.created_at.isoformat(),
        }

    nuclei_findings = Finding.query.filter_by(scan_id=id, engine='nuclei').order_by(Finding.created_at.desc()).all()
    openvas_findings = Finding.query.filter_by(scan_id=id, engine='openvas').order_by(Finding.created_at.desc()).all()
    legacy_findings = Finding.query.filter_by(scan_id=id, engine=None).order_by(Finding.created_at.desc()).all()

    return jsonify({
        'scan_id': id,
        'nuclei': [finding_dict(f) for f in nuclei_findings],
        'openvas': [finding_dict(f) for f in openvas_findings],
        'legacy': [finding_dict(f) for f in legacy_findings],
    })


@bp.route('/api/agents/heartbeat', methods=['POST'])
def agent_heartbeat():
    data = request.json
    agent_name = data.get('name')
    agent_type = data.get('type')
    
    agent = Agent.query.filter_by(name=agent_name).first()
    if not agent:
        agent = Agent(name=agent_name, type=agent_type, status='online')
        db.session.add(agent)
    else:
        agent.status = 'online'
        agent.last_seen = datetime.utcnow()
        
    db.session.commit()
    return {'status': 'success'}
