import os
import json
import subprocess
import time
from datetime import datetime
from celery import Celery
from config import Config

# Initialize Celery app
celery = Celery(
    'tasks',
    broker=Config.CELERY_BROKER_URL,
    backend=Config.CELERY_RESULT_BACKEND
)

# ---------------------------------------------------------------------------
# Parent dispatch task
# ---------------------------------------------------------------------------

@celery.task
def execute_scan(scan_id, scan_type, asset_ids):
    """
    Parent task: creates two ScanEngine rows and launches Nuclei + OpenVAS
    as completely independent parallel sub-tasks. Returns immediately after
    dispatching — it does NOT wait for either engine to finish.
    """
    from app import create_app, db
    from models import Scan, ScanEngine

    app = create_app()
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        scan.status = 'running'
        scan.start_time = datetime.utcnow()

        # Create one ScanEngine row per engine
        for engine_name in ('nuclei', 'openvas'):
            existing = ScanEngine.query.filter_by(scan_id=scan_id, engine=engine_name).first()
            if not existing:
                se = ScanEngine(
                    scan_id=scan_id,
                    engine=engine_name,
                    status='queued',
                    progress='Queued',
                    progress_pct=0,
                )
                db.session.add(se)

        db.session.commit()

        # Dispatch both sub-tasks independently
        nuclei_task = run_nuclei_engine.delay(scan_id, asset_ids)
        openvas_task = run_openvas_engine.delay(scan_id, asset_ids)

        # Record sub-task IDs
        nuclei_se = ScanEngine.query.filter_by(scan_id=scan_id, engine='nuclei').first()
        openvas_se = ScanEngine.query.filter_by(scan_id=scan_id, engine='openvas').first()
        if nuclei_se:
            nuclei_se.celery_task_id = nuclei_task.id
        if openvas_se:
            openvas_se.celery_task_id = openvas_task.id

        db.session.commit()


# ---------------------------------------------------------------------------
# Nuclei sub-task
# ---------------------------------------------------------------------------

@celery.task
def run_nuclei_engine(scan_id, asset_ids):
    """
    Runs Nuclei against all scan targets independently.
    All exceptions are caught and recorded — never re-raised.
    """
    from app import create_app, db
    from models import ScanEngine, Finding, Asset

    app = create_app()
    with app.app_context():
        se = ScanEngine.query.filter_by(scan_id=scan_id, engine='nuclei').first()
        if not se:
            return

        se.status = 'running'
        se.started_at = datetime.utcnow()
        se.progress = 'Initializing Nuclei...'
        se.progress_pct = 5
        db.session.commit()

        try:
            for asset_id in asset_ids:
                asset = Asset.query.get(asset_id)
                if not asset:
                    continue

                target = asset.ip_address or asset.hostname
                if not target:
                    continue

                _validate_target(target)
                _run_nuclei_scan(scan_id, asset_id, target, se, db, Finding)

            se.status = 'completed'
            se.progress = 'Nuclei scan completed'
            se.progress_pct = 100

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"[Nuclei] Scan {scan_id} failed:\n{error_trace}")
            se.status = 'failed'
            se.error_message = f"{str(e)}\n\nTraceback:\n{error_trace}"
            se.progress = 'Failed'

        finally:
            se.finished_at = datetime.utcnow()
            db.session.commit()
            _update_scan_status(scan_id, db)


# ---------------------------------------------------------------------------
# OpenVAS sub-task
# ---------------------------------------------------------------------------

@celery.task
def run_openvas_engine(scan_id, asset_ids):
    """
    Runs OpenVAS against all scan targets independently.
    All exceptions are caught and recorded — never re-raised.
    """
    from app import create_app, db
    from models import ScanEngine, Finding, Asset

    app = create_app()
    with app.app_context():
        se = ScanEngine.query.filter_by(scan_id=scan_id, engine='openvas').first()
        if not se:
            return

        se.status = 'running'
        se.started_at = datetime.utcnow()
        se.progress = 'Initializing OpenVAS...'
        se.progress_pct = 5
        db.session.commit()

        try:
            for asset_id in asset_ids:
                asset = Asset.query.get(asset_id)
                if not asset:
                    continue

                target = asset.ip_address or asset.hostname
                if not target:
                    continue

                _validate_target(target)
                _run_openvas_scan(scan_id, asset_id, target, se, db, Finding)

            se.status = 'completed'
            se.progress = 'OpenVAS scan completed'
            se.progress_pct = 100

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"[OpenVAS] Scan {scan_id} failed:\n{error_trace}")
            se.status = 'failed'
            se.error_message = f"{str(e)}\n\nTraceback:\n{error_trace}"
            se.progress = 'Failed'

        finally:
            se.finished_at = datetime.utcnow()
            db.session.commit()
            _update_scan_status(scan_id, db)


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _validate_target(target):
    """Raise if target is unresolvable. Shared by both engines."""
    import socket
    import ipaddress
    try:
        ipaddress.ip_address(target)
    except ValueError:
        try:
            socket.gethostbyname(target)
        except socket.gaierror:
            raise Exception(f"Target '{target}' is unresolvable via DNS. Scan aborted.")


def _update_scan_status(scan_id, db):
    """
    Recomputes and writes Scan.status based on all ScanEngine rows.
    Called by each engine sub-task when it finishes.

    Rules:
      - all queued          → queued
      - any running/queued  → running
      - all finished (completed or failed) → completed
    """
    from models import Scan, ScanEngine
    scan = Scan.query.get(scan_id)
    if not scan:
        return

    engines = ScanEngine.query.filter_by(scan_id=scan_id).all()
    if not engines:
        return

    statuses = {e.status for e in engines}
    terminal = {'completed', 'failed'}

    if statuses <= {'queued'}:
        scan.status = 'queued'
    elif all(s in terminal for s in statuses):
        scan.status = 'completed'
        scan.end_time = datetime.utcnow()
    else:
        scan.status = 'running'

    db.session.commit()


def _resolve_nuclei_binary():
    import shutil
    exe = shutil.which('nuclei') or shutil.which('nuclei.exe')
    if not exe:
        return 'nuclei'
    head = os.path.dirname(exe)
    if os.path.basename(head).lower() == 'shims':
        candidate = os.path.join(head, 'apps', 'nuclei', 'current', 'nuclei.exe')
        if os.path.isfile(candidate):
            return candidate
    return exe


def _run_nuclei_scan(scan_id, asset_id, target, se, db, Finding):
    """Run Nuclei CLI against one target; write findings. Updates `se` (ScanEngine row)."""
    se.progress = f"Running Nuclei on {target}..."
    se.progress_pct = 20
    db.session.commit()

    cmd = [
        _resolve_nuclei_binary(),
        '-u', target,
        '-tags', 'cve,misconfig',
        '-severity', 'critical,high,medium',
        '-j',
        '-silent'
    ]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=600
        )

        if result.returncode != 0:
            raise Exception(f"Nuclei exited with code {result.returncode}:\n{result.stdout}")

        se.progress = f"Parsing Nuclei results for {target}..."
        se.progress_pct = 80
        db.session.commit()

        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                info = data.get('info', {})
                severity_raw = info.get('severity', 'informational').title()

                if severity_raw in ['Critical', 'High', 'Medium', 'Low']:
                    severity = severity_raw
                else:
                    severity = 'Informational'

                finding = Finding(
                    scan_id=scan_id,
                    asset_id=asset_id,
                    engine='nuclei',
                    severity=severity,
                    cve=info.get('classification', {}).get('cve-id', ''),
                    description=info.get('description') or info.get('name') or 'Nuclei finding',
                    recommendation=info.get('remediation', '')
                )
                db.session.add(finding)
            except json.JSONDecodeError:
                pass

        db.session.commit()

    except subprocess.TimeoutExpired as e:
        raise Exception(f"Nuclei scan timed out for {target}") from e


def _run_openvas_scan(scan_id, asset_id, target, se, db, Finding):
    """
    Run OpenVAS against one target via GMP socket; write findings.
    Updates `se` (ScanEngine row). Raises on any failure.
    """
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform

    socket_path = "/run/gvmd/gvmd.sock"
    max_wait = 900

    # Wait for socket file
    waited = 0
    while not os.path.exists(socket_path) and waited < max_wait:
        time.sleep(10)
        waited += 10
        se.progress = f"Waiting for OpenVAS socket ({waited}/{max_wait}s)..."
        db.session.commit()

    if not os.path.exists(socket_path):
        raise Exception(f"OpenVAS socket not found at {socket_path} after {max_wait}s.")

    # Wait until socket accepts connections
    connection = UnixSocketConnection(path=socket_path)
    connected = False
    connect_wait = 0
    while not connected and connect_wait < 900:
        try:
            connection.connect()
            connection.disconnect()
            connected = True
        except Exception:
            time.sleep(10)
            connect_wait += 10
            se.progress = f"Waiting for OpenVAS connection ({connect_wait}/900s)..."
            db.session.commit()

    if not connected:
        raise Exception("Could not connect to OpenVAS socket after 900s.")

    transform = EtreeTransform()

    try:
        from gvm.protocols.gmp.requests.v224 import AliveTest
    except ImportError:
        AliveTest = None

    with Gmp(connection=UnixSocketConnection(path=socket_path), transform=transform) as gmp:
        gmp.authenticate('admin', 'admin')

        # Port list
        res = gmp.get_port_lists(filter_string="name=All IANA assigned TCP")
        port_lists = res.xpath('port_list/@id')
        if not port_lists:
            raise Exception("OpenVAS: port list 'All IANA assigned TCP' not found.")
        port_list_id = port_lists[0]

        # Scan config
        res = gmp.get_scan_configs(filter_string="name=Base")
        configs = res.xpath('config/@id')
        if not configs:
            raise Exception("OpenVAS: scan config 'Base' not found.")
        config_id = configs[0]

        # Scanner
        res = gmp.get_scanners(filter_string="name=CVE")
        scanners = res.xpath('scanner/@id')
        if not scanners:
            raise Exception("OpenVAS: scanner 'CVE' not found.")
        scanner_id = scanners[0]

        se.progress = f"Creating OpenVAS target {target}..."
        se.progress_pct = 10
        db.session.commit()

        # Create target
        alive_test = AliveTest.SCAN_CONFIG_DEFAULT if AliveTest else None
        kwargs = dict(name=f"Target-{target}-{scan_id}", hosts=[target], port_list_id=port_list_id)
        if alive_test is not None:
            kwargs['alive_test'] = alive_test
        res = gmp.create_target(**kwargs)
        if res.get('status') != '201':
            raise Exception(f"OpenVAS create_target failed: {res.get('status_text')}")
        target_id = res.xpath('//@id')[0]

        se.progress = "Creating OpenVAS task..."
        se.progress_pct = 15
        db.session.commit()

        # Create task
        res = gmp.create_task(
            name=f"Task-{target}-{scan_id}",
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id
        )
        if res.get('status') != '201':
            raise Exception(f"OpenVAS create_task failed: {res.get('status_text')}")
        task_id = res.xpath('//@id')[0]

        se.openvas_task_id = task_id
        db.session.commit()

        # Start task
        res = gmp.start_task(task_id)
        if res.get('status') != '202':
            raise Exception(f"OpenVAS start_task failed: {res.get('status_text')}")
        report_id = res.xpath('//report_id')[0].text

        se.progress = "Polling OpenVAS task..."
        se.progress_pct = 20
        db.session.commit()

        # Poll until done
        while True:
            task = gmp.get_task(task_id)
            status = task.xpath('//status')[0].text

            progress_node = task.xpath('//progress')
            if progress_node and progress_node[0].text and progress_node[0].text.isdigit():
                val = int(progress_node[0].text)
                if val > 0:
                    se.progress_pct = min(99, max(20, val))
                    db.session.commit()

            if status in ['Done', 'Stopped']:
                break
            elif status in ['Interrupted', 'Failed', 'Error']:
                raise Exception(f"OpenVAS task ended with status: {status}")
            time.sleep(10)

        se.progress = "Parsing OpenVAS results..."
        se.progress_pct = 99
        db.session.commit()

        results = gmp.get_results(filter_string=f"report_id={report_id}")
        report_xml = gmp.get_report(report_id)

        host_node = report_xml.xpath('//report/report/host')
        if not host_node and not results.xpath('//result'):
            raise Exception(f"OpenVAS: target '{target}' was considered dead or unreachable.")

        for result in results.xpath('//result'):
            severity_node = result.find('threat')
            severity = severity_node.text if severity_node is not None else 'Informational'
            if severity == 'Log':
                severity = 'Informational'

            desc_node = result.find('description')
            desc = desc_node.text if desc_node is not None else ''

            cve = ''
            nvt = result.find('nvt')
            if nvt is not None:
                cve_node = nvt.find('cve')
                if cve_node is not None and cve_node.text != 'NOCVE':
                    cve = cve_node.text

            finding = Finding(
                scan_id=scan_id,
                asset_id=asset_id,
                engine='openvas',
                severity=severity,
                cve=cve,
                description=desc.strip(),
                recommendation=''
            )
            db.session.add(finding)

        db.session.commit()
