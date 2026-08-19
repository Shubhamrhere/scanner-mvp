import os
import json
import ipaddress
import subprocess
import time
from datetime import datetime
from urllib.parse import urlparse
from celery import Celery
from config import Config

# Initialize Celery app
celery = Celery(
    'tasks',
    broker=Config.CELERY_BROKER_URL,
    backend=Config.CELERY_RESULT_BACKEND
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Nuclei defaults
DEFAULT_NUCLEI_TAGS = 'cve,misconfig'
DEFAULT_NUCLEI_SEVERITY = 'critical,high,medium'
NUCLEI_TIMEOUT_SECONDS = 600

# OpenVAS integration defaults
OPENVAS_SOCKET_PATH = '/run/gvmd/gvmd.sock'
OPENVAS_CONNECT_TIMEOUT = 900
OPENVAS_POLL_TIMEOUT = 12 * 60 * 60  # 12h cap so polling never hangs forever


# ---------------------------------------------------------------------------
# Parent dispatch task
# ---------------------------------------------------------------------------

@celery.task
def execute_scan(scan_id, scan_type, asset_ids):
    """
    Parent task: creates two ScanEngine rows and launches Nuclei + OpenVAS
    as completely independent parallel sub-tasks. Returns immediately after
    dispatching — it does NOT wait for either engine to finish.

    Both External and Internal scan types use the same concurrent pattern:
    Nuclei handles web/hostname targets; OpenVAS handles IP/network targets.
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

        # Create one ScanEngine row per engine (idempotent)
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

        # Dispatch both sub-tasks independently — each manages its own DB state
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
    All exceptions are caught and recorded in the ScanEngine row — never re-raised.
    A failure here does NOT affect the OpenVAS engine.
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

                target = asset.hostname or asset.ip_address
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
    All exceptions are caught and recorded in the ScanEngine row — never re-raised.
    A failure here does NOT affect the Nuclei engine.
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


def _is_ip_target(target):
    host = str(target).strip()
    if '/' in host:
        try:
            ipaddress.ip_network(host, strict=False)
            return True
        except ValueError:
            return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _extract_host(target):
    """Return a bare host/IP from a target, stripping any URL scheme and path."""
    t = str(target or '').strip()
    if '://' not in t:
        return t
    try:
        parsed = urlparse(t)
        return parsed.hostname or t
    except ValueError:
        return t


def _build_nuclei_cmd(target, options=None):
    opts = options or {}
    tags = opts.get('tags') or DEFAULT_NUCLEI_TAGS
    if isinstance(tags, (list, tuple)):
        tags = ','.join(tags)
    severity = opts.get('severity') or DEFAULT_NUCLEI_SEVERITY
    if isinstance(severity, (list, tuple)):
        severity = ','.join(severity)
    return [
        _resolve_nuclei_binary(),
        '-u', target,
        '-tags', tags,
        '-severity', severity,
        '-j',
        '-silent',
    ]


# ---------------------------------------------------------------------------
# Nuclei scan implementation
# ---------------------------------------------------------------------------

def _run_nuclei_scan(scan_id, asset_id, target, se, db, Finding, options=None):
    """Run Nuclei CLI against one target; write findings. Updates `se` (ScanEngine row)."""
    from models import normalize_severity

    se.progress = f"Running Nuclei on {target}..."
    se.progress_pct = 20
    db.session.commit()

    cmd = _build_nuclei_cmd(target, options)

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=NUCLEI_TIMEOUT_SECONDS
        )

        if result.returncode != 0:
            raise Exception(f"Nuclei exited with code {result.returncode}:\n{result.stdout[:2000]}")

        se.progress = f"Parsing Nuclei results for {target}..."
        se.progress_pct = 80
        db.session.commit()

        count = 0
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue

            info = data.get('info', {})
            finding = Finding(
                scan_id=scan_id,
                asset_id=asset_id,
                engine='nuclei',
                severity=normalize_severity(info.get('severity')),
                cve=info.get('classification', {}).get('cve-id', ''),
                description=info.get('description') or info.get('name') or 'Nuclei finding',
                recommendation=info.get('remediation', ''),
            )
            db.session.add(finding)
            count += 1

        db.session.commit()
        se.progress = f"Nuclei completed for {target} ({count} findings)."
        se.progress_pct = 95
        db.session.commit()

    except subprocess.TimeoutExpired as e:
        db.session.rollback()
        raise Exception(f"Nuclei scan timed out for {target} after {NUCLEI_TIMEOUT_SECONDS}s.") from e
    except Exception:
        db.session.rollback()
        raise


# ---------------------------------------------------------------------------
# OpenVAS scan implementation (refactored into helpers)
# ---------------------------------------------------------------------------

def _run_openvas_scan(scan_id, asset_id, target, se, db, Finding):
    """
    Run OpenVAS against one target via GMP socket; write findings.
    Updates `se` (ScanEngine row). Raises on any failure.

    Uses:
      - AliveTest.SCAN_CONFIG_DEFAULT (real alive checks, not CONSIDER_ALIVE)
      - scanner = CVE
      - config  = Base
    """
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    try:
        from gvm.protocols.gmp.requests.v224 import AliveTest
    except ImportError:
        AliveTest = None

    _wait_for_openvas_socket(se, db)

    connection = UnixSocketConnection(path=OPENVAS_SOCKET_PATH)
    _wait_for_openvas_connection(connection, se, db)

    transform = EtreeTransform()

    with Gmp(connection=UnixSocketConnection(path=OPENVAS_SOCKET_PATH), transform=transform) as gmp:
        gmp.authenticate('admin', 'admin')

        port_list_id = _get_port_list_id(gmp)
        config_id    = _get_scan_config_id(gmp)
        scanner_id   = _get_scanner_id(gmp)

        se.progress = f"Creating OpenVAS target {target}..."
        se.progress_pct = 10
        db.session.commit()

        # Use SCAN_CONFIG_DEFAULT so OpenVAS performs real alive checks.
        # Never use CONSIDER_ALIVE — that bypasses the check and creates fake success states.
        kwargs = dict(
            name=f"Target-{target}-{scan_id}",
            hosts=[target],
            port_list_id=port_list_id,
        )
        if AliveTest is not None:
            kwargs['alive_test'] = AliveTest.SCAN_CONFIG_DEFAULT

        res = gmp.create_target(**kwargs)
        if res.get('status') != '201':
            raise Exception(f"OpenVAS create_target failed: {res.get('status_text')}")
        target_id = res.xpath('//@id')[0]

        se.progress = "Creating OpenVAS task..."
        se.progress_pct = 15
        db.session.commit()

        res = gmp.create_task(
            name=f"Task-{target}-{scan_id}",
            config_id=config_id,
            target_id=target_id,
            scanner_id=scanner_id,
        )
        if res.get('status') != '201':
            raise Exception(f"OpenVAS create_task failed: {res.get('status_text')}")
        task_id = res.xpath('//@id')[0]

        se.openvas_task_id = task_id
        db.session.commit()

        res = gmp.start_task(task_id)
        if res.get('status') != '202':
            raise Exception(f"OpenVAS start_task failed: {res.get('status_text')}")
        report_id = res.xpath('//report_id')[0].text

        se.progress = "Polling OpenVAS task..."
        se.progress_pct = 20
        db.session.commit()

        _poll_openvas_task(gmp, task_id, se, db)

        se.progress = "Parsing OpenVAS results..."
        se.progress_pct = 99
        db.session.commit()

        results   = gmp.get_results(filter_string=f"report_id={report_id}")
        report_xml = gmp.get_report(report_id)

        # Dead-host guard: if OpenVAS produced no host data AND no results,
        # the target was considered unreachable — fail truthfully.
        host_node = report_xml.xpath('//report/report/host')
        if not host_node and not results.xpath('//result'):
            raise Exception(f"OpenVAS: target '{target}' was considered dead or unreachable.")

        count = _save_openvas_results(results, scan_id, asset_id, Finding, db)
        db.session.commit()

        se.progress = f"OpenVAS completed for {target} ({count} findings)."
        se.progress_pct = 100
        db.session.commit()


def _wait_for_openvas_socket(se, db):
    waited = 0
    while not os.path.exists(OPENVAS_SOCKET_PATH) and waited < OPENVAS_CONNECT_TIMEOUT:
        time.sleep(10)
        waited += 10
        se.progress = f"Waiting for OpenVAS socket ({waited}/{OPENVAS_CONNECT_TIMEOUT}s)..."
        db.session.commit()
    if not os.path.exists(OPENVAS_SOCKET_PATH):
        raise Exception(
            f"OpenVAS socket not found at {OPENVAS_SOCKET_PATH} after {OPENVAS_CONNECT_TIMEOUT} seconds."
        )


def _wait_for_openvas_connection(connection, se, db):
    connected = False
    waited = 0
    while not connected and waited < OPENVAS_CONNECT_TIMEOUT:
        try:
            connection.connect()
            connection.disconnect()
            connected = True
        except Exception:
            time.sleep(10)
            waited += 10
            se.progress = f"Waiting for OpenVAS connection ({waited}/{OPENVAS_CONNECT_TIMEOUT}s)..."
            db.session.commit()
    if not connected:
        raise Exception(f"Could not connect to OpenVAS socket after {OPENVAS_CONNECT_TIMEOUT} seconds.")


def _get_port_list_id(gmp):
    res = gmp.get_port_lists(filter_string="name=All IANA assigned TCP")
    ids = res.xpath('port_list/@id')
    if not ids:
        raise Exception("OpenVAS Error: Could not find port list 'All IANA assigned TCP'")
    return ids[0]


def _get_scan_config_id(gmp):
    # Use 'Base' config as confirmed working on main.
    # nuclei_integration used 'Full and fast' — keeping HEAD's 'Base' (proven stable).
    # FLAG: if you want to switch to 'Full and fast' for broader NVT coverage,
    # change this filter_string and confirm it exists in your OpenVAS instance.
    res = gmp.get_scan_configs(filter_string="name=Base")
    ids = res.xpath('config/@id')
    if not ids:
        raise Exception("OpenVAS Error: Could not find scan config 'Base'")
    return ids[0]


def _get_scanner_id(gmp):
    # Use 'CVE' scanner as confirmed working on main.
    # nuclei_integration used 'OpenVAS Default' — keeping HEAD's 'CVE' (proven stable).
    # FLAG: if you want to switch to 'OpenVAS Default' for live NVT scanning,
    # change this filter_string and confirm it exists in your OpenVAS instance.
    res = gmp.get_scanners(filter_string="name=CVE")
    ids = res.xpath('scanner/@id')
    if not ids:
        raise Exception("OpenVAS Error: Could not find scanner 'CVE'")
    return ids[0]


def _poll_openvas_task(gmp, task_id, se, db):
    deadline = time.time() + OPENVAS_POLL_TIMEOUT
    while True:
        task = gmp.get_task(task_id)
        status = task.xpath('//status')[0].text

        progress_node = task.xpath('//progress')
        if progress_node and progress_node[0].text and progress_node[0].text.isdigit():
            val = int(progress_node[0].text)
            if val > 0:
                se.progress_pct = min(99, max(20, val))
                db.session.commit()

        if status in ('Done', 'Stopped'):
            return
        if status in ('Interrupted', 'Failed', 'Error'):
            raise Exception(f"OpenVAS task ended with status: {status}")
        if time.time() > deadline:
            raise Exception(
                f"OpenVAS task timed out after {OPENVAS_POLL_TIMEOUT}s (status: {status})."
            )
        time.sleep(10)


def _save_openvas_results(results, scan_id, asset_id, Finding, db):
    from models import normalize_severity
    count = 0
    for result in results.xpath('//result'):
        severity_node = result.find('threat')
        severity = normalize_severity(severity_node.text if severity_node is not None else '')

        desc_node = result.find('description')
        desc = desc_node.text if desc_node is not None else ''

        cve = ''
        nvt = result.find('nvt')
        if nvt is not None:
            cve_node = nvt.find('cve')
            if cve_node is not None and cve_node.text and cve_node.text != 'NOCVE':
                cve = cve_node.text

        finding = Finding(
            scan_id=scan_id,
            asset_id=asset_id,
            engine='openvas',
            severity=severity,
            cve=cve,
            description=desc.strip(),
            recommendation='',
        )
        db.session.add(finding)
        count += 1
    return count
