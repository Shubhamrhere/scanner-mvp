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

# Nuclei defaults (overridable per-scan via scan options)
DEFAULT_NUCLEI_TAGS = 'dast,sqli,xss,exposure,misconfig,cve'
DEFAULT_NUCLEI_SEVERITY = 'critical,high,medium,low'
NUCLEI_TIMEOUT_SECONDS = 600

# OpenVAS integration defaults
OPENVAS_SOCKET_PATH = '/run/gvmd/gvmd.sock'
OPENVAS_CONNECT_TIMEOUT = 900
OPENVAS_POLL_TIMEOUT = 12 * 60 * 60  # 12h cap so polling never hangs forever

VALID_SEVERITIES = ('critical', 'high', 'medium', 'low')


@celery.task
def execute_scan(scan_id, scan_type, asset_ids):
    from app import create_app, db
    from models import Scan, Finding, Asset

    app = create_app()
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        scan.status = 'running'
        scan.progress = 'Initializing scan...'
        scan.progress_percent = 5
        scan.start_time = datetime.utcnow()
        db.session.commit()

        errors = []
        try:
            for asset_id in asset_ids:
                asset = Asset.query.get(asset_id)
                if not asset:
                    continue

                # Scan both fields when present: hostname -> Nuclei,
                # IP/subnet -> OpenVAS. Dedupe identical targets.
                targets = _collect_targets(asset)
                if not targets:
                    continue

                for target in targets:
                    try:
                        if _is_ip_target(target):
                            _run_openvas_scan(scan, asset_id, _extract_host(target), db, Finding)
                        else:
                            _run_nuclei_scan(scan, asset_id, target, db, Finding)
                    except Exception as e:
                        errors.append(f"{target}: {e}")
                        scan.status = 'failed'
                        scan.progress = 'Failed'
                        scan.error_message = "\n".join(errors)
                        db.session.commit()

            if not errors:
                scan.progress_percent = 100
                scan.progress = 'Completed'
                scan.status = 'completed'
                db.session.commit()
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"Error executing scan {scan_id}:\n{error_trace}")
            scan.status = 'failed'
            scan.error_message = f"{str(e)}\n\nTraceback:\n{error_trace}"
            scan.progress = 'Failed'
        finally:
            if scan.status == 'completed' and not scan.findings:
                scan.progress = 'Completed successfully (0 vulnerabilities found)'

            scan.end_time = datetime.utcnow()
            db.session.commit()


# ---------------------------------------------------------------- helpers

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


def _collect_targets(asset):
    targets = []
    for t in (asset.ip_address, asset.hostname):
        if t and str(t).strip() and str(t) not in targets:
            targets.append(str(t))
    return targets


def _normalize_severity(severity):
    """Map any raw severity string to a canonical lowercase value."""
    s = str(severity or '').strip().lower()
    if s in VALID_SEVERITIES:
        return s
    return 'info'


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


# ---------------------------------------------------------------- Nuclei

def _run_nuclei_scan(scan, asset_id, target, db, Finding, options=None):
    target = str(target or '').strip()
    scan.progress = f"Running Nuclei on {target}..."
    scan.progress_percent = 20
    db.session.commit()

    cmd = _build_nuclei_cmd(target, options)

    try:
        result = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, timeout=NUCLEI_TIMEOUT_SECONDS
        )

        if result.returncode != 0:
            raise Exception(
                f"Nuclei exited with code {result.returncode}:\n{result.stdout[:2000]}"
            )

        scan.progress = f"Parsing Nuclei results for {target}..."
        scan.progress_percent = 80
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
                scan_id=scan.id,
                asset_id=asset_id,
                severity=_normalize_severity(info.get('severity')),
                cve=info.get('classification', {}).get('cve-id', ''),
                description=info.get('description') or info.get('name') or 'Nuclei finding',
                recommendation=info.get('remediation', ''),
            )
            db.session.add(finding)
            count += 1

        db.session.commit()
        scan.progress = f"Nuclei completed for {target} ({count} findings)."
        scan.progress_percent = 85
        db.session.commit()
    except subprocess.TimeoutExpired as e:
        db.session.rollback()
        print(f"Nuclei scan timed out for {target}")
        raise Exception(
            f"Nuclei scan timed out for {target} after {NUCLEI_TIMEOUT_SECONDS}s."
        ) from e
    except Exception as e:
        db.session.rollback()
        print(f"Nuclei error: {e}")
        raise


# ---------------------------------------------------------------- OpenVAS

def _run_openvas_scan(scan, asset_id, target, db, Finding):
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.protocols.gmp.requests.v224 import AliveTest
    from gvm.transforms import EtreeTransform

    if not scan:
        raise Exception("Scan record not found.")

    host = _extract_host(target)
    scan.progress = f"Connecting to OpenVAS for {host}..."
    db.session.commit()

    try:
        _wait_for_openvas_socket(scan, db)

        connection = UnixSocketConnection(path=OPENVAS_SOCKET_PATH)
        _wait_for_openvas_connection(connection, scan, db)

        transform = EtreeTransform()
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate('admin', 'admin')

            # Comprehensive NVT config + local scanner.
            port_list_id = _get_port_list_id(gmp)
            config_id = _get_scan_config_id(gmp)
            scanner_id = _get_scanner_id(gmp)

            scan.progress = f"Creating OpenVAS target {host}..."
            scan.progress_percent = 10
            db.session.commit()

            res = gmp.create_target(
                name=f"Target-{host}-{scan.id}",
                hosts=[host],
                port_list_id=port_list_id,
                alive_test=AliveTest.CONSIDER_ALIVE,
            )
            if res.get('status') != '201':
                raise Exception(f"OpenVAS Error creating target: {res.get('status_text')}")
            target_id = res.xpath('//@id')[0]

            scan.progress = "Creating OpenVAS task..."
            scan.progress_percent = 15
            db.session.commit()

            res = gmp.create_task(
                name=f"Task-{host}-{scan.id}",
                config_id=config_id,
                target_id=target_id,
                scanner_id=scanner_id,
            )
            if res.get('status') != '201':
                raise Exception(f"OpenVAS Error creating task: {res.get('status_text')}")
            task_id = res.xpath('//@id')[0]
            scan.openvas_task_id = task_id
            db.session.commit()

            res = gmp.start_task(task_id)
            if res.get('status') != '202':
                raise Exception(f"OpenVAS Error starting task: {res.get('status_text')}")
            report_id = res.xpath('//report_id')[0].text

            scan.progress = "Polling OpenVAS task..."
            scan.progress_percent = 20
            db.session.commit()

            _poll_openvas_task(gmp, task_id, scan, db)

            scan.progress = "Parsing OpenVAS results..."
            db.session.commit()

            results = gmp.get_results(filter_string=f"report_id={report_id}")
            count = _save_openvas_results(results, scan, asset_id, Finding)

            db.session.commit()
            scan.progress = f"OpenVAS completed for {host} ({count} findings)."
            scan.progress_percent = 100
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"OpenVAS integration error: {e}")
        raise


def _wait_for_openvas_socket(scan, db):
    waited = 0
    while not os.path.exists(OPENVAS_SOCKET_PATH) and waited < OPENVAS_CONNECT_TIMEOUT:
        time.sleep(10)
        waited += 10
        scan.progress = f"Waiting for OpenVAS to initialize ({waited}/{OPENVAS_CONNECT_TIMEOUT}s)..."
        db.session.commit()
    if not os.path.exists(OPENVAS_SOCKET_PATH):
        raise Exception(
            f"OpenVAS socket not found at {OPENVAS_SOCKET_PATH} after {OPENVAS_CONNECT_TIMEOUT} seconds."
        )


def _wait_for_openvas_connection(connection, scan, db):
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
            scan.progress = f"Waiting for OpenVAS connection ({waited}/{OPENVAS_CONNECT_TIMEOUT}s)..."
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
    res = gmp.get_scan_configs(filter_string='name="Full and fast"')
    ids = res.xpath('config/@id')
    if not ids:
        raise Exception("OpenVAS Error: Could not find scan config 'Full and fast'")
    return ids[0]


def _get_scanner_id(gmp):
    res = gmp.get_scanners(filter_string="name=OpenVAS Default")
    ids = res.xpath('scanner/@id')
    if not ids:
        raise Exception("OpenVAS Error: Could not find scanner 'OpenVAS Default'")
    return ids[0]


def _poll_openvas_task(gmp, task_id, scan, db):
    deadline = time.time() + OPENVAS_POLL_TIMEOUT
    while True:
        task = gmp.get_task(task_id)
        status = task.xpath('//status')[0].text

        progress_node = task.xpath('//progress')
        if progress_node and progress_node[0].text and progress_node[0].text.isdigit():
            val = int(progress_node[0].text)
            if val > 0:
                scan.progress_percent = min(99, max(20, val))
                db.session.commit()

        if status in ('Done', 'Stopped'):
            return
        if status in ('Interrupted', 'Failed', 'Error'):
            raise Exception(f"OpenVAS task failed with status: {status}")
        if time.time() > deadline:
            raise Exception(
                f"OpenVAS task timed out after {OPENVAS_POLL_TIMEOUT}s (status: {status})."
            )
        time.sleep(10)


def _save_openvas_results(results, scan, asset_id, Finding):
    count = 0
    for result in results.xpath('//result'):
        severity_node = result.find('threat')
        severity = _normalize_severity(severity_node.text if severity_node is not None else '')

        desc_node = result.find('description')
        desc = desc_node.text if desc_node is not None else ''

        cve = ''
        nvt = result.find('nvt')
        if nvt is not None:
            cve_node = nvt.find('cve')
            if cve_node is not None and cve_node.text and cve_node.text != 'NOCVE':
                cve = cve_node.text

        finding = Finding(
            scan_id=scan.id,
            asset_id=asset_id,
            severity=severity,
            cve=cve,
            description=desc.strip(),
            recommendation='',
        )
        db.session.add(finding)
        count += 1
    return count
