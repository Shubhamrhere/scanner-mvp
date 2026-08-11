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
        
        try:
            for asset_id in asset_ids:
                asset = Asset.query.get(asset_id)
                if not asset:
                    continue
                
                target = asset.ip_address or asset.hostname
                if not target:
                    continue
                    
                if scan_type == 'external':
                    # Route to OpenVAS API
                    _run_openvas_scan(scan, asset_id, target, db, Finding)
                else:
                    # Route to Nuclei CLI
                    _run_nuclei_scan(scan, asset_id, target, db, Finding)
                    
            scan.progress_percent = 100
            scan.progress = 'Completed'
            scan.status = 'completed'
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"Error executing scan {scan_id}:\n{error_trace}")
            scan.status = 'failed'
            scan.error_message = f"{str(e)}\n\nTraceback:\n{error_trace}"
            scan.progress = 'Failed'
        finally:
            # Check findings
            if scan.status == 'completed' and not scan.findings:
                scan.progress = 'Completed successfully (0 vulnerabilities found)'
            
            scan.end_time = datetime.utcnow()
            db.session.commit()

def _run_nuclei_scan(scan, asset_id, target, db, Finding):
    scan.progress = f"Running Nuclei on {target}..."
    scan.progress_percent = 20
    db.session.commit()
    
    cmd = [
        'nuclei',
        '-u', target,
        '-tags', 'cve,misconfig',
        '-severity', 'critical,high,medium',
        '-j', 
        '-silent'
    ]
    
    try:
        # Use stderr=subprocess.STDOUT to capture all output
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)
        
        if result.returncode != 0:
            raise Exception(f"Nuclei exited with code {result.returncode}:\n{result.stdout}")
            
        scan.progress = f"Parsing Nuclei results for {target}..."
        scan.progress_percent = 80
        db.session.commit()
        
        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                info = data.get('info', {})
                severity_raw = info.get('severity', 'informational').title()
                
                # Normalize severity
                if severity_raw in ['Critical', 'High', 'Medium', 'Low']:
                    severity = severity_raw
                else:
                    severity = 'Informational'
                    
                finding = Finding(
                    scan_id=scan.id,
                    asset_id=asset_id,
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
        print(f"Nuclei scan timed out for {target}")
        raise e
    except Exception as e:
        print(f"Nuclei error: {e}")
        raise e

def _run_openvas_scan(scan, asset_id, target, db, Finding):
    from gvm.connections import UnixSocketConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    scan.progress = f"Connecting to OpenVAS for {target}..."
    db.session.commit()
    
    # Wait for OpenVAS socket to be ready (up to 15 minutes)
    socket_path = "/run/gvmd/gvmd.sock"
    max_wait = 900
    waited = 0
    while not os.path.exists(socket_path) and waited < max_wait:
        time.sleep(10)
        waited += 10
        scan.progress = f"Waiting for OpenVAS to initialize ({waited}/{max_wait}s)..."
        db.session.commit()
        
    if not os.path.exists(socket_path):
        raise Exception(f"OpenVAS socket not found at {socket_path} after {max_wait} seconds.")
        
    # We attempt to connect to OpenVAS container locally
    try:
        from gvm.protocols.gmp.requests.v224 import AliveTest
        connection = UnixSocketConnection(path=socket_path)
        
        # Wait until the connection is actually accepted
        connected = False
        connect_wait = 0
        while not connected and connect_wait < 900:
            try:
                connection.connect()
                connection.disconnect()
                connected = True
            except Exception as e:
                time.sleep(10)
                connect_wait += 10
                scan.progress = f"Waiting for OpenVAS connection ({connect_wait}/900s)..."
                db.session.commit()
                
        if not connected:
            raise Exception(f"Could not connect to OpenVAS socket after 900 seconds.")

        transform = EtreeTransform()
        
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate('admin', 'admin')
            
            scan.progress = f"Creating OpenVAS target {target}..."
            scan.progress_percent = 10
            db.session.commit()
            
            # Create target (Consider Alive to bypass ping failures)
            res = gmp.create_target(name=f"Target-{target}-{scan.id}", hosts=[target], alive_test=AliveTest.CONSIDER_ALIVE)
            target_id = res.xpath('//@id')[0]
            
            # Find scan config ("Full and fast")
            configs = gmp.get_scan_configs()
            config_id = None
            for config in configs.xpath('//config'):
                if 'Full and fast' in config.find('name').text:
                    config_id = config.get('id')
                    break
            
            if not config_id:
                raise Exception("Scan config 'Full and fast' not found")
                
            scan.progress = f"Starting OpenVAS task..."
            db.session.commit()
                
            # Create task
            res = gmp.create_task(name=f"Task-{scan.id}", config_id=config_id, target_id=target_id)
            task_id = res.xpath('//@id')[0]
            
            scan.openvas_task_id = task_id
            db.session.commit()
            
            # Start task
            res = gmp.start_task(task_id)
            report_id = res.xpath('//report_id')[0].text
            
            scan.progress = f"Polling OpenVAS task..."
            scan.progress_percent = 20
            db.session.commit()
            
            # Poll status
            while True:
                task = gmp.get_task(task_id)
                status = task.xpath('//status')[0].text
                
                # Fetch progress
                progress_node = task.xpath('//progress')
                if progress_node and progress_node[0].text and progress_node[0].text.isdigit():
                    val = int(progress_node[0].text)
                    if val > 0:
                        scan.progress_percent = min(99, max(20, val))
                        db.session.commit()
                        
                if status in ['Done', 'Stopped']:
                    break
                elif status in ['Interrupted', 'Failed', 'Error']:
                    raise Exception(f"OpenVAS task failed with status: {status}")
                time.sleep(10)
                
            # Fetch results
            scan.progress = f"Parsing OpenVAS results..."
            scan.progress_percent = 100
            db.session.commit()
            
            results = gmp.get_results(filter_string=f"report_id={report_id}")
            for result in results.xpath('//result'):
                severity_node = result.find('threat')
                severity = severity_node.text if severity_node is not None else 'Informational'
                if severity == 'Log': severity = 'Informational'
                
                desc_node = result.find('description')
                desc = desc_node.text if desc_node is not None else ''
                
                cve = ''
                nvt = result.find('nvt')
                if nvt is not None:
                    cve_node = nvt.find('cve')
                    if cve_node is not None and cve_node.text != 'NOCVE':
                        cve = cve_node.text
                        
                finding = Finding(
                    scan_id=scan.id,
                    asset_id=asset_id,
                    severity=severity,
                    cve=cve,
                    description=desc.strip(),
                    recommendation=''
                )
                db.session.add(finding)
            
            db.session.commit()
    except Exception as e:
        print(f"OpenVAS integration error: {e}")
        raise e
