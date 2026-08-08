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
                    _run_openvas_scan(scan_id, asset_id, target, db, Finding)
                else:
                    # Route to Nuclei CLI
                    _run_nuclei_scan(scan_id, asset_id, target, db, Finding)
                    
            scan.status = 'completed'
        except Exception as e:
            print(f"Error executing scan {scan_id}: {e}")
            scan.status = 'failed'
        finally:
            scan.end_time = datetime.utcnow()
            db.session.commit()

def _run_nuclei_scan(scan_id, asset_id, target, db, Finding):
    cmd = [
        'nuclei',
        '-u', target,
        '-j', 
        '-silent'
    ]
    
    try:
        # Run subprocess (timeout at 10 minutes)
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        
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
                    scan_id=scan_id,
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
    except subprocess.TimeoutExpired:
        print(f"Nuclei scan timed out for {target}")
    except Exception as e:
        print(f"Nuclei error: {e}")

def _run_openvas_scan(scan_id, asset_id, target, db, Finding):
    from gvm.connections import TLSConnection
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    
    # We attempt to connect to OpenVAS container locally
    try:
        connection = TLSConnection(hostname='openvas', port=9390)
        transform = EtreeTransform()
        
        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate('admin', 'admin')
            
            # Create target
            res = gmp.create_target(name=f"Target-{target}", hosts=[target])
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
                
            # Create task
            res = gmp.create_task(name=f"Task-{scan_id}", config_id=config_id, target_id=target_id)
            task_id = res.xpath('//@id')[0]
            
            # Start task
            res = gmp.start_task(task_id)
            report_id = res.xpath('//report_id')[0].text
            
            # Poll status
            while True:
                task = gmp.get_task(task_id)
                status = task.xpath('//status')[0].text
                if status in ['Done', 'Stopped']:
                    break
                time.sleep(10)
                
            # Fetch results
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
                    scan_id=scan_id,
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
