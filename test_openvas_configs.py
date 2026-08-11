import os
from gvm.connections import UnixSocketConnection
from gvm.protocols.gmp import Gmp
from gvm.transforms import EtreeTransform
from lxml import etree

socket_path = "/run/gvmd/gvmd.sock"
try:
    connection = UnixSocketConnection(path=socket_path)
    transform = EtreeTransform()
    
    with Gmp(connection=connection, transform=transform) as gmp:
        gmp.authenticate('admin', 'admin')
        
        print("Configs:")
        res = gmp.get_scan_configs()
        print(etree.tostring(res, pretty_print=True).decode('utf-8')[:500])
        
        print("Scanners:")
        res = gmp.get_scanners()
        print(etree.tostring(res, pretty_print=True).decode('utf-8')[:500])
        
except Exception as e:
    print(f"Error: {e}")
