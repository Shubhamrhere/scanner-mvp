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
        
        # Get port lists
        res = gmp.get_port_lists()
        
        print("Port Lists:")
        xml_str = etree.tostring(res, pretty_print=True).decode('utf-8')
        print(xml_str)
        
except Exception as e:
    print(f"Error: {e}")
