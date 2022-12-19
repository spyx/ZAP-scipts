"""
Targeted scripts can only be invoked by you, the user, e.g. via a right-click option on the Sites or History tabs
"""

import socket
from org.zaproxy.zap.utils.DesktopUtils import openUrlInBrowser

def invokeWith(msg):
  # Debugging can be done using print like this
  print('invokeWith called for url=' + msg.getRequestHeader().getURI().toString()); 
  hostname = msg.getRequestHeader().getURI().getHost();
  IPAddr=socket.gethostbyname(hostname)
  print('hostname: ' + IPAddr )
  openUrlInBrowser('https://search.censys.io/hosts/' + IPAddr)

  
