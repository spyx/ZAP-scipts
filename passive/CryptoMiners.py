"""
Passive scan rules should not make any requests.

Note that new passive scripts will initially be disabled
Right click the script in the Scripts tree and select "enable"
"""  

from org.zaproxy.zap.extension.pscan import PluginPassiveScanner;

SOURCES = '/home/kali/.ZAP/scripts/scripts/passive/sources.txt'
with open(SOURCES) as f:
  sources = [s.strip() for s in f]

def appliesToHistoryType(historyType):
    """Tells whether or not the scanner applies to the given history type.

    Args:
        historyType (int): The type (ID) of the message to be scanned.

    Returns:
        True to scan the message, False otherwise.

    """
    return PluginPassiveScanner.getDefaultHistoryTypes().contains(historyType);


def scan(ps, msg, src):
  """Passively scans the message sent/received through ZAP.

  Args:
    ps (ScriptsPassiveScanner): The helper class to raise alerts and add tags to the message.
    msg (HttpMessage): The HTTP message being scanned.
    src (Source): The HTML source of the message (if any). 

  """
  uri = msg.getRequestHeader().getURI().toString()
  body = msg.getResponseBody().toString()
  for source in sources:
    if source in body:
      print 'alert!!!'
      ps.raiseAlert(0, 2, 'Cryptocurrency mining script detected (cryptojacking)', 'Scripts were included from the following cryptocurrency mining domain: " + source', 
      msg.getRequestHeader().getURI().toString(), 
      None, None, 'The web browsers of visitors to the website could be used to mine cryptocurrency without their knowledge.', 'Avoid using scripts from cryptocurrency mining domains. Cryptocurrency mining scripts are often added to a web page during a website compromise. Investigate whether unauthorised changes have been made to the web application.', '', 0, 0, msg);
  