from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError

try:
    import pyclamd

    HAVE_CLAMD = True
except:
    HAVE_CLAMD = False

class Clamscan(ProcessingModule):
    name = "clamscan"
    description = "Scan files with ClamAV"

    config = [
        {
            'name': 'filename',
            'type': 'str',
            'description': 'UNIX socket file path',
            'default': '/var/run/clamav/clamd.ctl'
        },
        {
            'name': 'server',
            'type': 'str',
            'description': 'ClamAV server',
            'default': None
        },
        {
            'name': 'port',
            'type': 'str',
            'description': 'ClamAV port',
            'default': None
        }
    ]

    _clam = None
    _tag = 'malware'

    def initialize(self):
        if not HAVE_CLAMD:
            raise ModuleInitializationError(self, "Missing dependency: pyclamd")


    def each(self, target):
        if self._clam is None:
            if len(self.filename) > 0:
                self._clam = pyclamd.ClamdUnixSocket(filename=self.filename)
            elif len(self.server) > 0 and len(self.port) > 0:
                try:
                    host = self.server.strip()
                    port = int(self.port.strip())
                    self._clam = pyclamd.ClamdNetworkSocket(host=host,port=port)
                except:
                    return False
            else:
                return False

            if not self._clam.ping():
                return False

        res = self._clam.scan_file(target)
        if not res:
            return True

        status,name = res['stream']
        self.add_tag(self._tag)
        self.results = {'signature': [name]}

        return True
