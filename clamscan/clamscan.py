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
            'type': 'integer',
            'description': 'ClamAV port',
            'default': None
        }
    ]

    _clam = None
    _tag = 'malware'
    _MALWARE_KEYWORD = 'Malware Signature'

    def initialize(self):
        if not HAVE_CLAMD:
            raise ModuleInitializationError(self, "Missing dependency: pyclamd")


    def each(self, target):
        self.results = {
            'analysis': []
        }

        if self._clam is None:
            if len(self.filename) > 0:
                self._clam = pyclamd.ClamdUnixSocket(filename=self.filename)
            elif len(self.server) > 0 and self.port > 0:
                try:
                    self._clam = pyclamd.ClamdNetworkSocket(host=self.server,port=self.port)
                except:
                    return False
            else:
                return False

            if not self._clam.ping():
                return False

        res = None
	with open(target) as f:
            res = self._clam.scan_stream(f.read())
        if not res:
            return False

        status,name = res['stream']
        self.add_tag(self._tag)
        self.results['analysis'].append((self._MALWARE_KEYWORD,name))
        self.add_probable_name(name)

        return True
