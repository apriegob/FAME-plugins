import hashlib
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from fame.common.utils import tempdir

try:
    import requests
    HAVE_REQUESTS = True
except:
    HAVE_REQUESTS = False

class ReverseIT(ProcessingModule):
    name = "reverseit_check"
    description = "Check file hash with Payload Security"

    config = [
        {
            'name': 'API',
            'type': 'str',
            'description': 'API Key'
        },
        {
            'name': 'Secret',
            'type': 'str',
            'description': 'API Secret'
        },
        {
            'name': 'URL',
            'type': 'str',
            'description': 'API URL',
            'default': 'https://www.hybrid-analysis.com/api/scan'
        }
    ]


    def initialize(self):
        if not HAVE_REQUESTS:
            raise ModuleInitializationError(self, "Missing dependency: requests")


    def each(self, target):
        self.results = {}
        alg = hashlib.sha256()
        with open(target,'rb') as f:
            buf = f.read(1024)
            while len(buf) > 0:
                alg.update(buf)
                buf = f.read(1024)
        fhash = alg.hexdigest()

        headers = requests.utils.default_headers()
        headers.update({'User-Agent': 'VxStream'})
        try:
            data = requests.get("%s%s" % (self.URL,fhash),auth=(self.API, self.Secret),headers=headers).json()
        except:
            return False

        if data['response_code'] != 0:
            return False

	res = data['response'][0]
	if res['threatscore'] == 0:
            return False

        for tag in res['classification_tags']:
            self.add_tag(tag)

        self.results = {'threatscore': res['threatscore'],'date': res['analysis_start_time'],'link': "https://www.hybrid-analysis.com/sample/%s?environmentId=%s" % (fhash,res['environmentId'])}

        return True

