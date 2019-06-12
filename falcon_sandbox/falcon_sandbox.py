import hashlib
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from fame.common.utils import tempdir

try:
    import requests
    HAVE_REQUESTS = True
except:
    HAVE_REQUESTS = False

class Falcon_Sandbox(ProcessingModule):
    name = "Falcon_Sandbox"
    description = "Check file hash with Falcon Sandbox"

    config = [
        {
            'name': 'API',
            'type': 'str',
            'description': 'API Key'
        },

        {
            'name': 'URL',
            'type': 'str',
            'description': 'API URL',
            'default': 'https://www.hybrid-analysis.com/api/v2/search/hash'
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
        headers.update({'User-Agent': 'Falcon'})
        headers.update({'api-key': self.API})
        data_post = {
            'hash': fhash
        }
        try:
            data = requests.post(self.URL,headers=headers,data=data_post).json()
        except:
            return False

        #if found hash:
        if(len(data)==1):
                res = data[0]
                #add tags
                for tag in res['classification_tags']:
                        self.add_tag(tag)
                #add results
                self.results = {'score': (res['threat_score'])/10, 'tac_tec' : res['mitre_attcks'], 'date': res['analysis_start_time'],'link': "https://www.hybrid-analysis.com/sample/%s?environmentId=%s" % (fhash,res['environment_id'])}
       	return True
