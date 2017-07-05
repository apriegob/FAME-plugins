import hashlib
from fame.core.store import store
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from fame.common.utils import tempdir

try:
    import ssdeep
    HAVE_SSDEEP = True
except:
    HAVE_SSDEEP = False

try:
    import pyimpfuzzy
    HAVE_PYIMPFUZZY = True
except:
    HAVE_PYIMPFUZZY = False


class SimilarSamples(ProcessingModule):
    name = "similarsamples"
    description = "Look for similar/related samples"

    def initialize(self):
        if not HAVE_SSDEEP:
            raise ModuleInitializationError(self, "Missing dependency: ssdeep")
        if not HAVE_PYIMPFUZZY:
            raise ModuleInitializationError(self, "Missing dependency: pyimpfuzzy")


    def _compare_strings(self,stra,strb):
        ret = 0
        if stra == strb:
            ret = 100
        return ret


    def _discover_similar_samples(self,target=None):
        if not target:
            return None

        related = []
        compfunc = {'ssdeep': ssdeep.compare, 'impfuzzy': pyimpfuzzy.hash_compare, 'imphash': self._compare_strings}
        samples = store.files.find({},{'_id':1,'sha256':1,'imphash':1,'impfuzzy':1,'ssdeep':1,'names':1,'probable_names':1})
        for sample in samples:
            if sample['sha256'] == target['sha256']:
                continue
            ratio = 0
            match = None
            for alg in ['ssdeep','impfuzzy','imphash']:
                if alg in list(target.keys()):
                    aux = compfunc[alg](sample['ssdeep'],target['ssdeep'])
                    if ratio < aux:
                        ratio = aux
                        match = alg
            if ratio > 0:
                analysis = store.analysis.find_one({'file': sample['_id']},{'_id':1})
                if not len(sample['probable_names']):
                    sample['probable_names'] = ['N/A']
                related.append({'ratio': ratio, 'sha256': sample['sha256'],'algorithm': alg, 'analysis_id':analysis['_id'],'names': sample['names'],'probable_names':sample['probable_names']})

        if not len(related) > 0:
            related = None

        return related


    def each(self, target):
        self.results = {}
        alg = hashlib.sha256()
        with open(target,'rb') as f:
            buf = f.read(1024)
            while len(buf) > 0:
                alg.update(buf)
                buf = f.read(1024)
        fhash = alg.hexdigest()

        related = self._discover_similar_samples(store.files.find_one({'sha256': fhash}))
        if not related:
            self.log('debug','no related samples')
            return False

        self.results = related
        self.log('debug','%d related samples' % len(related))
        return True
