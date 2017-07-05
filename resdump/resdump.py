import hashlib
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from fame.common.utils import tempdir

try:
    import pefile
    HAVE_PEFILE = True
except:
    HAVE_PEFILE = False

try:
    import magic
    HAVE_MAGIC = True
except:
    HAVE_MAGIC = False

class Resdump(ProcessingModule):
    name = "resdump"
    description = "Identify and extract files embebbed in PE resources"
    acts_on = ["executable"]

    def initialize(self):
        if not HAVE_PEFILE:
            raise ModuleInitializationError(self, "Missing dependency: pefile")
        if not HAVE_MAGIC:
            raise ModuleInitializationError(self, "Missing dependency: pymagic")


    def each(self, target):
        self.results = []
        try:
            pe = pefile.PE(target)
        except:
            self.log("info","Error loading PE file")
            return False

        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            self.log("info","No resources found")
            return False

        count = 1
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name is not None:
                name = "%s" % resource_type.name
            else:
                name = "%s" % pefile.RESOURCE_TYPE.get(resource_type.struct.Id)
            if name is None:
                name = "%d" % resource_type.struct.Id
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData,resource_lang.data.struct.Size)
                            reshash = hashlib.sha256(data).hexdigest()
                            self.log("info",data[:256])
                            try:
                                filetype = magic.from_buffer(data).decode('utf-8')
                            except:
                                filetype = None
                            self.log('info',"Resource type %s" % filetype)
                            extracted = False
                            if filetype and filetype != 'data':
                                fpath = "%s/res%d_%s" % (tempdir(),count,name)
                                with open(fpath,'wb') as f:
                                    f.write(data)
                                extracted = True
                                self.add_extracted_file(fpath)
                            self.results.append({'name': name,'type': filetype, 'rva': "0x%08X" % resource_lang.data.struct.OffsetToData,'size': resource_lang.data.struct.Size,'extracted': extracted, 'sha256': reshash})
            count += 1

        return len(self.results) > 0

