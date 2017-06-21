import pefile
import hashlib
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from fame.common.utils import tempdir

class Resdump(ProcessingModule):
    name = "resdump"
    description = "Extract files embebbed in PE resources"
    acts_on = ["executable"]

    def each(self, target):
        self.results = {}
        try:
            pe = pefile.PE(target)
        except:
            self.log("info","Not a PE")
            return False

        if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            self.log("info","No resources found")
            return False

        ret = False
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
                            try:
                                filetype = magic.from_buffer(data).decode('utf-8')
                            except:
                                filetype = None
                            if filetype and filetype != 'data':
                                fname = hashlib.sha256(data).hexdigest()
                                fpath = "%s/res%s" % (tempdir(),fname)
                                with open(fpath,'wb') as f:
                                    f.write(data)
                                self.add_extracted_file(fpath)
                                self.log("info","Extracted resource type %s" % filetype)
                                ret = True

        return ret

