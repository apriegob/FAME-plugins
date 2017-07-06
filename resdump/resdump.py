import os
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

# meter en config
MIME_SAMPLE_SIZE = 1024

class Resdump(ProcessingModule):
    name = "resdump"
    description = "Identify and extract files embebbed in PE resources"
    acts_on = ["executable"]

    config = [
        {
            'name': 'MIME_SAMPLE_SIZE',
            'type': 'integer',
            'description': 'Max file header size to look for magic patterns'
        }
    ]

    def initialize(self):
        if not HAVE_PEFILE:
            raise ModuleInitializationError(self, "Missing dependency: pefile")
        if not HAVE_MAGIC:
            raise ModuleInitializationError(self, "Missing dependency: pymagic")


    def __extract(self,name,checksum,countid,data):
        fpath = "%s/res%d_%s" % (tempdir(),countid,name)
        with open(fpath,'wb') as f:
            f.write(data)
        self.add_extracted_file(fpath)
        return fpath


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
                    if not hasattr(resource_id, 'directory'):
                        continue

                    for resource_lang in resource_id.directory.entries:
                        data = pe.get_data(resource_lang.data.struct.OffsetToData,resource_lang.data.struct.Size)
                        reshash = hashlib.sha256(data).hexdigest()
                        lang = pefile.LANG.get(resource_lang.data.lang, 'qq_*unknown*')
                        sublang = pefile.get_sublang_name_for_lang( resource_lang.data.lang, resource_lang.data.sublang )
                        try:
                            filetype = magic.from_buffer(data).decode('utf-8')
                        except:
                            filetype = None
                        resource = {'name': name,'type': filetype, 'rva': "0x%08X" % resource_lang.data.struct.OffsetToData,'size': resource_lang.data.struct.Size, 'sha256': reshash,'lang': lang,'sublang':sublang}
                        extracted = False
                        if filetype is not None and filetype != 'data':
                            self.__extract(name,reshash,count,data)
                            resource['extracted'] = True
                            self.log('info',"Found resource type %s" % filetype)
                        else:
                            resource['extracted'] = False
                            maxsize = resource_lang.data.struct.Size
                            if maxsize > self.MIME_SAMPLE_SIZE:
                                maxsize -= self.MIME_SAMPLE_SIZE
                                for pos in range(1,maxsize ):
                                    auxtype = magic.from_buffer(data[pos:pos+self.MIME_SAMPLE_SIZE])
                                    if auxtype != 'data':
                                        count += 1
                                        reshash = hashlib.sha256(data[pos:]).hexdigest()
                                        respath = self.__extract(name,reshash,count,data[pos:])
                                        resname = os.path.basename(respath)
                                        resource['slipped'] = {'name': resname,'rva': "0x%08X" % (resource_lang.data.struct.OffsetToData + pos),'size': resource_lang.data.struct.Size - pos,'sha256': reshash,'type': auxtype,'extracted': True}
                                        break
                        self.results.append(resource)
                    count += 1

        return len(self.results) > 0

