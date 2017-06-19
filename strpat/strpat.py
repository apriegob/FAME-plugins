from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from lib import patterns

class Strpat(ProcessingModule):
    name = "strings"
    description = "Dump strings and search patterns"

    def each(self, target):
        self.results = {
            'strings': []
        }

        mix = False
        beg = None
        with open(target,'rb') as f:
            buf = f.read(1024).decode('utf-8',errors='replace').replace('  ',' ')
            if buf[-1:] == ' ':
                mix = True
            buf = buf.strip().split(' ')
            if mix:
                if not beg:
                    beg = buf[-1:]
                    buf = buf[:-1]
                else:
                    buf.insert(0,beg)
                    beg = None
                    mix = False

            chunk = '\n'.join(buf)
            strings += chunk
            res = config.eval_patterns(chunk)
            if res:
                for i in res:
                    self.results['patterns'].append(i)

        if not len(strings):
            return False

        self.results['strings'] = strings
        return True

