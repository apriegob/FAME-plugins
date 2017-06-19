import string
from fame.core.module import ProcessingModule
from fame.common.exceptions import ModuleInitializationError
from lib import patterns

class Strpat(ProcessingModule):
    name = "strings"
    description = "Dump strings and search patterns"

    # from: https://stackoverflow.com/a/17197027
    def strings(self,filename, min=4):
        with open(filename, "rb") as f:
            result = ""
            for c in f.read():
                if c in string.printable:
                    result += c
                    continue
                if len(result) >= min:
                    yield result
                result = ""
            if len(result) >= min:  # catch result at EOF
                yield result

    def each(self, target):
        self.results = {
            'strings': '',
            'patterns': {}
        }

        for chunk in self.strings(target):
            self.results['strings'] += chunk + '\n'
            res = patterns.eval_patterns(chunk)
            if res:
                for i in res:
                    name,value = i
                    if not name in list(self.results['patterns'].keys()):
                        self.results['patterns'][name] = []
                    self.results['patterns'][name].append(value)

        return True

