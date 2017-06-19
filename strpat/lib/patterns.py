import re

patterns = {
    "btc": re.compile(r'^[a-zA-Z0-9]{34}$'),
    "domain": re.compile(r'^.*[a-zA-Z0-9][-a-zA-Z0-9]+[a-zA-Z0-9].[a-z]{2,3}(.[a-z]{2,3})?(.[a-z]{2,3})?$'),
    "fileextension": re.compile(r'^\.[a-zA-Z0-9]{3,4}$'),
    "ipaddress": re.compile(r'^[1-9]+[0-9]{1,2}(\.[0-9]{1,3}){3}$')
}


def eval_patterns(string):
    ret = []

    for name in list(patterns.keys()):
        res = patterns[name].search(string)
        if not res:
            continue

        ret.append((name,('\n'.join(res.groups()))))

    if not len(ret):
        ret = None

    return ret
