import re

patterns = {
    "btc": re.compile(r'^[a-zA-Z0-9]{34}$'),
    "domain": re.compile(r'^.*[a-zA-Z0-9][-a-zA-Z0-9]+[a-zA-Z0-9](\.[a-z]{2,3}){1,3}$'),
    "ipaddress": re.compile(r'^[1-9]+[0-9]{1,2}(\.[0-9]{1,3}){3}$')
}


def eval_patterns(string):
    ret = []

    for name in list(patterns.keys()):
        res = patterns[name].search(string)
        if not res:
            continue

        ret.append((name,res.group()))

    if not len(ret):
        ret = None

    return ret
