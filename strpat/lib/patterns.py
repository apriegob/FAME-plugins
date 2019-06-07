import re

patterns = {
    "btc": re.compile(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$'),
    "suspicious": re.compile(r'^(http|https):\/\/|[a-z0-9]{3,}([\-\.]{1}[a-z0-9]+)*\.(?!dll)[a-z]{2,6}(:[0-9]{1,5})?(\/.*)?$'),
    "ipaddress": re.compile(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:\/[0-9]{1,2})?')
}


def eval_patterns(string):
    ret = []

    for name in list(patterns.keys()):
        res = patterns[name].search(string.strip())
        if not res:
            continue

        ret.append((name,res.group()))

    if not len(ret):
        ret = None

    return ret
