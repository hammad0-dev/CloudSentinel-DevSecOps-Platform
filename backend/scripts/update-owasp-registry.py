"""Rebuild the offline CWE registry from pinned official OWASP category documents.
No scanner or application data is read. Review upstream commit before changing it.
Only identifiers, category names and source URLs are retained, not document bodies.
"""
import concurrent.futures
import json
import pathlib
import re
import urllib.request

REVISION = '3a31f35346c3f4e90f350395124382fa53af2afe'
ROOT = 'https://raw.githubusercontent.com/OWASP/Top10/' + REVISION

def load(url):
    with urllib.request.urlopen(url, timeout=40) as response:
        return response.read().decode('utf-8')

def category(item):
    version, name = item
    source = f'{ROOT}/{version}/docs/en/{name}'
    body = load(source)
    section = re.split(r'##\s+List of Mapped CWEs', body, flags=re.I)
    if len(section) != 2:
        raise ValueError(f'Missing CWE section: {source}')
    cwes = sorted({int(n) for n in re.findall(r'https://cwe.mitre.org/data/definitions/(\d+)\.html', section[1])})
    if not cwes:
        raise ValueError(f'Empty CWE section: {source}')
    number = name[:3]
    title = name.removesuffix('.md').split('-', 1)[1].replace('_', ' ')
    return {'id': f'{number}:{version}', 'name': title, 'version': version,
            'framework': f'OWASP Top 10:{version}', 'frameworkId': f'owasp-top10-{version}',
            'cwes': cwes, 'reference': f'https://top10.owasp.org/{version}/{name[:-3]}/',
            'mappingSource': source, 'sourceRevision': REVISION}

if __name__ == '__main__':
    items = []
    for version in ['2021', '2025']:
        files = json.loads(load(f'https://api.github.com/repos/OWASP/Top10/contents/{version}/docs/en?ref={REVISION}'))
        names = sorted(f['name'] for f in files if re.match(r'A(?:0[1-9]|10)_', f['name']))
        if len(names) != 10:
            raise ValueError(f'Expected ten categories for {version}')
        items.extend((version, name) for name in names)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        categories = list(executor.map(category, items))
    output = {'source': 'OWASP/Top10 official mapped CWE lists', 'revision': REVISION,
              'attribution': 'OWASP Foundation and Top 10 contributors. Adapted category metadata and CWE associations; full text omitted. Source documents and pinned revision are attached per category.',
              'license': 'CC-BY-SA-4.0', 'licenseUrl': 'https://creativecommons.org/licenses/by-sa/4.0/',
              'categories': categories}
    destination = pathlib.Path(__file__).resolve().parent.parent / 'config/compliance/owasp-cwes.json'
    destination.write_text(json.dumps(output, indent=2) + '\n')
    for version in ['2021', '2025']:
        values = [c for c in categories if c['version'] == version]
        print(version, len(values), 'categories;', sum(len(c['cwes']) for c in values), 'CWE associations')
