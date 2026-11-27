"""Check local HTML targets/fragments, project-prefix routing and search assets."""
from html.parser import HTMLParser
from pathlib import Path
import sys
from urllib.parse import unquote, urlsplit

PREFIX = '/kumade/'


class Page(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()
        self.links = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            self.ids.add(attrs['id'])
        if tag in ('a','link') and attrs.get('href'):
            self.links.append(attrs['href'])
        if tag in ('img','script') and attrs.get('src'):
            self.links.append(attrs['src'])


def main():
    root = Path(sys.argv[1]if len(sys.argv)>1 else 'website/site').resolve()
    pages = {}
    for path in root.rglob('*.html'):
        parser = Page()
        parser.feed(path.read_text())
        pages[path] = parser
    assert pages,'No built HTML'
    errors = []
    for source, page in pages.items():
        for link in page.links:
            url = urlsplit(link)
            if url.scheme or url.netloc or not link:
                continue
            path = unquote(url.path)
            if path.startswith('/'):
                if not path.startswith(PREFIX):
                    errors.append(f'{source.relative_to(root)}: missing project prefix: {link}')
                    continue
                target = root/path[len(PREFIX):]
            else:
                target = source.parent/path if path else source
            target = target.resolve()
            if not target.is_relative_to(root):
                errors.append(f'{source.relative_to(root)}: escaped site: {link}')
                continue
            if target.is_dir():
                target = target/'index.html'
            if not target.exists():
                errors.append(f'{source.relative_to(root)}: missing target: {link}')
            elif url.fragment and target in pages and unquote(url.fragment)not in pages[target].ids:
                errors.append(f'{source.relative_to(root)}: missing anchor: {link}')
    home = (root/'index.html').read_text()
    for required in ['Kumade','assets/kumade-golden-waves.png','Getting Started','Commands','Collection','Output','Benchmarks','Resources']:
        assert required in home,required
    assert (root/'assets/kumade-golden-waves.png').stat().st_size>1000
    index = root/'search/search_index.json'
    assert index.is_file(),'Missing search index'
    assert not errors,'\n'.join(errors[:80])
    print(f'Checked {len(pages)} HTML pages, local links/fragments, logo and search index.')


if __name__ == '__main__':
    main()
