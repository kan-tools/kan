#!/usr/bin/env python3
"""Regenerate the offline design artifact, including the shared theme controller."""
from pathlib import Path
root = Path(__file__).resolve().parent.parent
studio = root / '.design/kan-studio'
theme = (root / 'web/theme.js').read_text()
(studio / 'theme.js').write_text(theme)
html = (studio / 'index.html').read_text()
html = html.replace('<script src="theme.js"></script>', '<script>' + theme + '</script>')
html = html.replace('<link rel="stylesheet" href="studio.css">', '<style>' + (studio / 'studio.css').read_text() + '</style>')
html = html.replace('<script defer src="studio.js"></script>', '')
html = html.replace('</body>', '<script>' + (studio / 'studio.js').read_text() + '</script></body>')
(studio / 'preview.html').write_text(html)
