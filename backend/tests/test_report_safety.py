"""PDF reports embed text that originates from scanned (hostile) targets."""
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest

from scanner import report_generator as rg

HOSTILE = '<img src="http://127.0.0.1:9/x.png"><script>alert(1)</script>'


def _interpreted():
    return {
        'risk_level': 'HIGH',
        'executive_summary': HOSTILE,
        'severity_counts': {'critical': 0, 'high': 1, 'medium': 0, 'low': 0, 'info': 0},
        'total_findings': 1,
        'findings': [{
            'title': HOSTILE, 'severity': 'high', 'description': HOSTILE,
            'impact': HOSTILE, 'recommendation': HOSTILE, 'evidence': HOSTILE,
            'tool': 'nmap',
        }],
    }


def _scan():
    return SimpleNamespace(scan_type='quick', result=HOSTILE)


def test_report_html_escapes_untrusted_text():
    html = rg.render_report_html(
        report_id=1, target=HOSTILE, interpreted=_interpreted(),
        user=None, scan_results=[_scan()],
    )
    assert '<img src="http://127.0.0.1:9' not in html
    assert '<script>alert(1)</script>' not in html
    assert '&lt;img src=&#34;http://127.0.0.1:9/x.png&#34;&gt;' in html


@pytest.mark.parametrize('url', [
    'file:///etc/hosts',
    'http://127.0.0.1:8000/admin/',
    'https://example.com/x.png',
    'ftp://example.com/x',
    'http://169.254.169.254/latest/meta-data/',
])
def test_url_fetcher_refuses_everything_but_data_urls(url):
    with pytest.raises(ValueError):
        rg._safe_url_fetcher(url)


def test_url_fetcher_allows_data_urls():
    result = rg._safe_url_fetcher('data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg"/>')
    assert result.get('string') or result.get('file_obj')


class _Counter(BaseHTTPRequestHandler):
    hits = []

    def do_GET(self):
        _Counter.hits.append(self.path)
        self.send_response(404)
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def local_server():
    _Counter.hits = []
    srv = HTTPServer(('127.0.0.1', 0), _Counter)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f'http://127.0.0.1:{srv.server_port}', _Counter.hits
    srv.shutdown()


def test_pdf_rendering_never_fetches_remote_resources(local_server, tmp_path):
    from weasyprint import HTML

    base, hits = local_server
    html = (f'<html><head><link rel="stylesheet" href="{base}/s.css"></head>'
            f'<body><img src="{base}/pixel.png"></body></html>')

    # Control: WeasyPrint's default fetcher DOES reach out, so the assertion
    # below is meaningful.
    HTML(string=html).write_pdf(str(tmp_path / 'control.pdf'))
    assert hits, 'control failed: default fetcher did not make a request'

    hits.clear()
    rg._write_pdf(html, tmp_path / 'safe.pdf')
    assert hits == []
    assert (tmp_path / 'safe.pdf').stat().st_size > 0
