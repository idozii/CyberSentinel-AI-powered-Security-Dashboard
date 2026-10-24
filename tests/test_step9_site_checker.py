"""No external networking: Step 9 passive-site-check security contract tests."""
from __future__ import annotations

import socket
import unittest
from unittest.mock import patch

from dashboard.site_checker import (
    SiteCheckError, check_website, evaluate_headers, fetch_headers,
    normalize_domain, resolve_public_ipv4,
)


def record(ip: str):
    family = socket.AF_INET6 if ':' in ip else socket.AF_INET
    address = (ip, 443, 0, 0) if family == socket.AF_INET6 else (ip, 443)
    return (family, socket.SOCK_STREAM, 6, '', address)


class DomainSafetyTests(unittest.TestCase):
    def test_plain_and_https_domain_normalization(self):
        self.assertEqual(normalize_domain('WWW.EXAMPLE.COM'), 'www.example.com')
        self.assertEqual(normalize_domain('https://WWW.EXAMPLE.COM/'), 'www.example.com')

    def test_rejects_http_ports_userinfo_path_and_query(self):
        for name in ('http://example.com', 'https://example.com:443',
                     'https://user:password@example.com', 'example.com/admin',
                     'https://example.com/?token=abc', 'https://example.com/#frag'):
            with self.subTest(name=name), self.assertRaises(SiteCheckError):
                normalize_domain(name)

    def test_rejects_private_hostnames_and_ip_literals(self):
        for name in ('127.0.0.1', '192.168.1.1', '[::1]', 'localhost',
                     'metadata.google.internal', 'server.local', 'host.test',
                     'singlehost', 'example.com.', 'example.com\\@localhost'):
            with self.subTest(name=name), self.assertRaises(SiteCheckError):
                normalize_domain(name)

    def test_rejects_control_and_escaped_hosts(self):
        for name in ('example.com\r\nHost: 127.0.0.1', 'exa mple.com',
                     'https://example.com%2f@localhost', 'https://☃.com'):
            with self.subTest(name=name), self.assertRaises(SiteCheckError):
                normalize_domain(name)

    @patch('dashboard.site_checker.socket.getaddrinfo', return_value=[record('1.1.1.1'), record('8.8.8.8')])
    def test_accepts_only_global_public_dns_and_returns_pinned_ip(self, lookup):
        self.assertEqual(resolve_public_ipv4('www.example.com'), '1.1.1.1')
        lookup.assert_called_once()

    def test_rejects_private_or_link_local_dns_if_mixed_with_public(self):
        for unsafe in ('127.0.0.1','10.0.0.2','169.254.169.254','192.168.1.2','100.64.0.1','::1','fd00::1','::ffff:10.1.2.3'):
            with self.subTest(unsafe=unsafe), patch('dashboard.site_checker.socket.getaddrinfo',return_value=[record('1.1.1.1'),record(unsafe)]):
                with self.assertRaisesRegex(SiteCheckError, 'non-public|Special-use'):
                    resolve_public_ipv4('www.example.com')

    @patch('dashboard.site_checker.socket.getaddrinfo', return_value=[record('2606:4700:4700::1111')])
    def test_ipv6_only_site_is_fail_closed(self, _lookup):
        with self.assertRaisesRegex(SiteCheckError, 'IPv4'):
            resolve_public_ipv4('www.example.com')

    @patch('dashboard.site_checker.socket.getaddrinfo', side_effect=socket.gaierror('No address'))
    def test_dns_error_is_safely_reported(self, _lookup):
        with self.assertRaisesRegex(SiteCheckError, 'cannot be resolved'):
            resolve_public_ipv4('www.example.com')


class PinnedHTTPSChecks(unittest.TestCase):
    def test_never_connects_to_unapproved_literal(self):
        with patch('dashboard.site_checker.socket.create_connection') as connect:
            with self.assertRaises(SiteCheckError):
                fetch_headers('example.com', '127.0.0.1')
            connect.assert_not_called()

    def test_tls_uses_original_host_and_http_uses_head_only(self):
        class ContextValue:
            def __init__(self):self.sent=[]
            def __enter__(self):return self
            def __exit__(self,*_):return False
            def settimeout(self,_):pass
            def sendall(self,b):self.sent.append(b)
        raw=ContextValue(); tls=ContextValue()
        class FakeContext:
            def wrap_socket(self,_raw,server_hostname):
                self.hostname=server_hostname
                return tls
        context=FakeContext()
        class FakeResponse:
            status=200
            def __init__(self,sock,method):
                assert sock is tls and method=='HEAD'
            def begin(self):pass
            def getheaders(self):return [('Strict-Transport-Security','max-age=31536000')]
            def close(self):pass
        with (patch('dashboard.site_checker.ssl.create_default_context',return_value=context),
              patch('dashboard.site_checker.socket.create_connection',return_value=raw) as connect,
              patch('dashboard.site_checker.http.client.HTTPResponse',FakeResponse),
              patch('dashboard.site_checker.socket.getaddrinfo') as lookup):
            status, headers=fetch_headers('www.example.com','1.1.1.1')
        connect.assert_called_once_with(('1.1.1.1',443),timeout=4.0)
        lookup.assert_not_called()  # no second DNS lookup after IP validation
        self.assertEqual(context.hostname,'www.example.com')
        req=b''.join(tls.sent).decode('ascii')
        self.assertTrue(req.startswith('HEAD / HTTP/1.1\r\nHost: www.example.com\r\n'))
        self.assertNotIn('GET ',req)
        self.assertEqual(status,200)
        self.assertIn('strict-transport-security',headers)

    def test_csp_report_only_not_counted_as_enforced(self):
        data=evaluate_headers({'Content-Security-Policy-Report-Only':"default-src 'self'"})
        self.assertEqual(data['score'],0)

    def test_hsts_short_max_age_does_not_pass(self):
        data=evaluate_headers({'Strict-Transport-Security':'max-age=0'})
        self.assertEqual(data['score'],0)

    def test_complete_header_set_scores_100_as_configuration_not_security(self):
        headers={
            'Strict-Transport-Security':'max-age=31536000; includeSubDomains',
            'Content-Security-Policy':"default-src 'self'; frame-ancestors 'none'",
            'X-Content-Type-Options':'nosniff',
            'Referrer-Policy':'strict-origin-when-cross-origin',
            'Permissions-Policy':'geolocation=()',
        }
        data=evaluate_headers(headers)
        self.assertEqual(data['score'],100)
        self.assertEqual(len(data['checks']),6)
        self.assertIn('NOT a security guarantee',data['disclaimer'])

    @patch('dashboard.site_checker.fetch_headers',return_value=(301,{'location':'http://127.0.0.1/internal'}))
    @patch('dashboard.site_checker.resolve_public_ipv4',return_value='1.1.1.1')
    def test_redirect_does_not_recurse_or_get_a_score(self,resolve,fetch):
        result=check_website('www.example.com')
        self.assertEqual(result['status'],'not_scored')
        self.assertNotIn('score',result)
        fetch.assert_called_once_with('www.example.com','1.1.1.1')
        resolve.assert_called_once()

    @patch('dashboard.site_checker.fetch_headers',return_value=(405,{}))
    @patch('dashboard.site_checker.resolve_public_ipv4',return_value='1.1.1.1')
    def test_head_not_supported_is_unscored(self,_r,_f):
        self.assertEqual(check_website('www.example.com')['status'],'not_scored')

    @patch('dashboard.site_checker.fetch_headers',return_value=(200,{'strict-transport-security':'max-age=31536000'}))
    @patch('dashboard.site_checker.resolve_public_ipv4',return_value='1.1.1.1')
    def test_valid_assessment_observes_only_allowed_headers(self,_r,_f):
        result=check_website('www.example.com')
        self.assertEqual(result['score'],20)
        self.assertEqual(result['status'],'evaluated')
        self.assertTrue(result['https_certificate_verified'])

    @patch('dashboard.site_checker.resolve_public_ipv4')
    def test_malformed_input_never_reaches_dns(self,resolve):
        with self.assertRaises(SiteCheckError):check_website('http://localhost/')
        resolve.assert_not_called()


if __name__=='__main__':unittest.main()
