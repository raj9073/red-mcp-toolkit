"""Offline boundary regressions; external security tools are never executed."""
import importlib.util
import ipaddress
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('boundaries_server', ROOT / 'kali-mcp/kali_security_server.py')
server = importlib.util.module_from_spec(spec)
with patch.dict(os.environ, {'KALI_TARGET_ALLOWLIST': '', 'KALI_TARGET_DENYLIST': ''}):
    spec.loader.exec_module(server)


class ScopeTests(unittest.TestCase):
    def setUp(self):
        self.scope = patch.multiple(server, ALLOW_NETS=[ipaddress.ip_network('192.0.2.0/24')],
                                    ALLOW_HOSTS=['example.invalid'], DENY_NETS=[], DENY_HOSTS=[])
        self.scope.start()
        self.addCleanup(self.scope.stop)

    def test_empty_scope_fails_closed(self):
        with patch.multiple(server, ALLOW_NETS=[], ALLOW_HOSTS=[]):
            self.assertFalse(server._in_scope('example.invalid')[0])

    def test_domain_boundaries_and_normalization(self):
        for target in ('example.invalid', 'a.example.invalid', 'https://EXAMPLE.INVALID./path?x=1'):
            self.assertTrue(server._in_scope(target)[0], target)
        for target in ('badexample.invalid', 'example.invalid.evil.invalid', '-example.invalid',
                       'good@elsewhere.invalid', 'example.invalid,elsewhere.invalid',
                       'https://user:password@example.invalid', 'example.invalid:abc'):
            self.assertFalse(server._in_scope(target)[0], target)

    def test_ip_allow_and_deny(self):
        self.assertTrue(server._in_scope('192.0.2.8')[0])
        self.assertFalse(server._in_scope('192.0.3.8')[0])
        with patch.object(server, 'DENY_NETS', [ipaddress.ip_network('192.0.2.8/32')]):
            self.assertFalse(server._in_scope('192.0.2.8')[0])

    def test_host_deny_wins_for_subdomains(self):
        with patch.object(server, 'DENY_HOSTS', ['blocked.example.invalid']):
            self.assertFalse(server._in_scope('x.blocked.example.invalid')[0])

    def test_dns_deny_and_resolution_failure_fail_closed(self):
        with patch.object(server, 'DENY_NETS', [ipaddress.ip_network('192.0.2.0/24')]):
            for ips in ([], [ipaddress.ip_address('192.0.2.8')],
                        [ipaddress.ip_address('198.51.100.2'), ipaddress.ip_address('192.0.2.8')]):
                with patch.object(server, '_resolve_ips', return_value=ips):
                    self.assertFalse(server._in_scope('example.invalid')[0])
            with patch.object(server, '_resolve_ips', return_value=[ipaddress.ip_address('198.51.100.2')]):
                self.assertTrue(server._in_scope('example.invalid')[0])

    def test_out_of_scope_name_is_not_resolved(self):
        with patch.object(server, 'DENY_NETS', [ipaddress.ip_network('192.0.2.0/24')]), \
                patch.object(server, '_resolve_ips') as resolve:
            self.assertFalse(server._in_scope('other.invalid')[0])
            resolve.assert_not_called()

    def test_range_targets_not_silently_reduced_to_one_ip(self):
        for target in ('192.0.2.0/24', '192.0.2.0/16', '192.0.2.1-12'):
            self.assertFalse(server._in_scope(target)[0])

    def test_blocked_errors_and_logs_do_not_echo_url_credentials(self):
        secret = 'synthetic-sensitive-query'
        with self.assertLogs('kali-mcp', level='WARNING') as logs:
            result = server._guard('https://outside.invalid/?token=' + secret)
        self.assertNotIn(secret, str(result) + '\n'.join(logs.output))

    def test_option_and_control_char_arguments_rejected(self):
        for target in ('--help', 'host\n', 'host;id'):
            if target == 'host\n':
                # whitespace at outer boundaries is intentionally normalized
                continue
            with self.assertRaises(ValueError):
                server._sanitize(target)
        for arg in ('-flag', 'module\nrun', 'x\x00y'):
            with self.assertRaises(ValueError):
                server._arg(arg)

    def test_sqlmap_target_and_command_options_never_run(self):
        for extra in ('-u https://outside.invalid/', '--os-shell', '--file-read=/etc/passwd',
                      '--proxy=http://outside.invalid', '--level=5', '--risk=3', '--timeout', '"'):
            with self.subTest(extra=extra), patch.object(server, '_run') as run:
                result = server.sqlmap_scan('https://example.invalid/?id=1', extra)
                self.assertTrue(result.startswith('[blocked]'), result)
                run.assert_not_called()

    def test_sqlmap_conservative_options_are_structured(self):
        with patch.object(server, '_run', return_value='stub') as run:
            self.assertEqual(server.sqlmap_scan('https://example.invalid/?id=1', '--timeout=9 --threads 2'), 'stub')
        args = run.call_args.args[0]
        self.assertEqual(args[:3], ['sqlmap', '-u', 'https://example.invalid/?id=1'])
        self.assertIn('--batch', args)
        self.assertEqual(args[args.index('--risk') + 1], '1')

    def test_msf_target_override_or_console_injection_never_runs(self):
        for module, options in [('auxiliary/scanner/http/http_version', 'RHOSTS=outside.invalid'),
                                ('auxiliary/scanner/http/http_version\nrun', ''),
                                ('auxiliary/scanner/http/http_version', 'RPORT=80\nrun'),
                                ('auxiliary/scanner/http/http_version', 'PAYLOAD=anything')]:
            with patch.object(server, '_msf_console_run') as run:
                result = server.msf_run(module, 'example.invalid', options, confirm='RUN')
                self.assertTrue(result.startswith('[blocked]'), result)
                run.assert_not_called()


class WorkspaceTests(unittest.TestCase):
    def test_traversal_and_symlink_are_confined(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside, \
                patch.object(server, 'WORKSPACE', root):
            self.assertEqual(server._ws_path('safe.txt'), str(Path(root) / 'safe.txt'))
            for path in ('../outside.txt', outside):
                with self.assertRaises(ValueError):
                    server._ws_path(path)
            Path(root, 'escape').symlink_to(outside, target_is_directory=True)
            with self.assertRaises(ValueError):
                server._ws_path('escape/secret.txt')
            self.assertIsNone(server._ws_dir('escape'))
            self.assertIsNone(server._ws_dir('../outside'))

    def test_write_check_does_not_overwrite_existing_sentinel(self):
        with tempfile.TemporaryDirectory() as root, patch.object(server, 'WORKSPACE', root):
            path = Path(root, '.wtest')
            path.write_text('preserve me')
            self.assertTrue(server._ws_available())
            self.assertEqual(path.read_text(), 'preserve me')


@unittest.skipUnless(os.name == 'posix', 'Kali runner process-group semantics require POSIX')
class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.config = patch.multiple(server, WORKSPACE=self.tmp.name, MAX_OUTPUT_BYTES=4096, MAX_OUTPUT_CHARS=4096)
        self.config.start()
        self.addCleanup(self.config.stop)

    def run_python(self, source, **kwargs):
        return server._run([sys.executable, '-c', source], **kwargs)

    def test_success_stderr_and_nonzero_exit_are_explicit(self):
        result = self.run_python("import sys;print('fixture stdout');print('fixture stderr',file=sys.stderr);sys.exit(7)")
        self.assertIn('fixture stdout', result)
        self.assertIn('fixture stderr', result)
        self.assertIn('[exit code: 7]', result)

    def test_empty_output_still_reports_success(self):
        self.assertEqual(self.run_python('pass'), '(no output)\n[exit code: 0]')

    def test_streaming_output_is_bounded_and_terminated(self):
        started = time.monotonic()
        result = self.run_python("import os;\nwhile True: os.write(1,b'x'*65536)", timeout=3)
        self.assertIn('output limit reached at 4096 bytes', result)
        self.assertLess(len(result), 4250)
        self.assertLess(time.monotonic() - started, 2)
        evidence = list(Path(self.tmp.name, 'output').glob('*.txt'))
        self.assertEqual(len(evidence), 1)
        self.assertLess(evidence[0].stat().st_size, 4600)

    def test_stdin_and_utf8_replacement(self):
        self.assertIn('hello fixture', self.run_python('import sys;print(sys.stdin.read())', input_text='hello fixture'))
        self.assertIn('\ufffd', self.run_python("import os;os.write(1,b'\\xff')"))

    def test_stdin_and_output_do_not_deadlock(self):
        result = self.run_python("import sys;sys.stdout.write('ready\\n');sys.stdout.flush();print(len(sys.stdin.read()))",
                                 input_text='a' * 100000, timeout=2)
        self.assertIn('100000', result)
        self.assertIn('[exit code: 0]', result)

    def test_timeout_kills_descendant_process(self):
        pid_file = str(Path(self.tmp.name, 'child.pid'))
        script = ("import os,time; pid=os.fork(); "
                  "open(" + repr(pid_file) + ",'w').write(str(pid)) if pid else None; time.sleep(20)")
        result = self.run_python(script, timeout=0.3)
        self.assertIn('timed out', result)
        child = int(Path(pid_file).read_text())
        proc_stat = Path('/proc') / str(child) / 'stat'
        if proc_stat.exists():
            self.assertEqual(proc_stat.read_text().split()[2], 'Z', 'descendant still executing')

    def test_missing_tool_and_invalid_limits_are_errors(self):
        self.assertIn('[error] tool not found', server._run(['/nonexistent/red-mcp-test-tool']))
        for timeout in (0, -1, float('nan'), float('inf')):
            self.assertIn('[error]', self.run_python('pass', timeout=timeout))
        with patch.object(server, 'MAX_OUTPUT_BYTES', 0):
            self.assertIn('[error]', self.run_python('pass'))

    def test_secret_args_not_in_output_log_or_evidence(self):
        secret = 'synthetic-command-credential'
        with self.assertLogs('kali-mcp', level='INFO') as logs:
            result = server._run([sys.executable, '-c', 'import sys;print(sys.argv[-1])', '--password', secret])
        evidence = list(Path(self.tmp.name, 'output').glob('*.txt'))[0]
        self.assertNotIn(secret, result + evidence.read_text() + '\n'.join(logs.output))
        self.assertEqual(stat.S_IMODE(evidence.stat().st_mode), 0o600)

    def test_evidence_filenames_do_not_collide(self):
        self.run_python("print('one')")
        self.run_python("print('two')")
        self.assertEqual(len(list(Path(self.tmp.name, 'output').glob('*.txt'))), 2)

    def test_redacts_inline_header_and_impacket_credentials(self):
        cases = [(['tool', '--password=synthetic-inline'], 'synthetic-inline'),
                 (['tool', '-H', 'Authorization: Bearer synthetic-header'], 'synthetic-header'),
                 (['impacket-GetUserSPNs', 'domain/user:synthetic-embedded'], 'synthetic-embedded'),
                 (['tool', 'https://host.invalid/?api_key=synthetic-query'], 'synthetic-query')]
        for command, secret in cases:
            self.assertNotIn(secret, server._redact(command))


class ReviewRegressions(unittest.TestCase):
    def test_scope_rules_normalize_trailing_dns_dot(self):
        nets, hosts = server._parse_allowlist('Example.Invalid.,.sub.example.invalid.')
        self.assertEqual(hosts, ['example.invalid', 'sub.example.invalid'])
        with patch.multiple(server, ALLOW_NETS=nets, ALLOW_HOSTS=hosts,
                            DENY_NETS=[], DENY_HOSTS=server._parse_allowlist('blocked.example.invalid.')[1]):
            self.assertFalse(server._in_scope('https://blocked.example.invalid./')[0])

    def test_invalid_scope_configuration_fails_early(self):
        for rule in ('*', 'https://example.invalid', '192.0.2.0/999', 'host;command'):
            with self.assertRaises(ValueError):
                server._parse_allowlist(rule)

    def test_port_flags_do_not_corrupt_tool_output(self):
        self.assertEqual(server._command_secrets(['nmap', '-p', '80', '192.0.2.1']), [])
        self.assertEqual(server._command_secrets(['masscan', '-p', '80', '192.0.2.1']), [])
        self.assertIn('fixture', server._command_secrets(['nxc', 'smb', '192.0.2.1', '-p', 'fixture']))
        self.assertIn('fixture', server._command_secrets(['env', 'LDAPTLS_REQCERT=never', 'ldapsearch', '-w', 'fixture']))

    def test_url_encoded_and_quoted_credentials_are_masked(self):
        cases = [(['tool', 'https://example.invalid/?token=synthetic%2Dencoded%2Dsecret'], 'synthetic%2Dencoded%2Dsecret'),
                 (['tool', '--password', "synthetic'quoted'secret"], 'synthetic')]
        for cmd, forbidden in cases:
            self.assertNotIn(forbidden, server._redact(cmd))

    def test_partial_known_credential_is_not_returned_or_saved(self):
        secret = 'synthetic-command-secret'
        with tempfile.TemporaryDirectory() as root, patch.multiple(server, WORKSPACE=root, MAX_OUTPUT_BYTES=20):
            result = server._run([sys.executable, '-c', 'import sys;print(sys.argv[-1])', '--password', secret])
            evidence = ''.join(p.read_text() for p in Path(root).rglob('*.txt'))
        self.assertNotIn('synthetic-command', result + evidence)
        self.assertIn('output limit', result)

    def test_unavailable_workspace_is_visible(self):
        with tempfile.NamedTemporaryFile() as not_a_directory, patch.object(server, 'WORKSPACE', not_a_directory.name):
            result = server._run([sys.executable, '-c', "print('fixture')"])
        self.assertIn('[warning] evidence could not be saved', result)

    def test_module_info_does_not_accept_console_commands(self):
        with patch.object(server, '_msf_console_run') as run:
            result = server.msf_module_info('auxiliary/scanner/http/http_version;run')
            self.assertTrue(result.startswith('[blocked]'))
            run.assert_not_called()

class ByteCredentialRegression(unittest.TestCase):
    def test_cap_inside_multibyte_credential_does_not_leak_prefix(self):
        secret = 'fixture-☃-secret'
        partial = secret.encode('utf-8')[:9]
        self.assertEqual(server._mask_command_bytes(partial, [secret]), b'***')

    def test_prefix_mask_is_linear_for_repeated_bytes(self):
        secret = 'a' * 100000 + 'b'
        started = time.monotonic()
        self.assertEqual(server._mask_command_bytes(b'a' * 80000, [secret]), b'***')
        self.assertLess(time.monotonic() - started, 2)


class ConfigurationTests(unittest.TestCase):
    def test_tests_install_the_pinned_production_dependencies(self):
        from importlib.metadata import version
        runtime = (ROOT / 'kali-mcp/requirements.txt').read_text().splitlines()
        tests = (ROOT / 'requirements-test.txt').read_text().splitlines()
        runtime_mcp = next(line for line in runtime if line.startswith('mcp['))
        self.assertIn('-r kali-mcp/requirements.txt', tests)
        self.assertIn('==', runtime_mcp)
        self.assertEqual(version('mcp'), runtime_mcp.split('==')[1])
        self.assertEqual(runtime_mcp.split('==')[1].split('.')[0], '1',
                         'MCP2 removed FastMCP: migrate server and tests before upgrading')

    def test_all_declared_python_dependencies_import_without_connecting(self):
        from mcp.server.fastmcp import FastMCP
        from pymetasploit3.msfrpc import MsfRpcClient
        import jwt
        import requests
        import yaml
        self.assertTrue(all((FastMCP, MsfRpcClient, jwt, requests, yaml)))

    def test_mcp_defaults_are_portable_and_deny_by_default(self):
        import json
        config = json.loads((ROOT / '.mcp.json').read_text())
        args = config['mcpServers']['kali-security']['args']
        self.assertIn('KALI_TARGET_ALLOWLIST=', args)
        self.assertIn('--cap-drop=ALL', args)
        self.assertIn('red-mcp-workspace:/workspace', args)
        self.assertFalse(any('C:/' in arg or '--cap-add' in arg for arg in args))

    def test_vulnerable_lab_port_is_loopback_only(self):
        compose = (ROOT / 'lab/docker-compose.yml').read_text()
        self.assertIn('"127.0.0.1:8080:80"', compose)
        self.assertNotIn('"8080:80"', compose)

    def test_impacket_auth_delimiters_do_not_leak_or_mask_ipv6_addresses(self):
        cmd = ['impacket-GetUserSPNs', 'domain/user:synthetic@credential', '-dc-ip', '2001:db8::1']
        masked = server._redact(cmd)
        self.assertNotIn('synthetic', masked)
        self.assertNotIn('credential', masked)
        self.assertIn('2001:db8::1', masked)
        dumped = server._redact(['impacket-secretsdump', 'domain/user:synthetic@credential@host.invalid'])
        self.assertNotIn('synthetic', dumped)
        self.assertNotIn('credential', dumped)
        self.assertIn('host.invalid', dumped)

if __name__ == '__main__':
    unittest.main()
