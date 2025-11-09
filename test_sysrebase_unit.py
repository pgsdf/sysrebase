#!/usr/bin/env python3
"""
Unit tests for sysrebase with mocking.

Usage:
    python3 test_sysrebase_unit.py
    python3 -m pytest test_sysrebase_unit.py -v
"""

import unittest
from unittest.mock import Mock, MagicMock, patch, mock_open, call
from pathlib import Path
import subprocess
import sys
import os

# Add parent directory to path to import sysrebase_fixed
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import from fixed version
import sysrebase_fixed as sysrebase


class TestInputValidator(unittest.TestCase):
    """Test input validation to prevent injection attacks"""
    
    def test_valid_be_names(self):
        """Test valid boot environment names"""
        valid_names = [
            "simple",
            "with-dash",
            "with_underscore",
            "with.dot",
            "complex-name_123.test",
            "a" * 255,  # Max length
        ]
        
        for name in valid_names:
            with self.subTest(name=name):
                is_valid, msg = sysrebase.InputValidator.validate_be_name(name)
                self.assertTrue(is_valid, f"'{name}' should be valid: {msg}")
    
    def test_invalid_be_names(self):
        """Test invalid boot environment names"""
        invalid_names = [
            "",  # Empty
            "a" * 256,  # Too long
            "bad;name",  # Semicolon
            "bad&name",  # Ampersand
            "bad|name",  # Pipe
            "bad$name",  # Dollar
            "bad`name",  # Backtick
            "bad\nname",  # Newline
            "../etc/passwd",  # Path traversal
            "-starts-with-dash",  # Starts with dash
            ".starts-with-dot",  # Starts with dot
            "has space",  # Space
            "has/slash",  # Slash
        ]
        
        for name in invalid_names:
            with self.subTest(name=repr(name)):
                is_valid, msg = sysrebase.InputValidator.validate_be_name(name)
                self.assertFalse(is_valid, f"'{name}' should be invalid")
    
    def test_valid_versions(self):
        """Test valid version strings"""
        valid_versions = ["25.02", "24.10", "00.00", "99.99"]
        
        for version in valid_versions:
            with self.subTest(version=version):
                is_valid, msg = sysrebase.InputValidator.validate_version(version)
                self.assertTrue(is_valid, f"'{version}' should be valid: {msg}")
    
    def test_invalid_versions(self):
        """Test invalid version strings"""
        invalid_versions = [
            "",
            "25",
            "25.2",
            "2025.02",
            "25.02.1",
            "v25.02",
            "25-02",
        ]
        
        for version in invalid_versions:
            with self.subTest(version=version):
                is_valid, msg = sysrebase.InputValidator.validate_version(version)
                self.assertFalse(is_valid, f"'{version}' should be invalid")
    
    def test_valid_mirror_names(self):
        """Test valid mirror codes"""
        valid_mirrors = ["us", "ca", "fr", "de", "jp", "uk"]
        
        for mirror in valid_mirrors:
            with self.subTest(mirror=mirror):
                is_valid, msg = sysrebase.InputValidator.validate_mirror_name(mirror)
                self.assertTrue(is_valid, f"'{mirror}' should be valid: {msg}")
    
    def test_invalid_mirror_names(self):
        """Test invalid mirror codes"""
        invalid_mirrors = ["", "u", "usa", "US", "1a", "a1", "a-b"]
        
        for mirror in invalid_mirrors:
            with self.subTest(mirror=mirror):
                is_valid, msg = sysrebase.InputValidator.validate_mirror_name(mirror)
                self.assertFalse(is_valid, f"'{mirror}' should be invalid")
    
    def test_path_validation_basic(self):
        """Test basic path validation"""
        # Valid paths
        is_valid, msg = sysrebase.InputValidator.validate_path("/usr/local/etc/pkg")
        self.assertTrue(is_valid)
        
        # Invalid: empty
        is_valid, msg = sysrebase.InputValidator.validate_path("")
        self.assertFalse(is_valid)
        
        # Invalid: contains ..
        is_valid, msg = sysrebase.InputValidator.validate_path("/etc/../../../etc/passwd")
        self.assertFalse(is_valid)
        
        # Invalid: null byte
        is_valid, msg = sysrebase.InputValidator.validate_path("/etc/\0passwd")
        self.assertFalse(is_valid)
    
    def test_path_validation_with_allowed_dirs(self):
        """Test path validation with allowed directories"""
        allowed = ["/usr/local/etc/pkg/repos", "/etc/pkg"]
        
        # Valid: within allowed directory
        is_valid, msg = sysrebase.InputValidator.validate_path(
            "/usr/local/etc/pkg/repos/test.conf",
            allowed_dirs=allowed
        )
        self.assertTrue(is_valid)
        
        # Invalid: outside allowed directories
        is_valid, msg = sysrebase.InputValidator.validate_path(
            "/tmp/test.conf",
            allowed_dirs=allowed
        )
        self.assertFalse(is_valid)
    
    def test_repo_conf_validation_safe(self):
        """Test repository configuration validation - safe configs"""
        safe_configs = [
            'url = "https://pkg.ghostbsd.org/stable"',
            'GhostBSD: {\n  url: "https://pkg.ghostbsd.org",\n  enabled: yes\n}',
            'mirror_type: srv',
        ]
        
        for config in safe_configs:
            with self.subTest(config=config[:50]):
                is_valid, msg = sysrebase.InputValidator.validate_repo_conf(config)
                self.assertTrue(is_valid, f"Safe config should be valid: {msg}")
    
    def test_repo_conf_validation_dangerous(self):
        """Test repository configuration validation - dangerous configs"""
        dangerous_configs = [
            'url = "`rm -rf /`"',  # Backtick injection
            'url = "$(cat /etc/passwd)"',  # Command substitution
            'url = "test"; rm -rf /',  # Command chaining
            'url = "test" | cat /etc/passwd',  # Pipe
            'url = "test" && echo hacked',  # AND chain
            'url = "test" || echo hacked',  # OR chain
            'url = "test" > /tmp/evil',  # Output redirection
            'url = "test" < /etc/passwd',  # Input redirection
            'url = "test\0backdoor"',  # Null byte
        ]
        
        for config in dangerous_configs:
            with self.subTest(config=repr(config[:50])):
                is_valid, msg = sysrebase.InputValidator.validate_repo_conf(config)
                self.assertFalse(is_valid, f"Dangerous config should be invalid: {config}")
    
    def test_url_validation_safe(self):
        """Test URL validation - safe URLs"""
        safe_urls = [
            "https://pkg.ghostbsd.org/stable",
            "http://pkg.ghostbsd.org/stable",
            "ftp://ftp.freebsd.org/pub",
            "file:///usr/local/packages",
        ]
        
        for url in safe_urls:
            with self.subTest(url=url):
                is_valid, msg = sysrebase.InputValidator.validate_url(url)
                self.assertTrue(is_valid, f"Safe URL should be valid: {msg}")
    
    def test_url_validation_dangerous(self):
        """Test URL validation - dangerous URLs"""
        dangerous_urls = [
            "javascript:alert(1)",  # Invalid scheme
            "data:text/html,<script>alert(1)</script>",  # Invalid scheme
            "http://localhost/evil",  # Localhost (SSRF)
            "https://127.0.0.1/evil",  # Localhost IP
            "http://`whoami`.evil.com",  # Backtick injection
            "http://evil.com;rm -rf /",  # Command injection
            "",  # Empty
        ]
        
        for url in dangerous_urls:
            with self.subTest(url=repr(url[:50])):
                is_valid, msg = sysrebase.InputValidator.validate_url(url)
                self.assertFalse(is_valid, f"Dangerous URL should be invalid: {url}")
    
    def test_validate_all_inputs(self):
        """Test comprehensive input validation"""
        # All valid
        all_valid, errors = sysrebase.InputValidator.validate_all_inputs(
            be_name="test-be",
            version="25.02",
            mirror="ca",
            repo_path="/usr/local/etc/pkg/repos/test.conf"
        )
        self.assertTrue(all_valid)
        self.assertEqual(len(errors), 0)
        
        # Invalid BE name
        all_valid, errors = sysrebase.InputValidator.validate_all_inputs(
            be_name="bad;name",
            version="25.02"
        )
        self.assertFalse(all_valid)
        self.assertGreater(len(errors), 0)
        self.assertTrue(any("BE Name" in e for e in errors))
        
        # Invalid version
        all_valid, errors = sysrebase.InputValidator.validate_all_inputs(
            be_name="test-be",
            version="invalid"
        )
        self.assertFalse(all_valid)
        self.assertTrue(any("Version" in e for e in errors))
        
        # Invalid repo config
        all_valid, errors = sysrebase.InputValidator.validate_all_inputs(
            be_name="test-be",
            version="25.02",
            repo_conf='url = "`rm -rf /`"'
        )
        self.assertFalse(all_valid)
        self.assertTrue(any("Repo Configuration" in e for e in errors))


class TestDiskSpaceValidator(unittest.TestCase):
    """Test disk space validation"""
    
    @patch('shutil.disk_usage')
    def test_get_free_space(self, mock_disk_usage):
        """Test getting free space"""
        # Mock 10 GB free
        mock_disk_usage.return_value = Mock(
            total=100 * 1024**3,
            used=90 * 1024**3,
            free=10 * 1024**3
        )
        
        free_gb = sysrebase.DiskSpaceValidator.get_free_space_gb('/')
        self.assertEqual(free_gb, 10.0)
    
    @patch('shutil.disk_usage')
    def test_check_sufficient_space_ok(self, mock_disk_usage):
        """Test disk space check with sufficient space"""
        mock_disk_usage.return_value = Mock(free=20 * 1024**3)
        
        is_sufficient, msg, free_gb = sysrebase.DiskSpaceValidator.check_sufficient_space()
        self.assertTrue(is_sufficient)
        self.assertEqual(free_gb, 20.0)
    
    @patch('shutil.disk_usage')
    def test_check_sufficient_space_low(self, mock_disk_usage):
        """Test disk space check with low space"""
        mock_disk_usage.return_value = Mock(free=7 * 1024**3)
        
        is_sufficient, msg, free_gb = sysrebase.DiskSpaceValidator.check_sufficient_space()
        self.assertTrue(is_sufficient)  # Still sufficient but warning
        self.assertIn("WARNING", msg)
    
    @patch('shutil.disk_usage')
    def test_check_insufficient_space(self, mock_disk_usage):
        """Test disk space check with insufficient space"""
        mock_disk_usage.return_value = Mock(free=2 * 1024**3)
        
        is_sufficient, msg, free_gb = sysrebase.DiskSpaceValidator.check_sufficient_space()
        self.assertFalse(is_sufficient)
        self.assertIn("CRITICAL", msg)
    
    def test_parse_size_to_gb(self):
        """Test parsing ZFS size strings"""
        test_cases = [
            ("1G", 1.0),
            ("500M", 0.49),  # Approximate
            ("2T", 2048.0),
            ("1024K", 0.0),  # Less than 1 GB
            ("100", 0.0),  # No unit defaults to bytes
        ]
        
        for size_str, expected_gb in test_cases:
            with self.subTest(size_str=size_str):
                result = sysrebase.DiskSpaceValidator._parse_size_to_gb(size_str)
                self.assertAlmostEqual(result, expected_gb, places=1)


class TestSystemInfo(unittest.TestCase):
    """Test system information detection"""
    
    @patch('builtins.open', new_callable=mock_open, read_data='ID=GhostBSD\nVERSION_ID="25.02"')
    @patch('subprocess.run')
    def test_detect_os_from_os_release(self, mock_run, mock_file):
        """Test OS detection from /etc/os-release"""
        # Mock subprocess to return valid ABI
        mock_run.return_value = Mock(returncode=0, stdout='FreeBSD:14:amd64\n')
        
        info = sysrebase.SystemInfo()
        self.assertEqual(info.os_type, 'GhostBSD')
    
    @patch('builtins.open', side_effect=FileNotFoundError)
    @patch('subprocess.run')
    def test_detect_os_fallback_to_uname(self, mock_run, mock_file):
        """Test OS detection fallback to uname"""
        mock_run.return_value = Mock(returncode=0, stdout='GhostBSD\n')
        
        info = sysrebase.SystemInfo()
        self.assertEqual(info.os_type, 'GhostBSD')
    
    @patch('subprocess.run')
    def test_detect_arch(self, mock_run):
        """Test architecture detection"""
        mock_run.return_value = Mock(returncode=0, stdout='amd64\n')
        
        info = sysrebase.SystemInfo()
        self.assertEqual(info.arch, 'amd64')
    
    @patch('subprocess.run')
    def test_detect_abi_from_pkg(self, mock_run):
        """Test ABI detection from pkg config"""
        # First call: pkg config ABI
        mock_run.return_value = Mock(
            returncode=0,
            stdout='FreeBSD:14:amd64\n'
        )
        
        info = sysrebase.SystemInfo()
        self.assertEqual(info.abi, 'FreeBSD:14:amd64')
    
    @patch('subprocess.run')
    def test_detect_abi_fallback_freebsd_version(self, mock_run):
        """Test ABI detection fallback to freebsd-version"""
        def mock_run_side_effect(cmd, *args, **kwargs):
            if 'pkg' in cmd:
                # pkg fails
                return Mock(returncode=1, stdout='')
            elif 'freebsd-version' in cmd:
                # freebsd-version succeeds
                return Mock(returncode=0, stdout='14.2-RELEASE\n')
            return Mock(returncode=1, stdout='')
        
        mock_run.side_effect = mock_run_side_effect
        
        info = sysrebase.SystemInfo()
        self.assertEqual(info.abi, 'FreeBSD:14:amd64')
    
    @patch('subprocess.run')
    def test_detect_abi_fallback_uname(self, mock_run):
        """Test ABI detection fallback to uname"""
        def mock_run_side_effect(cmd, *args, **kwargs):
            if 'pkg' in cmd or 'freebsd-version' in cmd:
                return Mock(returncode=1, stdout='')
            elif 'uname' in cmd:
                if '-r' in cmd:
                    return Mock(returncode=0, stdout='13.2-STABLE\n')
                elif '-m' in cmd:
                    return Mock(returncode=0, stdout='amd64\n')
            return Mock(returncode=1, stdout='')
        
        mock_run.side_effect = mock_run_side_effect
        
        info = sysrebase.SystemInfo()
        self.assertEqual(info.abi, 'FreeBSD:13:amd64')
    
    @patch('subprocess.run')
    def test_detect_abi_failure_raises_error(self, mock_run):
        """Test that ABI detection raises error when all methods fail"""
        # All commands fail
        mock_run.return_value = Mock(returncode=1, stdout='')
        
        with self.assertRaises(sysrebase.ValidationError) as context:
            info = sysrebase.SystemInfo()
        
        self.assertIn("Could not detect FreeBSD version", str(context.exception))
    
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.glob')
    @patch('subprocess.run')
    def test_detect_mirrors(self, mock_run, mock_glob, mock_exists):
        """Test mirror detection from config files"""
        mock_exists.return_value = True
        mock_run.return_value = Mock(returncode=0, stdout='FreeBSD:14:amd64\n')
        
        # Mock mirror config files with proper Mock objects
        mock_ca = Mock()
        mock_ca.name = 'GhostBSD.conf.ca'
        mock_ca.suffix = '.ca'
        
        mock_fr = Mock()
        mock_fr.name = 'GhostBSD.conf.fr'
        mock_fr.suffix = '.fr'
        
        mock_default = Mock()
        mock_default.name = 'GhostBSD.conf.default'
        mock_default.suffix = '.default'
        
        mock_glob.return_value = [mock_ca, mock_fr, mock_default]
        
        info = sysrebase.SystemInfo()
        
        self.assertIn('ca', info.available_mirrors)
        self.assertIn('fr', info.available_mirrors)
        self.assertNotIn('default', info.available_mirrors)


class TestBootEnvironmentManager(unittest.TestCase):
    """Test boot environment management with context managers"""
    
    def setUp(self):
        self.logger = Mock()
    
    @patch('subprocess.run')
    def test_create_be_success(self, mock_run):
        """Test creating boot environment"""
        mock_run.return_value = Mock(returncode=0, stdout='')
        
        be_manager = sysrebase.BootEnvironmentManager(self.logger)
        be_manager.create('test-be')
        
        # Verify bectl create was called
        mock_run.assert_called_with(
            ['bectl', 'create', 'test-be'],
            capture_output=True,
            text=True,
            timeout=sysrebase.Timeouts.BECTL_OPERATION,
            check=False
        )
    
    @patch('subprocess.run')
    def test_create_be_already_exists_without_force(self, mock_run):
        """Test creating BE that already exists without force"""
        # Mock bectl list to show BE exists
        mock_run.return_value = Mock(returncode=0, stdout='test-be\tactive\t-\n')
        
        be_manager = sysrebase.BootEnvironmentManager(self.logger)
        
        with self.assertRaises(sysrebase.ValidationError):
            be_manager.create('test-be', force=False)
    
    @patch('subprocess.run')
    def test_mounted_be_context_manager(self, mock_run):
        """Test mounted BE context manager properly cleans up"""
        # Setup mocks
        def mock_run_side_effect(cmd, *args, **kwargs):
            if cmd[1] == 'mount':
                return Mock(returncode=0)
            elif cmd[1] == 'list':
                return Mock(returncode=0, stdout='test-be\t-\t/tmp/be.XXXXX\n')
            elif cmd[1] == 'unmount':
                return Mock(returncode=0)
            return Mock(returncode=0)
        
        mock_run.side_effect = mock_run_side_effect
        
        be_manager = sysrebase.BootEnvironmentManager(self.logger)
        
        # Test normal flow
        with be_manager.mounted_be('test-be') as mountpoint:
            self.assertIsInstance(mountpoint, Path)
            self.assertIn('test-be', be_manager._mounted_bes)
        
        # Verify unmount was called
        unmount_calls = [c for c in mock_run.call_args_list if 'unmount' in c[0][0]]
        self.assertGreater(len(unmount_calls), 0)
    
    @patch('subprocess.run')
    def test_mounted_be_cleanup_on_exception(self, mock_run):
        """Test mounted BE context manager cleans up on exception"""
        def mock_run_side_effect(cmd, *args, **kwargs):
            if cmd[1] == 'mount':
                return Mock(returncode=0)
            elif cmd[1] == 'list':
                return Mock(returncode=0, stdout='test-be\t-\t/tmp/be.XXXXX\n')
            elif cmd[1] == 'unmount':
                return Mock(returncode=0)
            return Mock(returncode=0)
        
        mock_run.side_effect = mock_run_side_effect
        
        be_manager = sysrebase.BootEnvironmentManager(self.logger)
        
        # Test exception handling
        with self.assertRaises(RuntimeError):
            with be_manager.mounted_be('test-be') as mountpoint:
                raise RuntimeError("Test exception")
        
        # Verify unmount was still called
        unmount_calls = [c for c in mock_run.call_args_list if 'unmount' in c[0][0]]
        self.assertGreater(len(unmount_calls), 0)


class TestDevFSManager(unittest.TestCase):
    """Test devfs management with context managers"""
    
    def setUp(self):
        self.logger = Mock()
    
    @patch('subprocess.run')
    def test_mounted_devfs_context_manager(self, mock_run):
        """Test mounted devfs context manager properly cleans up"""
        # Setup mocks
        def mock_run_side_effect(cmd, *args, **kwargs):
            if cmd[0] == 'mount':
                return Mock(returncode=0)
            elif cmd[0] == 'umount':
                return Mock(returncode=0)
            return Mock(returncode=0)
        
        mock_run.side_effect = mock_run_side_effect
        
        devfs_manager = sysrebase.DevFSManager(self.logger)
        mountpoint = Path('/tmp/test-be')
        
        # Test normal flow
        with devfs_manager.mounted_devfs(mountpoint) as dev_dir:
            self.assertEqual(dev_dir, mountpoint / 'dev')
            self.assertIn(str(dev_dir), devfs_manager._mounted_devfs)
        
        # Verify umount was called
        umount_calls = [c for c in mock_run.call_args_list if c[0][0][0] == 'umount']
        self.assertGreater(len(umount_calls), 0)
    
    @patch('subprocess.run')
    def test_mounted_devfs_cleanup_on_exception(self, mock_run):
        """Test mounted devfs context manager cleans up on exception"""
        mock_run.return_value = Mock(returncode=0)
        
        devfs_manager = sysrebase.DevFSManager(self.logger)
        mountpoint = Path('/tmp/test-be')
        
        # Test exception handling
        with self.assertRaises(ValueError):
            with devfs_manager.mounted_devfs(mountpoint) as dev_dir:
                raise ValueError("Test exception")
        
        # Verify umount was still called
        umount_calls = [c for c in mock_run.call_args_list if c[0][0][0] == 'umount']
        self.assertGreater(len(umount_calls), 0)


class TestRebaseConfig(unittest.TestCase):
    """Test rebase configuration validation"""
    
    @patch('subprocess.run')
    def test_config_requires_target_version(self, mock_run):
        """Test that configuration requires target version"""
        mock_run.return_value = Mock(returncode=0, stdout='FreeBSD:14:amd64\n')
        
        args = Mock(
            to=None,
            auto_to=False,
            be_name=None,
            activate=False,
            keep_mounted=False,
            repo_conf=None,
            repo_path=None,
            mirror=None,
            skip_packages=False,
            dry_run=False,
            force=False,
            preserve_configs=True,
            no_pkgbase=False,
            base_packages='GhostBSD-*',
            base_repo='GhostBSD-base'
        )
        
        system_info = sysrebase.SystemInfo()
        
        with self.assertRaises(sysrebase.ValidationError) as context:
            config = sysrebase.RebaseConfig(args, system_info)
        
        self.assertIn("Target version", str(context.exception))
    
    @patch('subprocess.run')
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.glob')
    def test_config_validates_inputs(self, mock_glob, mock_exists, mock_run):
        """Test that configuration validates all inputs"""
        mock_run.return_value = Mock(returncode=0, stdout='FreeBSD:14:amd64\n')
        mock_exists.return_value = False
        mock_glob.return_value = []
        
        args = Mock(
            to='25.02',
            auto_to=False,
            be_name='bad;name',  # Invalid name
            activate=False,
            keep_mounted=False,
            repo_conf=None,
            repo_path=None,
            mirror=None,
            skip_packages=False,
            dry_run=False,
            force=False,
            preserve_configs=True,
            no_pkgbase=False,
            base_packages='GhostBSD-*',
            base_repo='GhostBSD-base'
        )
        
        system_info = sysrebase.SystemInfo()
        
        with self.assertRaises(sysrebase.ValidationError) as context:
            config = sysrebase.RebaseConfig(args, system_info)
        
        self.assertIn("BE Name", str(context.exception))


class TestIntegration(unittest.TestCase):
    """Integration tests with full mocking"""
    
    @patch('os.geteuid', return_value=0)  # Mock root
    @patch('subprocess.run')
    @patch('pathlib.Path.exists')
    @patch('pathlib.Path.glob')
    @patch('shutil.disk_usage')
    def test_dry_run_succeeds(self, mock_disk_usage, mock_glob, mock_exists, 
                              mock_run, mock_geteuid):
        """Test that dry-run mode works end-to-end"""
        # Setup mocks
        mock_disk_usage.return_value = Mock(free=20 * 1024**3)
        mock_exists.return_value = True
        mock_glob.return_value = []
        mock_run.return_value = Mock(
            returncode=0,
            stdout='FreeBSD:14:amd64\n',
            stderr=''
        )
        
        # Create args
        args = Mock(
            to='25.02',
            auto_to=False,
            be_name='test-be',
            activate=False,
            keep_mounted=False,
            repo_conf=None,
            repo_path=None,
            mirror=None,
            skip_packages=False,
            dry_run=True,  # Dry run
            force=False,
            preserve_configs=True,
            no_pkgbase=False,
            base_packages='GhostBSD-*',
            base_repo='GhostBSD-base',
            verbose=False,
            log_file=None
        )
        
        # Run sysrebase
        logger = sysrebase.setup_logging(False, None)
        system_info = sysrebase.SystemInfo(logger)
        config = sysrebase.RebaseConfig(args, system_info)
        rebase = sysrebase.SysRebase(config, logger)
        
        # Should not raise exception
        rebase.run()


def run_tests():
    """Run all tests and report results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestInputValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestDiskSpaceValidator))
    suite.addTests(loader.loadTestsFromTestCase(TestSystemInfo))
    suite.addTests(loader.loadTestsFromTestCase(TestBootEnvironmentManager))
    suite.addTests(loader.loadTestsFromTestCase(TestDevFSManager))
    suite.addTests(loader.loadTestsFromTestCase(TestRebaseConfig))
    suite.addTests(loader.loadTestsFromTestCase(TestIntegration))
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("\n" + "="*70)
    print("TEST SUMMARY")
    print("="*70)
    print(f"Tests run: {result.testsRun}")
    print(f"Successes: {result.testsRun - len(result.failures) - len(result.errors)}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Skipped: {len(result.skipped)}")
    
    if result.wasSuccessful():
        print("\n✓ ALL TESTS PASSED!")
        return 0
    else:
        print("\n✗ SOME TESTS FAILED")
        return 1


if __name__ == '__main__':
    sys.exit(run_tests())
