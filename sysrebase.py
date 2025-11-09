#!/usr/bin/env python3
"""
sysrebase - System Rebase Utility for PGSD/GhostBSD with pkgbase support
"""

import os
import sys
import argparse
import subprocess
import logging
import signal
import json
import re
import shutil
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from contextlib import contextmanager
from functools import cached_property
from urllib.parse import urlparse

# Version
__version__ = "0.1.0-fixed"

# Custom Exceptions
class SysrebaseError(Exception):
    """Base exception for sysrebase"""
    pass

class CommandError(SysrebaseError):
    """Command execution failed"""
    pass

class ValidationError(SysrebaseError):
    """Validation failed"""
    pass

class ResourceError(SysrebaseError):
    """Resource management failed"""
    pass

# Color codes for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'
    BOLD = '\033[1m'

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for different log levels"""
    
    FORMATS = {
        logging.DEBUG: Colors.CYAN + '%(levelname)s: %(message)s' + Colors.RESET,
        logging.INFO: Colors.GREEN + '%(levelname)s: %(message)s' + Colors.RESET,
        logging.WARNING: Colors.YELLOW + '%(levelname)s: %(message)s' + Colors.RESET,
        logging.ERROR: Colors.RED + '%(levelname)s: %(message)s' + Colors.RESET,
        logging.CRITICAL: Colors.RED + Colors.BOLD + '%(levelname)s: %(message)s' + Colors.RESET,
    }
    
    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno, '%(levelname)s: %(message)s')
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)

# Constants for timeouts
class Timeouts:
    """Named constants for operation timeouts"""
    ZFS_OPERATION = 30
    BECTL_OPERATION = 60
    PWD_REBUILD = 60
    PKG_BOOTSTRAP = 300
    PKG_UPDATE = 300
    PKG_INSTALL = 1800
    PKG_UPGRADE = 1800
    PKG_DELETE = 300
    COMMAND_DEFAULT = 120

class SystemInfo:
    """Handles system information detection for PGSD/GhostBSD"""
    
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger('sysrebase')
        self.os_type = self._detect_os()
        self.version = self._detect_version()
        self.arch = self._detect_arch()
        self.abi = self._detect_abi()
        self.available_mirrors = self._detect_mirrors()
        self.uses_pkgbase = self._detect_pkgbase()
        
    def _detect_os(self) -> str:
        """Detect OS type (PGSD/GhostBSD)"""
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if 'PGSD' in content:
                    return 'PGSD'
                elif 'GhostBSD' in content:
                    return 'GhostBSD'
        except FileNotFoundError:
            pass
        
        # Fallback: check uname
        try:
            result = subprocess.run(['uname', '-s'], capture_output=True, 
                                   text=True, timeout=5, check=False)
            if result.returncode == 0 and 'GhostBSD' in result.stdout:
                return 'GhostBSD'
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return 'Unknown'
    
    def _detect_version(self) -> Optional[str]:
        """Detect current OS version"""
        # Try /etc/os-release first
        try:
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('VERSION_ID='):
                        version = line.split('=')[1].strip().strip('"')
                        return version
        except FileNotFoundError:
            pass
        
        # Try uname -r and parse
        try:
            result = subprocess.run(['uname', '-r'], capture_output=True, 
                                   text=True, timeout=5, check=False)
            if result.returncode == 0:
                version_str = result.stdout.strip()
                # Extract version number (e.g., "14.0-STABLE" -> "14.0")
                match = re.match(r'(\d+\.\d+)', version_str)
                if match:
                    return match.group(1)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        return None
    
    def _detect_arch(self) -> str:
        """Detect system architecture"""
        try:
            result = subprocess.run(['uname', '-m'], capture_output=True, 
                                   text=True, timeout=5, check=False)
            if result.returncode == 0:
                return result.stdout.strip()
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        return 'amd64'
    
    def _detect_abi(self) -> str:
        """
        Detect package ABI with dynamic FreeBSD version detection.
        CRITICAL FIX #1: Now fails explicitly instead of using hardcoded fallback.
        """
        # Try pkg config first
        try:
            result = subprocess.run(['pkg', 'config', 'ABI'], 
                                   capture_output=True, text=True, 
                                   timeout=Timeouts.COMMAND_DEFAULT, check=False)
            if result.returncode == 0 and result.stdout.strip():
                abi = result.stdout.strip()
                self.logger.info(f"Detected ABI from pkg: {abi}")
                return abi
        except (subprocess.TimeoutExpired, FileNotFoundError):
            self.logger.warning("pkg command not available or timed out")
        
        # Fallback: detect FreeBSD version dynamically
        return self._detect_freebsd_abi_fallback()
    
    def _detect_freebsd_abi_fallback(self) -> str:
        """
        Dynamically detect FreeBSD ABI version.
        
        CRITICAL FIX #1: Now raises ValidationError instead of using hardcoded
        FreeBSD:14 which would fail on FreeBSD 13 or 15 systems.
        
        Returns:
            ABI string in format "FreeBSD:MAJOR:ARCH"
            
        Raises:
            ValidationError: If FreeBSD version cannot be detected
        """
        # Method 1: Try freebsd-version command (most reliable)
        for cmd in [['freebsd-version', '-k'], ['freebsd-version']]:
            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=Timeouts.COMMAND_DEFAULT,
                    check=False
                )
                if result.returncode == 0 and result.stdout.strip():
                    version_str = result.stdout.strip()
                    major_version = version_str.split('.')[0].split('-')[0]
                    if major_version.isdigit():
                        abi = f"FreeBSD:{major_version}:{self.arch}"
                        self.logger.info(f"Detected ABI from freebsd-version: {abi}")
                        return abi
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
                self.logger.debug(f"freebsd-version attempt failed: {e}")
        
        # Method 2: Try uname -r (fallback)
        try:
            result = subprocess.run(
                ['uname', '-r'],
                capture_output=True,
                text=True,
                timeout=Timeouts.COMMAND_DEFAULT,
                check=False
            )
            if result.returncode == 0 and result.stdout.strip():
                version_str = result.stdout.strip()
                major_version = version_str.split('.')[0].split('-')[0]
                if major_version.isdigit():
                    abi = f"FreeBSD:{major_version}:{self.arch}"
                    self.logger.info(f"Detected ABI from uname: {abi}")
                    return abi
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            self.logger.debug(f"uname attempt failed: {e}")
        
        # CRITICAL FIX #1: Fail explicitly instead of using hardcoded value
        raise ValidationError(
            "Could not detect FreeBSD version. "
            "This is required for proper package ABI detection. "
            "Please ensure freebsd-version or uname commands are available, "
            "or manually specify ABI with PKG_ABI environment variable."
        )
    
    def _detect_mirrors(self) -> List[str]:
        """Detect available mirrors from repo config directory"""
        mirrors = []
        repo_dir = Path('/usr/local/etc/pkg/repos')
        
        if not repo_dir.exists():
            return mirrors
        
        # Look for GhostBSD.conf.XX files
        for conf_file in repo_dir.glob('GhostBSD.conf.*'):
            if conf_file.name == 'GhostBSD.conf.default':
                continue
            # Extract mirror code (e.g., 'ca', 'fr', 'no', 'za')
            mirror = conf_file.suffix[1:]  # Remove the dot
            if mirror:
                mirrors.append(mirror)
        
        return sorted(mirrors)
    
    def _detect_pkgbase(self) -> bool:
        """Detect if system uses pkgbase"""
        try:
            # Check if GhostBSD-runtime package is installed
            result = subprocess.run(['pkg', 'info', 'GhostBSD-runtime'],
                                   capture_output=True, text=True, 
                                   timeout=Timeouts.COMMAND_DEFAULT, check=False)
            if result.returncode == 0:
                return True
            
            # Check if os-generic-* packages exist (old style)
            result = subprocess.run(['pkg', 'info', '-g', 'os-generic-*'],
                                   capture_output=True, text=True,
                                   timeout=Timeouts.COMMAND_DEFAULT, check=False)
            if result.returncode == 0 and result.stdout.strip():
                return False
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Default to pkgbase for newer systems
        return True


class DiskSpaceValidator:
    """Validates disk space availability"""
    
    MIN_FREE_GB = 5.0
    RECOMMENDED_FREE_GB = 10.0
    
    @staticmethod
    def get_free_space_gb(path: str = '/') -> float:
        """Get free disk space in GB"""
        try:
            stat = shutil.disk_usage(path)
            free_gb = stat.free / (1024 ** 3)
            return round(free_gb, 2)
        except Exception as e:
            raise RuntimeError(f"Failed to check disk space for {path}: {e}")
    
    @staticmethod
    def check_sufficient_space(
        path: str = '/',
        required_gb: Optional[float] = None,
        warn_only: bool = False
    ) -> Tuple[bool, str, float]:
        """Check if sufficient disk space is available"""
        required_gb = required_gb or DiskSpaceValidator.MIN_FREE_GB
        
        try:
            free_gb = DiskSpaceValidator.get_free_space_gb(path)
            
            if free_gb < required_gb:
                msg = (
                    f"CRITICAL: Insufficient disk space on {path}\n"
                    f"Required: {required_gb}GB, Available: {free_gb}GB\n"
                    f"Please free up {required_gb - free_gb:.2f}GB before continuing"
                )
                return (False, msg, free_gb)
            
            elif free_gb < DiskSpaceValidator.RECOMMENDED_FREE_GB:
                msg = (
                    f"WARNING: Low disk space on {path}\n"
                    f"Available: {free_gb}GB (Recommended: {DiskSpaceValidator.RECOMMENDED_FREE_GB}GB)"
                )
                return (True, msg, free_gb)
            
            else:
                msg = f"Disk space check passed: {free_gb}GB available on {path}"
                return (True, msg, free_gb)
                
        except RuntimeError as e:
            msg = f"ERROR: Unable to check disk space: {e}"
            return (False, msg, 0.0)
    
    @staticmethod
    def validate_zfs_pool_space(pool_name: Optional[str] = None) -> Tuple[bool, str]:
        """Check ZFS pool space"""
        try:
            cmd = ['zpool', 'list', '-H', '-o', 'name,free,size']
            if pool_name:
                cmd.append(pool_name)
                
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Timeouts.ZFS_OPERATION,
                check=False
            )
            
            if result.returncode != 0:
                return (False, f"Failed to query ZFS pools: {result.stderr}")
            
            lines = result.stdout.strip().split('\n')
            if not lines or not lines[0]:
                return (False, "No ZFS pools found")
            
            pool_info = lines[0].split('\t')
            if len(pool_info) < 3:
                return (False, "Unable to parse ZFS pool information")
            
            pool, free_str, size_str = pool_info[0], pool_info[1], pool_info[2]
            
            free_gb = DiskSpaceValidator._parse_size_to_gb(free_str)
            size_gb = DiskSpaceValidator._parse_size_to_gb(size_str)
            
            if free_gb < DiskSpaceValidator.MIN_FREE_GB:
                return (
                    False,
                    f"Insufficient space in ZFS pool '{pool}': "
                    f"{free_gb:.2f}GB free of {size_gb:.2f}GB total"
                )
            
            return (
                True,
                f"✓ ZFS pool '{pool}' has sufficient space: "
                f"{free_gb:.2f}GB free of {size_gb:.2f}GB total"
            )
            
        except Exception as e:
            return (False, f"Error checking ZFS pool space: {e}")
    
    @staticmethod
    def _parse_size_to_gb(size_str: str) -> float:
        """Parse ZFS size string to GB"""
        size_str = size_str.strip().upper()
        
        match = re.match(r'^([\d.]+)([KMGT]?)$', size_str)
        if not match:
            return 0.0
        
        value = float(match.group(1))
        unit = match.group(2) or 'B'
        
        multipliers = {
            'K': 1 / (1024 ** 2),
            'M': 1 / 1024,
            'G': 1,
            'T': 1024,
            'B': 1 / (1024 ** 3),
        }
        
        return round(value * multipliers.get(unit, 1), 2)


class InputValidator:
    """Validates user input to prevent injection attacks"""
    
    BE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9._-]{1,255}$')
    VERSION_PATTERN = re.compile(r'^\d{2}\.\d{2}$')
    MIRROR_NAME_PATTERN = re.compile(r'^[a-z]{2}$')
    DANGEROUS_CHARS = [';', '&', '|', '$', '`', '\n', '\r', '\\', '"', "'", '<', '>']
    
    @staticmethod
    def validate_be_name(name: str) -> Tuple[bool, str]:
        """Validate boot environment name"""
        if not name:
            return (False, "BE name cannot be empty")
        
        if len(name) > 255:
            return (False, f"BE name too long (max 255 chars): {len(name)}")
        
        for char in InputValidator.DANGEROUS_CHARS:
            if char in name:
                return (False, f"BE name contains invalid character: {repr(char)}")
        
        if not InputValidator.BE_NAME_PATTERN.match(name):
            return (False, 
                   "BE name must contain only letters, numbers, dots, underscores, and hyphens")
        
        if name.startswith(('-', '.')):
            return (False, "BE name cannot start with dash or dot")
        
        return (True, "")
    
    @staticmethod
    def validate_version(version: str) -> Tuple[bool, str]:
        """Validate version string format"""
        if not version:
            return (False, "Version cannot be empty")
        
        if not InputValidator.VERSION_PATTERN.match(version):
            return (False, 
                   f"Invalid version format '{version}' (expected: YY.MM like 25.02)")
        
        return (True, "")
    
    @staticmethod
    def validate_mirror_name(mirror: str) -> Tuple[bool, str]:
        """Validate mirror name"""
        if not mirror:
            return (False, "Mirror name cannot be empty")
        
        if not InputValidator.MIRROR_NAME_PATTERN.match(mirror):
            return (False, 
                   f"Invalid mirror code '{mirror}' (expected: 2-letter country code)")
        
        return (True, "")
    
    @staticmethod
    def validate_path(path: str, allowed_dirs: Optional[list] = None) -> Tuple[bool, str]:
        """Validate file path to prevent path traversal"""
        if not path:
            return (False, "Path cannot be empty")
        
        try:
            path_obj = Path(path).resolve()
            
            if '..' in str(path):
                return (False, "Path contains '..' (potential path traversal)")
            
            if '\0' in path:
                return (False, "Path contains null byte")
            
            if allowed_dirs:
                is_allowed = False
                for allowed_dir in allowed_dirs:
                    allowed_path = Path(allowed_dir).resolve()
                    try:
                        path_obj.relative_to(allowed_path)
                        is_allowed = True
                        break
                    except ValueError:
                        continue
                
                if not is_allowed:
                    return (False, 
                           f"Path must be within allowed directories: {', '.join(allowed_dirs)}")
            
            return (True, "")
            
        except Exception as e:
            return (False, f"Invalid path: {e}")
    
    @staticmethod
    def validate_repo_conf(content: str) -> Tuple[bool, str]:
        """
        Validate repository configuration content.
        
        CRITICAL FIX #2: Validates repo configuration to prevent:
        - Command injection via backticks or $()
        - Malicious URLs
        - Shell metacharacter injection
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not content:
            return (False, "Repository configuration cannot be empty")
        
        # Check for command injection patterns
        dangerous_patterns = [
            (r'`[^`]*`', 'backtick command substitution'),
            (r'\$\([^)]*\)', '$(command) substitution'),
            (r';\s*\w+', 'command chaining with semicolon'),
            (r'\|\s*\w+', 'pipe to command'),
            (r'&&\s*\w+', 'command chaining with &&'),
            (r'\|\|', 'command chaining with ||'),
            (r'>\s*/\w+', 'output redirection'),
            (r'<\s*/\w+', 'input redirection'),
        ]
        
        for pattern, description in dangerous_patterns:
            if re.search(pattern, content):
                return (False, f"Suspicious pattern detected: {description}")
        
        # Validate URLs if present
        url_matches = re.finditer(r'url\s*[=:]\s*["\']([^"\']+)["\']', content, re.IGNORECASE)
        for match in url_matches:
            url = match.group(1)
            is_valid, error = InputValidator.validate_url(url)
            if not is_valid:
                return (False, f"Invalid URL in configuration: {error}")
        
        # Check for null bytes
        if '\0' in content:
            return (False, "Configuration contains null byte")
        
        # Validate overall structure (should look like a config file)
        if not any(char in content for char in ['=', ':']):
            return (False, "Configuration doesn't appear to be in valid format")
        
        return (True, "")
    
    @staticmethod
    def validate_url(url: str) -> Tuple[bool, str]:
        """
        Validate URL for safety.
        
        Args:
            url: URL string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        try:
            parsed = urlparse(url)
            
            # Must have valid scheme
            if parsed.scheme not in ['http', 'https', 'file', 'ftp']:
                return (False, f"Invalid URL scheme: {parsed.scheme}")
            
            # Check for dangerous characters in URL
            for char in InputValidator.DANGEROUS_CHARS:
                if char in url:
                    return (False, f"URL contains dangerous character: {repr(char)}")
            
            # Validate hostname for network URLs
            if parsed.scheme in ['http', 'https', 'ftp']:
                if not parsed.netloc:
                    return (False, "URL missing hostname")
                
                # Check for localhost/internal IPs (potential SSRF)
                if any(term in parsed.netloc.lower() for term in ['localhost', '127.0.0.1', '::1']):
                    return (False, "URL points to localhost (potential security risk)")
            
            return (True, "")
            
        except Exception as e:
            return (False, f"Invalid URL: {e}")
    
    @staticmethod
    def validate_all_inputs(be_name: str, version: str, 
                           mirror: Optional[str] = None,
                           repo_path: Optional[str] = None,
                           repo_conf: Optional[str] = None) -> Tuple[bool, list]:
        """Validate all user inputs at once"""
        errors = []
        
        is_valid, msg = InputValidator.validate_be_name(be_name)
        if not is_valid:
            errors.append(f"BE Name: {msg}")
        
        is_valid, msg = InputValidator.validate_version(version)
        if not is_valid:
            errors.append(f"Version: {msg}")
        
        if mirror:
            is_valid, msg = InputValidator.validate_mirror_name(mirror)
            if not is_valid:
                errors.append(f"Mirror: {msg}")
        
        if repo_path:
            allowed_dirs = ['/usr/local/etc/pkg/repos', '/etc/pkg']
            is_valid, msg = InputValidator.validate_path(repo_path, allowed_dirs)
            if not is_valid:
                errors.append(f"Repo Path: {msg}")
        
        # CRITICAL FIX #2: Validate repo configuration content
        if repo_conf:
            is_valid, msg = InputValidator.validate_repo_conf(repo_conf)
            if not is_valid:
                errors.append(f"Repo Configuration: {msg}")
        
        return (len(errors) == 0, errors)


class RebaseConfig:
    """Configuration for rebase operation"""
    
    def __init__(self, args, system_info: SystemInfo):
        self.target_version = args.to or (system_info.version if args.auto_to else None)
        self.be_name = args.be_name or f"rebase-{self.target_version}"
        self.activate = args.activate
        self.keep_mounted = args.keep_mounted
        self.repo_conf = args.repo_conf
        self.repo_path = args.repo_path or "/usr/local/etc/pkg/repos/GhostBSD.conf.default"
        self.mirror = args.mirror
        self.skip_packages = args.skip_packages
        self.dry_run = args.dry_run
        self.force = args.force
        self.system_info = system_info
        self.preserve_configs = args.preserve_configs
        
        # pkgbase-specific
        self.use_pkgbase = not args.no_pkgbase
        self.base_packages = args.base_packages or "GhostBSD-*"
        self.base_repo = args.base_repo or "GhostBSD-base"
        
        # Validate configuration
        self._validate()
    
    def _validate(self):
        """Validate configuration"""
        if not self.target_version:
            raise ValidationError("Target version must be specified with --to or --auto-to")
        
        # Validate all inputs
        all_valid, errors = InputValidator.validate_all_inputs(
            be_name=self.be_name,
            version=self.target_version,
            mirror=self.mirror,
            repo_path=self.repo_path if self.repo_path else None,
            repo_conf=self.repo_conf if self.repo_conf else None
        )
        
        if not all_valid:
            error_msg = "Input validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
            raise ValidationError(error_msg)
        
        if self.mirror:
            if self.mirror not in self.system_info.available_mirrors:
                available = ', '.join(self.system_info.available_mirrors)
                raise ValidationError(
                    f"Mirror '{self.mirror}' not found. Available mirrors: {available}"
                )
    
    def get_repo_url(self) -> str:
        """Get repository URL with mirror"""
        base_url = "pkg.ghostbsd.org"
        if self.mirror:
            base_url = f"pkg.{self.mirror}.ghostbsd.org"
        return f"https://{base_url}/stable/{self.system_info.abi}/latest"


class BootEnvironmentManager:
    """
    Manages ZFS boot environments with proper resource management.
    
    CRITICAL FIX #3: Implements context managers for automatic cleanup.
    """
    
    def __init__(self, logger):
        self.logger = logger
        self._cleanup_list = []
        self._mounted_bes = set()
    
    @cached_property
    def current_be(self) -> str:
        """Get current boot environment name (cached)"""
        result = subprocess.run(['bectl', 'list', '-H'],
                               capture_output=True, text=True,
                               timeout=Timeouts.BECTL_OPERATION, check=False)
        if result.returncode != 0:
            raise CommandError("Failed to get boot environment list")
        
        for line in result.stdout.splitlines():
            if 'NR' in line or 'N' in line:
                return line.split()[0]
        
        raise CommandError("Could not determine current boot environment")
    
    def exists(self, be_name: str) -> bool:
        """Check if boot environment exists"""
        result = subprocess.run(['bectl', 'list', '-H'],
                               capture_output=True, text=True,
                               timeout=Timeouts.BECTL_OPERATION, check=False)
        return be_name in result.stdout
    
    def create(self, be_name: str, force: bool = False):
        """Create a new boot environment"""
        if self.exists(be_name):
            if force:
                self.logger.warning(f"Boot environment {be_name} exists, destroying...")
                self.destroy(be_name, force=True)
            else:
                raise ValidationError(f"Boot environment {be_name} already exists")
        
        self.logger.info(f"Creating boot environment: {be_name}")
        result = subprocess.run(['bectl', 'create', be_name],
                               capture_output=True, text=True,
                               timeout=Timeouts.BECTL_OPERATION, check=False)
        if result.returncode != 0:
            raise CommandError(f"Failed to create BE: {result.stderr}")
        
        self._cleanup_list.append(be_name)
    
    def _mount_be(self, be_name: str) -> Path:
        """Internal: Mount boot environment and return mountpoint"""
        self.logger.info(f"Mounting boot environment: {be_name}")
        result = subprocess.run(['bectl', 'mount', be_name],
                               capture_output=True, text=True,
                               timeout=Timeouts.BECTL_OPERATION, check=False)
        if result.returncode != 0:
            raise CommandError(f"Failed to mount BE: {result.stderr}")
        
        # Poll for mountpoint with retry (fixes race condition)
        import time
        mountpoint = None
        for attempt in range(10):
            time.sleep(0.3)
            result = subprocess.run(['bectl', 'list', '-H'],
                                   capture_output=True, text=True,
                                   timeout=Timeouts.BECTL_OPERATION, check=False)
            
            for line in result.stdout.splitlines():
                if line.startswith(be_name):
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] != '-':
                        mountpoint = parts[2]
                        break
            
            if mountpoint:
                break
        
        if not mountpoint:
            raise CommandError(f"Failed to get mountpoint for {be_name} after 3 seconds")
        
        self._mounted_bes.add(be_name)
        return Path(mountpoint)
    
    def _unmount_be(self, be_name: str, force: bool = False):
        """Internal: Unmount boot environment"""
        self.logger.info(f"Unmounting boot environment: {be_name}")
        cmd = ['bectl', 'unmount']
        if force:
            cmd.append('-f')
        cmd.append(be_name)
        
        result = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=Timeouts.BECTL_OPERATION, check=False)
        if result.returncode != 0 and not force:
            raise CommandError(f"Failed to unmount BE: {result.stderr}")
        
        self._mounted_bes.discard(be_name)
    
    @contextmanager
    def mounted_be(self, be_name: str):
        """
        Context manager for mounting boot environment.
        
        CRITICAL FIX #3: Ensures BE is always unmounted even on exceptions.
        
        Usage:
            with be_manager.mounted_be("my-be") as mountpoint:
                # Work with mountpoint
                pass
            # BE automatically unmounted here
        """
        mountpoint = None
        try:
            mountpoint = self._mount_be(be_name)
            yield mountpoint
        except Exception as e:
            self.logger.error(f"Error while BE mounted: {e}")
            raise
        finally:
            if mountpoint and be_name in self._mounted_bes:
                try:
                    self._unmount_be(be_name, force=True)
                except Exception as e:
                    self.logger.error(f"Failed to unmount BE {be_name}: {e}")
    
    def activate(self, be_name: str):
        """Activate boot environment"""
        self.logger.info(f"Activating boot environment: {be_name}")
        result = subprocess.run(['bectl', 'activate', be_name],
                               capture_output=True, text=True,
                               timeout=Timeouts.BECTL_OPERATION, check=False)
        if result.returncode != 0:
            raise CommandError(f"Failed to activate BE: {result.stderr}")
    
    def destroy(self, be_name: str, force: bool = False):
        """Destroy boot environment"""
        cmd = ['bectl', 'destroy']
        if force:
            cmd.append('-F')
        cmd.append(be_name)
        
        result = subprocess.run(cmd, capture_output=True, text=True,
                               timeout=Timeouts.BECTL_OPERATION, check=False)
        if result.returncode != 0:
            raise CommandError(f"Failed to destroy BE: {result.stderr}")
    
    def snapshot(self, be_name: str, snapshot_name: str):
        """Create snapshot of boot environment"""
        full_name = f"{be_name}@{snapshot_name}"
        self.logger.info(f"Creating snapshot: {full_name}")
        result = subprocess.run(['bectl', 'create', '-e', be_name, full_name],
                               capture_output=True, text=True,
                               timeout=Timeouts.BECTL_OPERATION, check=False)
        if result.returncode != 0:
            raise CommandError(f"Failed to create snapshot: {result.stderr}")
    
    def cleanup(self):
        """Cleanup created BEs on failure"""
        for be_name in self._cleanup_list:
            if self.exists(be_name):
                self.logger.warning(f"Cleaning up boot environment: {be_name}")
                try:
                    if be_name in self._mounted_bes:
                        self._unmount_be(be_name, force=True)
                    self.destroy(be_name, force=True)
                except Exception as e:
                    self.logger.error(f"Failed to cleanup {be_name}: {e}")


class DevFSManager:
    """
    Manages devfs mounting with proper resource management.
    
    CRITICAL FIX #3: Context manager for automatic devfs cleanup.
    """
    
    def __init__(self, logger):
        self.logger = logger
        self._mounted_devfs = set()
    
    def _mount_devfs(self, mountpoint: Path) -> Path:
        """Internal: Mount devfs"""
        dev_dir = mountpoint / 'dev'
        self.logger.info(f"Mounting devfs at {dev_dir}")
        
        result = subprocess.run(
            ['mount', '-t', 'devfs', 'devfs', str(dev_dir)],
            capture_output=True,
            text=True,
            timeout=Timeouts.COMMAND_DEFAULT,
            check=False
        )
        
        if result.returncode != 0:
            raise CommandError(f"Failed to mount devfs: {result.stderr}")
        
        self._mounted_devfs.add(str(dev_dir))
        return dev_dir
    
    def _unmount_devfs(self, dev_dir: Path):
        """Internal: Unmount devfs"""
        self.logger.info(f"Unmounting devfs at {dev_dir}")
        
        result = subprocess.run(
            ['umount', str(dev_dir)],
            capture_output=True,
            text=True,
            timeout=Timeouts.COMMAND_DEFAULT,
            check=False
        )
        
        if result.returncode != 0:
            self.logger.warning(f"Failed to unmount devfs cleanly: {result.stderr}")
        
        self._mounted_devfs.discard(str(dev_dir))
    
    @contextmanager
    def mounted_devfs(self, mountpoint: Path):
        """
        Context manager for mounting devfs.
        
        CRITICAL FIX #3: Ensures devfs is always unmounted.
        
        Usage:
            with devfs_manager.mounted_devfs(mountpoint) as dev_dir:
                # Work with dev_dir
                pass
            # devfs automatically unmounted here
        """
        dev_dir = None
        try:
            dev_dir = self._mount_devfs(mountpoint)
            yield dev_dir
        except Exception as e:
            self.logger.error(f"Error while devfs mounted: {e}")
            raise
        finally:
            if dev_dir and str(dev_dir) in self._mounted_devfs:
                try:
                    self._unmount_devfs(dev_dir)
                except Exception as e:
                    self.logger.error(f"Failed to unmount devfs: {e}")
    
    def cleanup_all(self):
        """Force cleanup all mounted devfs"""
        for dev_dir in list(self._mounted_devfs):
            try:
                self._unmount_devfs(Path(dev_dir))
            except Exception as e:
                self.logger.error(f"Failed to cleanup devfs {dev_dir}: {e}")


class SysRebase:
    """Main rebase orchestrator with improved error handling"""
    
    def __init__(self, config: RebaseConfig, logger):
        self.config = config
        self.logger = logger
        self.be_manager = BootEnvironmentManager(logger)
        self.devfs_manager = DevFSManager(logger)
        self.interrupted = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        self.logger.warning("\nInterrupt received, cleaning up...")
        self.interrupted = True
        self.devfs_manager.cleanup_all()
        self.be_manager.cleanup()
        sys.exit(130)
    
    def _run_command(self, cmd: List[str], timeout: Optional[int] = None, 
                    check: bool = True, **kwargs) -> subprocess.CompletedProcess:
        """Run command with consistent error handling"""
        self.logger.debug(f"Running: {' '.join(cmd)}")
        
        timeout = timeout or Timeouts.COMMAND_DEFAULT
        
        try:
            result = subprocess.run(cmd, timeout=timeout, check=False, **kwargs)
            if check and result.returncode != 0:
                raise CommandError(
                    f"Command failed with code {result.returncode}: {' '.join(cmd)}\n"
                    f"stderr: {result.stderr if hasattr(result, 'stderr') else 'N/A'}"
                )
            return result
        except subprocess.TimeoutExpired:
            raise CommandError(f"Command timed out after {timeout}s: {' '.join(cmd)}")
    
    def preflight_checks(self):
        """Perform pre-flight validation"""
        self.logger.info("Performing pre-flight checks...")
        
        # Check root
        if os.geteuid() != 0:
            raise ValidationError("Must run as root")
        
        # Check ZFS
        result = subprocess.run(['zfs', 'list'], capture_output=True,
                               timeout=Timeouts.ZFS_OPERATION, check=False)
        if result.returncode != 0:
            raise ValidationError("ZFS not available - system may not support boot environments")
        
        # Check bectl
        result = subprocess.run(['which', 'bectl'], capture_output=True,
                               timeout=Timeouts.COMMAND_DEFAULT, check=False)
        if result.returncode != 0:
            raise ValidationError("bectl not found - required for boot environment management")
        
        # Check pkg
        result = subprocess.run(['which', 'pkg'], capture_output=True,
                               timeout=Timeouts.COMMAND_DEFAULT, check=False)
        if result.returncode != 0:
            self.logger.warning("pkg not found - package operations will fail")
        
        # Check disk space
        self.logger.info("Checking disk space...")
        required_space = 7.0  # Estimated: 2GB BE + 3GB packages + 2GB working
        is_sufficient, msg, free_gb = DiskSpaceValidator.check_sufficient_space(
            required_gb=required_space
        )
        if not is_sufficient:
            raise ValidationError(msg)
        elif free_gb < DiskSpaceValidator.RECOMMENDED_FREE_GB:
            self.logger.warning(msg)
        else:
            self.logger.info(msg)
        
        # Check ZFS pool space
        is_sufficient, msg = DiskSpaceValidator.validate_zfs_pool_space()
        if not is_sufficient:
            raise ValidationError(msg)
        else:
            self.logger.info(msg)
        
        # Check BE name availability
        if self.be_manager.exists(self.config.be_name) and not self.config.force:
            raise ValidationError(
                f"Boot environment '{self.config.be_name}' already exists. "
                f"Use --force to overwrite or choose a different name."
            )
        
        self.logger.info("✓ Pre-flight checks passed")
    
    def preserve_config_files(self, mountpoint: Path):
        """Preserve important configuration files"""
        configs_to_preserve = [
            '/etc/passwd',
            '/etc/master.passwd',
            '/etc/group',
            '/etc/sysctl.conf',
            '/etc/rc.conf',
            '/etc/fstab',
            '/etc/ssh/sshd_config',
        ]
        
        self.logger.info("Preserving configuration files...")
        for config in configs_to_preserve:
            src = Path(config)
            if src.exists():
                dest = mountpoint / config.lstrip('/')
                dest.parent.mkdir(parents=True, exist_ok=True)
                self.logger.debug(f"Copying {src} to {dest}")
                try:
                    shutil.copy2(src, dest)
                except Exception as e:
                    self.logger.warning(f"Failed to copy {config}: {e}")
    
    def rebuild_password_database(self, mountpoint: Path):
        """Rebuild password database"""
        self.logger.info("Rebuilding password database...")
        cmd = ['chroot', str(mountpoint), 'pwd_mkdb', '-p', '/etc/master.passwd']
        self._run_command(cmd, timeout=Timeouts.PWD_REBUILD)
    
    def delete_old_base_packages(self, mountpoint: Path):
        """Delete old os-generic-* base packages"""
        self.logger.info("Removing old os-generic-* packages...")
        
        pkg_cmd = 'pkg-static' if shutil.which('pkg-static') else 'pkg'
        cmd = [pkg_cmd, '-r', str(mountpoint), 'delete', '-y', '-g', 'os-generic-*']
        
        result = self._run_command(cmd, timeout=Timeouts.PKG_DELETE, check=False, 
                                   capture_output=True, text=True)
        if result.returncode != 0:
            if 'No packages matched' in result.stderr or 'No packages matched' in result.stdout:
                self.logger.info("No os-generic-* packages found (already using pkgbase)")
            else:
                self.logger.warning(f"Failed to remove os-generic packages: {result.stderr}")
    
    def install_pkgbase_packages(self, mountpoint: Path):
        """Install GhostBSD pkgbase packages"""
        self.logger.info(f"Installing {self.config.base_packages} from {self.config.base_repo}...")
        
        pkg_cmd = 'pkg-static' if shutil.which('pkg-static') else 'pkg'
        cmd = [pkg_cmd, '-r', str(mountpoint), 'install', '-y', 
               '-r', self.config.base_repo, '-g', self.config.base_packages]
        
        self._run_command(cmd, timeout=Timeouts.PKG_INSTALL)
    
    def update_repo_conf(self, mountpoint: Path):
        """Update repository configuration"""
        if not self.config.repo_conf:
            return
        
        repo_file = mountpoint / self.config.repo_path.lstrip('/')
        repo_file.parent.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"Writing repository configuration to {repo_file}")
        try:
            repo_file.write_text(self.config.repo_conf)
        except Exception as e:
            raise CommandError(f"Failed to write repo configuration: {e}")
    
    def bootstrap_pkg(self, mountpoint: Path):
        """Bootstrap pkg in new root"""
        self.logger.info("Bootstrapping pkg...")
        
        cmd = ['chroot', str(mountpoint), 'env', 'ASSUME_ALWAYS_YES=yes',
               'pkg', 'bootstrap', '-f']
        self._run_command(cmd, timeout=Timeouts.PKG_BOOTSTRAP)
    
    def upgrade_packages(self, mountpoint: Path):
        """Upgrade packages in new root"""
        self.logger.info("Upgrading packages...")
        
        # Update repo
        cmd = ['chroot', str(mountpoint), 'pkg', 'update', '-f']
        self._run_command(cmd, timeout=Timeouts.PKG_UPDATE)
        
        # Upgrade
        cmd = ['chroot', str(mountpoint), 'pkg', 'upgrade', '-y']
        self._run_command(cmd, timeout=Timeouts.PKG_UPGRADE)
    
    def show_plan(self):
        """Show execution plan for dry-run"""
        print(f"\n{Colors.BOLD}=== Rebase Execution Plan ==={Colors.RESET}\n")
        print(f"OS Type:           {self.config.system_info.os_type}")
        print(f"Current Version:   {self.config.system_info.version}")
        print(f"Target Version:    {self.config.target_version}")
        print(f"Architecture:      {self.config.system_info.arch}")
        print(f"ABI:               {self.config.system_info.abi}")
        print(f"Uses pkgbase:      {self.config.system_info.uses_pkgbase}")
        print(f"Boot Environment:  {self.config.be_name}")
        print(f"Activate:          {self.config.activate}")
        if self.config.mirror:
            print(f"Mirror:            {self.config.mirror}")
        print(f"Repository URL:    {self.config.get_repo_url()}")
        print(f"Base Repository:   {self.config.base_repo}")
        print(f"Base Packages:     {self.config.base_packages}")
        print(f"Skip Packages:     {self.config.skip_packages}")
        
        print(f"\n{Colors.BOLD}Steps:{Colors.RESET}")
        print("1. Create snapshot of current BE")
        print(f"2. Create new BE: {self.config.be_name}")
        print(f"3. Mount new BE (with automatic unmount on completion)")
        print("4. Mount devfs (with automatic unmount on completion)")
        if self.config.use_pkgbase:
            print("5. Delete old os-generic-* packages (if any)")
            print(f"6. Install pkgbase packages: {self.config.base_packages}")
        if self.config.preserve_configs:
            print("7. Preserve configuration files")
            print("8. Rebuild password database")
        if self.config.repo_conf:
            print("9. Update repository configuration")
        if not self.config.skip_packages:
            print("10. Bootstrap pkg")
            print("11. Upgrade packages")
        if self.config.activate:
            print(f"12. Activate {self.config.be_name}")
        
        print(f"\n{Colors.YELLOW}This is a dry-run. No changes will be made.{Colors.RESET}\n")
    
    def run(self):
        """Execute the rebase operation with proper resource management"""
        if self.config.dry_run:
            self.show_plan()
            return
        
        self.logger.info(f"Starting rebase to {self.config.target_version}")
        
        try:
            # Pre-flight checks
            self.preflight_checks()
            
            # Create snapshot of current BE
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            snapshot_name = f"pre-rebase-{timestamp}"
            self.be_manager.snapshot(self.be_manager.current_be, snapshot_name)
            
            # Create new BE
            self.be_manager.create(self.config.be_name, force=self.config.force)
            
            # CRITICAL FIX #3: Use context managers for automatic cleanup
            with self.be_manager.mounted_be(self.config.be_name) as mountpoint:
                with self.devfs_manager.mounted_devfs(mountpoint):
                    # pkgbase operations
                    if self.config.use_pkgbase:
                        self.delete_old_base_packages(mountpoint)
                        self.install_pkgbase_packages(mountpoint)
                    
                    # Preserve configs
                    if self.config.preserve_configs:
                        self.preserve_config_files(mountpoint)
                        self.rebuild_password_database(mountpoint)
                    
                    # Update repo conf
                    self.update_repo_conf(mountpoint)
                    
                    # Package operations
                    if not self.config.skip_packages:
                        self.bootstrap_pkg(mountpoint)
                        self.upgrade_packages(mountpoint)
                
                # devfs automatically unmounted here
                
                # Final steps
                if self.config.activate:
                    self.be_manager.activate(self.config.be_name)
                    self.logger.info(f"\n{Colors.GREEN}✓ Rebase complete! "
                                   f"Reboot to use {self.config.be_name}{Colors.RESET}")
                elif self.config.keep_mounted:
                    # Re-mount for inspection
                    mp = self.be_manager._mount_be(self.config.be_name)
                    self.logger.info(f"\n{Colors.GREEN}✓ Rebase complete! "
                                   f"BE mounted at: {mp}{Colors.RESET}")
                    self.logger.info("Run 'bectl unmount' when done inspecting")
                else:
                    self.logger.info(f"\n{Colors.GREEN}✓ Rebase complete! "
                                   f"Use 'bectl activate {self.config.be_name}' to use it{Colors.RESET}")
            
            # BE automatically unmounted here (unless keep_mounted)
        
        except KeyboardInterrupt:
            self.logger.warning("\nOperation cancelled by user")
            raise
        except Exception as e:
            self.logger.error(f"Rebase failed: {e}")
            self.devfs_manager.cleanup_all()
            self.be_manager.cleanup()
            raise


def setup_logging(verbose: bool, log_file: Optional[str]) -> logging.Logger:
    """Setup logging configuration"""
    logger = logging.getLogger('sysrebase')
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Remove existing handlers
    logger.handlers.clear()
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)
    
    # File handler
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(levelname)s - %(message)s'
        ))
        logger.addHandler(file_handler)
    
    return logger


def main():
    parser = argparse.ArgumentParser(
        description='System rebase utility for PGSD/GhostBSD (FIXED VERSION)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Version and target
    parser.add_argument('--version', action='version', version=f'sysrebase {__version__}')
    parser.add_argument('--to', help='Target version (e.g., 25.02)')
    parser.add_argument('--auto-to', action='store_true',
                       help='Use detected system version as target')
    
    # Boot environment options
    parser.add_argument('--be-name', help='Custom boot environment name')
    parser.add_argument('--activate', action='store_true',
                       help='Activate the new BE after completion')
    parser.add_argument('--keep-mounted', action='store_true',
                       help='Keep BE mounted after completion')
    
    # Repository options
    parser.add_argument('--repo-conf', help='Custom repository configuration content')
    parser.add_argument('--repo-path', 
                       help='Repository config path in new root')
    parser.add_argument('--mirror', help='Geographic mirror to use (ca, fr, no, za)')
    
    # pkgbase options
    parser.add_argument('--no-pkgbase', action='store_true',
                       help='Use traditional base.txz instead of pkgbase')
    parser.add_argument('--base-packages', default='GhostBSD-*',
                       help='Base packages to install (default: GhostBSD-*)')
    parser.add_argument('--base-repo', default='GhostBSD-base',
                       help='Base repository name (default: GhostBSD-base)')
    parser.add_argument('--preserve-configs', action='store_true', default=True,
                       help='Preserve configuration files (default: enabled)')
    parser.add_argument('--no-preserve-configs', action='store_false', dest='preserve_configs',
                       help='Do not preserve configuration files')
    
    # Execution options
    parser.add_argument('--skip-packages', action='store_true',
                       help='Skip pkg bootstrap and upgrade')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show plan without making changes')
    parser.add_argument('--force', action='store_true',
                       help='Continue on non-critical errors')
    
    # Logging options
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    parser.add_argument('--log-file', help='Write logs to file')
    
    args = parser.parse_args()
    
    # Setup logging
    logger = setup_logging(args.verbose, args.log_file)
    
    try:
        # Gather system info
        logger.info("Detecting system information...")
        system_info = SystemInfo(logger)
        logger.info(f"Detected OS: {system_info.os_type} {system_info.version}")
        logger.info(f"Architecture: {system_info.arch}")
        logger.info(f"ABI: {system_info.abi}")
        logger.info(f"Uses pkgbase: {system_info.uses_pkgbase}")
        
        if system_info.available_mirrors:
            logger.info(f"Available mirrors: {', '.join(system_info.available_mirrors)}")
        
        # Create configuration
        config = RebaseConfig(args, system_info)
        
        # Create and run rebase
        rebase = SysRebase(config, logger)
        rebase.run()
        
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        sys.exit(1)
    except CommandError as e:
        logger.error(f"Command error: {e}")
        sys.exit(1)
    except SysrebaseError as e:
        logger.error(f"Rebase error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.warning("\nOperation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logger.critical(f"Unexpected error: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == '__main__':
    main()
