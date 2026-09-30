import sys
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QTabWidget,
    QProgressBar, QMessageBox, QGroupBox,
    QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal


class ScannerThread(QThread):
    """Thread for running security scans without blocking the GUI"""
    update_signal = pyqtSignal(str)
    finished_signal = pyqtSignal(dict)
    progress_signal = pyqtSignal(int)

    def __init__(self, url, scan_options):
        super().__init__()
        self.url = url
        self.scan_options = scan_options
        self.results = {
            'info_gathering': [],
            'headers': [],
            'ssl_tls': [],
            'xss': [],
            'sql_injection': [],
            'directory_traversal': [],
            'open_redirect': [],
            'csrf': [],
            'misconfigurations': []
        }

    def run(self):
        try:
            self.update_signal.emit("Starting security scan...")
            self.progress_signal.emit(10)

            # Normalize URL
            if not self.url.startswith(('http://', 'https://')):
                self.url = 'http://' + self.url

            parsed_url = urlparse(self.url)
            base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

            # Information Gathering
            if self.scan_options.get('info_gathering', True):
                self.update_signal.emit("Performing information gathering...")
                self.gather_information(base_url)
                self.progress_signal.emit(20)

            # Security Headers Check
            if self.scan_options.get('headers', True):
                self.update_signal.emit("Checking security headers...")
                self.check_security_headers(base_url)
                self.progress_signal.emit(30)

            # SSL/TLS Check
            if self.scan_options.get('ssl_tls', True) and parsed_url.scheme == 'https':
                self.update_signal.emit("Checking SSL/TLS configuration...")
                self.check_ssl_tls(base_url)
                self.progress_signal.emit(40)

            # XSS Check
            if self.scan_options.get('xss', True):
                self.update_signal.emit("Testing for XSS vulnerabilities...")
                self.test_xss(base_url)
                self.progress_signal.emit(50)

            # SQL Injection Check
            if self.scan_options.get('sql_injection', True):
                self.update_signal.emit("Testing for SQL injection vulnerabilities...")
                self.test_sql_injection(base_url)
                self.progress_signal.emit(60)

            # Directory Traversal Check
            if self.scan_options.get('directory_traversal', True):
                self.update_signal.emit("Checking for directory traversal vulnerabilities...")
                self.test_directory_traversal(base_url)
                self.progress_signal.emit(70)

            # Open Redirect Check
            if self.scan_options.get('open_redirect', True):
                self.update_signal.emit("Testing for open redirect vulnerabilities...")
                self.test_open_redirect(base_url)
                self.progress_signal.emit(80)

            # CSRF Check
            if self.scan_options.get('csrf', True):
                self.update_signal.emit("Checking for CSRF vulnerabilities...")
                self.test_csrf(base_url)
                self.progress_signal.emit(90)

            # Misconfigurations Check
            if self.scan_options.get('misconfigurations', True):
                self.update_signal.emit("Checking for common misconfigurations...")
                self.check_misconfigurations(base_url)
                self.progress_signal.emit(100)

            self.update_signal.emit("Scan completed!")
            self.finished_signal.emit(self.results)

        except Exception as e:
            self.update_signal.emit(f"Error during scan: {str(e)}")
            self.finished_signal.emit(self.results)

    def gather_information(self, base_url):
        """Gather basic information about the target"""
        try:
            response = requests.get(base_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Server header
            server = response.headers.get('Server', 'Not disclosed')
            if server != 'Not disclosed':
                self.results['info_gathering'].append({
                    'type': 'Server Header',
                    'detail': f"Server: {server}",
                    'severity': 'Low'
                })

            # X-Powered-By header
            powered_by = response.headers.get('X-Powered-By', 'Not disclosed')
            if powered_by != 'Not disclosed':
                self.results['info_gathering'].append({
                    'type': 'Technology Disclosure',
                    'detail': f"X-Powered-By: {powered_by}",
                    'severity': 'Low'
                })

            # Generator meta tag
            generator = soup.find('meta', attrs={'name': 'generator'})
            if generator and generator.get('content'):
                self.results['info_gathering'].append({
                    'type': 'CMS/Framework Disclosure',
                    'detail': f"Generator: {generator.get('content')}",
                    'severity': 'Low'
                })

            # Comments in HTML
            comments = soup.find_all(string=lambda text: isinstance(text, str) and '<!--' in text)
            for comment in comments[:5]:  # Limit to first 5
                if len(comment.strip()) > 10:
                    self.results['info_gathering'].append({
                        'type': 'HTML Comment',
                        'detail': f"Comment found: {comment.strip()[:100]}...",
                        'severity': 'Info'
                    })

        except Exception as e:
            self.results['info_gathering'].append({
                'type': 'Error',
                'detail': f"Failed to gather information: {str(e)}",
                'severity': 'High'
            })

    def check_security_headers(self, base_url):
        """Check for important security headers"""
        try:
            response = requests.get(base_url, timeout=10, verify=False)
            headers = response.headers

            security_headers = {
                'X-Frame-Options': {
                    'description': 'Protects against clickjacking',
                    'recommended': ['DENY', 'SAMEORIGIN'],
                    'severity': 'Medium'
                },
                'X-XSS-Protection': {
                    'description': 'Enables XSS filtering in browsers',
                    'recommended': ['1; mode=block'],
                    'severity': 'Medium'
                },
                'X-Content-Type-Options': {
                    'description': 'Prevents MIME type sniffing',
                    'recommended': ['nosniff'],
                    'severity': 'Low'
                },
                'Strict-Transport-Security': {
                    'description': 'Enforces HTTPS connections',
                    'recommended': None,  # Just check if present
                    'severity': 'High'
                },
                'Content-Security-Policy': {
                    'description': 'Prevents XSS and other code injection attacks',
                    'recommended': None,  # Just check if present
                    'severity': 'High'
                },
                'Referrer-Policy': {
                    'description': 'Controls referrer information sent with requests',
                    'recommended': ['strict-origin-when-cross-origin', 'no-referrer'],
                    'severity': 'Low'
                },
                'Permissions-Policy': {
                    'description': 'Controls browser features and APIs',
                    'recommended': None,  # Just check if present
                    'severity': 'Low'
                }
            }

            for header, info in security_headers.items():
                value = headers.get(header)
                if value:
                    self.results['headers'].append({
                        'type': f'Present: {header}',
                        'detail': f"Value: {value}",
                        'severity': 'Info'
                    })

                    # Check if value meets recommendations
                    if info['recommended']:
                        if value not in info['recommended']:
                            self.results['headers'].append({
                                'type': f'Misconfigured: {header}',
                                'detail': f"Current value: {value}. Recommended: {', '.join(info['recommended'])}",
                                'severity': info['severity']
                            })
                else:
                    self.results['headers'].append({
                        'type': f'Missing: {header}',
                        'detail': info['description'],
                        'severity': info['severity']
                    })

        except Exception as e:
            self.results['headers'].append({
                'type': 'Error',
                'detail': f"Failed to check security headers: {str(e)}",
                'severity': 'High'
            })

    def check_ssl_tls(self, base_url):
        """Check SSL/TLS configuration"""
        try:
            # This is a basic check - for more advanced SSL testing, consider using sslscan or similar
            requests.get(base_url, timeout=10, verify=True)
            self.results['ssl_tls'].append({
                'type': 'SSL/TLS Enabled',
                'detail': "SSL/TLS certificate is valid and trusted",
                'severity': 'Info'
            })
        except requests.exceptions.SSLError as e:
            self.results['ssl_tls'].append({
                'type': 'SSL/TLS Error',
                'detail': f"SSL/TLS certificate issue: {str(e)}",
                'severity': 'High'
            })
        except Exception as e:
            self.results['ssl_tls'].append({
                'type': 'Error',
                'detail': f"Failed to check SSL/TLS: {str(e)}",
                'severity': 'High'
            })

    def test_xss(self, base_url):
        """Basic XSS testing"""
        try:
            # Simple XSS payloads
            xss_payloads = [
                "<script>alert('XSS')</script>",
                "'><script>alert('XSS')</script>",
                "\"><script>alert('XSS')</script>",
                "javascript:alert('XSS')"
            ]

            # Test in common parameters
            test_params = ['q', 'search', 'query', 's', 'keyword']

            for param in test_params:
                for payload in xss_payloads:
                    try:
                        test_url = f"{base_url}?{param}={requests.utils.quote(payload)}"
                        response = requests.get(test_url, timeout=5, verify=False)

                        # Check if payload is reflected in response
                        if payload in response.text or \
                           payload.replace('<', '<').replace('>', '>') in response.text:
                            self.results['xss'].append({
                                'type': 'Reflected XSS',
                                'detail': f"Parameter '{param}' may be vulnerable to XSS with payload: {payload[:50]}...",
                                'severity': 'High'
                            })
                            break  # Found vulnerability, move to next parameter
                    except:
                        continue

        except Exception as e:
            self.results['xss'].append({
                'type': 'Error',
                'detail': f"Failed to test XSS: {str(e)}",
                'severity': 'High'
            })

    def test_sql_injection(self, base_url):
        """Basic SQL injection testing"""
        try:
            # Simple SQL injection payloads
            sql_payloads = [
                "'",
                "\"",
                "' OR '1'='1",
                "\" OR \"1\"=\"1",
                "' OR '1'='1' --",
                "1' OR '1'='1' /*"
            ]

            # Test in common parameters
            test_params = ['id', 'user', 'username', 'password', 'search', 'q']

            for param in test_params:
                for payload in sql_payloads:
                    try:
                        test_url = f"{base_url}?{param}={requests.utils.quote(payload)}"
                        response = requests.get(test_url, timeout=5, verify=False)

                        # Check for common SQL error messages
                        sql_errors = [
                            'you have an error in your sql syntax',
                            'warning: mysql',
                            'unclosed quotation mark',
                            'quoted string not properly terminated',
                            'sql command not properly ended',
                            'ora-01756',
                            'microsoft ole db provider for sql server'
                        ]

                        response_lower = response.text.lower()
                        for error in sql_errors:
                            if error in response_lower:
                                self.results['sql_injection'].append({
                                    'type': 'SQL Injection',
                                    'detail': f"Parameter '{param}' may be vulnerable to SQL injection with payload: {payload}",
                                    'severity': 'High'
                                })
                                break  # Found vulnerability, move to next parameter
                        else:
                            continue
                        break  # Break outer loop if vulnerability found
                    except:
                        continue

        except Exception as e:
            self.results['sql_injection'].append({
                'type': 'Error',
                'detail': f"Failed to test SQL injection: {str(e)}",
                'severity': 'High'
            })

    def test_directory_traversal(self, base_url):
        """Basic directory traversal testing"""
        try:
            # Common directory traversal payloads
            traversal_payloads = [
                "../../etc/passwd",
                "..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "....//....//etc/passwd"
            ]

            # Test in common parameters
            test_params = ['file', 'page', 'path', 'doc', 'document']

            for param in test_params:
                for payload in traversal_payloads:
                    try:
                        test_url = f"{base_url}?{param}={requests.utils.quote(payload)}"
                        response = requests.get(test_url, timeout=5, verify=False)

                        # Check for signs of successful traversal
                        success_indicators = [
                            'root:',  # /etc/passwd
                            '[extensions]',  # Windows hosts file
                            'bin/bash',
                            'daemon:'
                        ]

                        response_lower = response.text.lower()
                        for indicator in success_indicators:
                            if indicator in response_lower:
                                self.results['directory_traversal'].append({
                                    'type': 'Directory Traversal',
                                    'detail': f"Parameter '{param}' may be vulnerable to directory traversal with payload: {payload}",
                                    'severity': 'High'
                                })
                                break
                        else:
                            continue
                        break
                    except:
                        continue

        except Exception as e:
            self.results['directory_traversal'].append({
                'type': 'Error',
                'detail': f"Failed to test directory traversal: {str(e)}",
                'severity': 'High'
            })

    def test_open_redirect(self, base_url):
        """Test for open redirect vulnerabilities"""
        try:
            # Common open redirect payloads
            redirect_payloads = [
                "http://evil.com",
                "https://evil.com",
                "//evil.com",
                "\\\\evil.com",
                "http://evil.com@google.com"
            ]

            # Test in common parameters
            test_params = ['url', 'redirect', 'return', 'returnTo', 'next', 'target']

            for param in test_params:
                for payload in redirect_payloads:
                    try:
                        test_url = f"{base_url}?{param}={requests.utils.quote(payload)}"
                        response = requests.get(test_url, timeout=5, allow_redirects=False, verify=False)

                        # Check if redirecting to external domain
                        location = response.headers.get('Location', '')
                        if location and ('evil.com' in location or location.startswith('//')):
                            self.results['open_redirect'].append({
                                'type': 'Open Redirect',
                                'detail': f"Parameter '{param}' may be vulnerable to open redirect with payload: {payload}",
                                'severity': 'Medium'
                            })
                            break
                    except:
                        continue

        except Exception as e:
            self.results['open_redirect'].append({
                'type': 'Error',
                'detail': f"Failed to test open redirect: {str(e)}",
                'severity': 'High'
            })

    def test_csrf(self, base_url):
        """Basic CSRF testing - check for CSRF tokens in forms"""
        try:
            response = requests.get(base_url, timeout=10, verify=False)
            soup = BeautifulSoup(response.text, 'html.parser')

            # Find all forms
            forms = soup.find_all('form')
            forms_without_csrf = 0

            for form in forms:
                # Check for common CSRF token field names
                csrf_fields = form.find_all('input', {
                    'name': re.compile(r'csrf|token|_token|authenticity_token', re.I)
                })

                # Also check for hidden inputs that might be tokens
                hidden_inputs = form.find_all('input', {'type': 'hidden'})
                has_token = len(csrf_fields) > 0 or len(hidden_inputs) > 0

                if not has_token and form.find('input', {'type': 'submit'}):
                    forms_without_csrf += 1

            if forms_without_csrf > 0:
                self.results['csrf'].append({
                    'type': 'Missing CSRF Protection',
                    'detail': f"{forms_without_csrf} form(s) found without apparent CSRF protection",
                    'severity': 'Medium'
                })
            elif len(forms) > 0:
                self.results['csrf'].append({
                    'type': 'CSRF Protection Present',
                    'detail': f"All {len(forms)} form(s) appear to have CSRF protection",
                    'severity': 'Info'
                })

        except Exception as e:
            self.results['csrf'].append({
                'type': 'Error',
                'detail': f"Failed to test CSRF: {str(e)}",
                'severity': 'High'
            })

    def check_misconfigurations(self, base_url):
        """Check for common misconfigurations"""
        try:
            # Check for common sensitive files
            sensitive_files = [
                '/.env',
                '/.git/config',
                '/.htaccess',
                '/.htpasswd',
                '/web.config',
                '/wp-config.php',
                '/configuration.php',
                '/phpinfo.php',
                '/info.php',
                '/test.php',
                '/debug.php',
                '/backup/',
                '/backups/',
                '/admin/',
                '/administrator/',
                '/wp-admin/',
                '/phpmyadmin/'
            ]

            for file_path in sensitive_files:
                try:
                    test_url = urljoin(base_url, file_path)
                    response = requests.get(test_url, timeout=5, verify=False)

                    # Consider it a finding if we get a 200 OK and the content looks sensitive
                    if response.status_code == 200:
                        content_lower = response.text.lower()
                        sensitive_indicators = [
                            'password', 'secret', 'key', 'token', 'mysql',
                            'postgresql', 'localhost', '127.0.0.1'
                        ]

                        # For certain files, just finding them is enough
                        if any(indicator in file_path for indicator in ['.env', '.git', 'config', 'backup']):
                            self.results['misconfigurations'].append({
                                'type': 'Sensitive File Exposure',
                                'detail': f"Accessible sensitive file: {file_path}",
                                'severity': 'High'
                            })
                        elif any(indicator in content_lower for indicator in sensitive_indicators):
                            self.results['misconfigurations'].append({
                                'type': 'Information Disclosure',
                                'detail': f"Sensitive information exposed in {file_path}",
                                'severity': 'Medium'
                            })

                except:
                    continue  # Skip failed requests

        except Exception as e:
            self.results['misconfigurations'].append({
                'type': 'Error',
                'detail': f"Failed to check misconfigurations: {str(e)}",
                'severity': 'High'
            })


class WebScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Web Vulnerability Scanner")
        self.setGeometry(100, 100, 1200, 800)
        self.setMinimumSize(1000, 700)

        # Apply futuristic cyberpunk styling
        self.setStyleSheet("""
            QMainWindow {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #000000, stop:0.5 #0d0d0d, stop:1 #000000);
            }
            QWidget {
                font-family: 'Segoe UI', Arial, sans-serif;
                color: #e0e0e0;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ffff, stop:1 #0099cc);
                color: #000000;
                border: none;
                padding: 12px 24px;
                border-radius: 10px;
                font-weight: bold;
                font-size: 14px;
                border: 2px solid #00ffff;
                box-shadow: 0 0 10px #00ffff;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ffff, stop:1 #00ffff);
                border: 2px solid #00ffff;
                color: #000000;
                box-shadow: 0 0 15px #00ffff, 0 0 20px #00ffff;
            }
            QPushButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0099cc, stop:1 #006699);
                border: 2px solid #0099cc;
                box-shadow: 0 0 5px #0099cc;
            }
            QPushButton:disabled {
                background: #2a2a2a;
                color: #555555;
                border: 2px solid #444444;
            }
            QLineEdit, QSpinBox {
                padding: 12px;
                border: 2px solid #00ffff;
                border-radius: 10px;
                font-size: 14px;
                background: rgba(10, 10, 10, 0.8);
                color: #00ffff;
                selection-background-color: #0099cc;
                box-shadow: 0 0 5px #00ffff;
            }
            QLineEdit:focus, QSpinBox:focus {
                border: 2px solid #ff00ff;
                background: rgba(10, 10, 10, 0.9);
                color: #ff00ff;
                box-shadow: 0 0 8px #ff00ff;
            }
            QTabWidget::pane {
                border: 2px solid #00ffff;
                background: rgba(10, 10, 10, 0.7);
                border-radius: 12px;
            }
            QTabBar::tab {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #1a002e, stop:1 #0a0a0a);
                color: #00ffff;
                padding: 14px 24px;
                margin-right: 4px;
                border-top-left-radius: 10px;
                border-top-right-radius: 10px;
                border: 2px solid #00ffff;
                border-bottom: none;
                font-weight: bold;
                font-size: 13px;
                box-shadow: 0 0 3px #00ffff;
            }
            QTabBar::tab:selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00ffff, stop:1 #0099cc);
                color: #000000;
                border-bottom: 4px solid #00ffff;
                border-bottom-left-radius: 0px;
                border-bottom-right-radius: 0px;
                box-shadow: 0 0 8px #00ffff;
            }
            QTabBar::tab:hover:!selected {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #0a0a0a, stop:1 #1a002e);
                border: 2px solid #ff00ff;
                color: #ff00ff;
                box-shadow: 0 0 5px #ff00ff;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #00ffff;
                border-radius: 12px;
                margin-top: 15px;
                padding-top: 18px;
                background: rgba(10, 10, 10, 0.6);
                box-shadow: 0 0 8px #00ffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 8px 0 8px;
                color: #00ffff;
                font-size: 15px;
                background: rgba(10, 10, 10, 0.8);
                border-radius: 6px;
            }
            QTextEdit {
                border: 2px solid #00ffff;
                border-radius: 10px;
                background: rgba(10, 10, 10, 0.8);
                color: #00ffff;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 13px;
                selection-background-color: #0099cc;
                box-shadow: 0 0 5px #00ffff;
            }
            QTextEdit:focus {
                border: 2px solid #ff00ff;
                background: rgba(10, 10, 10, 0.9);
                color: #ff00ff;
                box-shadow: 0 0 8px #ff00ff;
            }
            QProgressBar {
                border: 2px solid #00ffff;
                border-radius: 10px;
                text-align: center;
                background: rgba(10, 10, 10, 0.6);
            }
            QProgressBar::chunk {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ffff, stop:0.5 #0099cc, stop:1 #00ffff);
                border-radius: 6px;
                box-shadow: 0 0 5px #00ffff;
            }
            QLabel {
                color: #e0e0e0;
            }
            QLabel#title_label {
                color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00ffff, stop:0.5 #ff00ff, stop:1 #00ffff);
                font-size: 32px;
                font-weight: bold;
                letter-spacing: 3px;
                margin: 20px;
            }
            QLabel#status_label {
                color: #00ffff;
                font-style: italic;
                padding: 12px;
                background: rgba(0, 255, 255, 0.1);
                border-radius: 8px;
                border: 1px solid rgba(0, 255, 255, 0.3);
                box-shadow: 0 0 5px #00ffff;
            }
            QMessageBox {
                background-color: rgba(10, 10, 10, 0.95);
            }
            QMessageBox QLabel {
                color: #e0e0e0;
            }
            QMessageBox QPushButton {
                min-width: 80px;
            }
        """)

        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.setup_ui()
        self.scanner_thread = None

    def setup_ui(self):
        # Title
        title_label = QLabel("Web Vulnerability Scanner")
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #0078d4; margin: 20px;")
        self.layout.addWidget(title_label)

        # URL Input Section
        url_group = QGroupBox("Target URL")
        url_layout = QHBoxLayout()

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("Enter website URL (e.g., example.com or https://example.com)")
        self.url_input.setMinimumHeight(40)

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.setMinimumHeight(40)
        self.scan_button.clicked.connect(self.start_scan)

        url_layout.addWidget(QLabel("URL:"))
        url_layout.addWidget(self.url_input, 3)
        url_layout.addWidget(self.scan_button, 1)
        url_group.setLayout(url_layout)
        self.layout.addWidget(url_group)

        # Scan Options
        options_group = QGroupBox("Scan Options")
        options_layout = QHBoxLayout()

        self.options = {
            'info_gathering': QCheckBox("Information Gathering"),
            'headers': QCheckBox("Security Headers"),
            'ssl_tls': QCheckBox("SSL/TLS"),
            'xss': QCheckBox("XSS Testing"),
            'sql_injection': QCheckBox("SQL Injection"),
            'directory_traversal': QCheckBox("Directory Traversal"),
            'open_redirect': QCheckBox("Open Redirect"),
            'csrf': QCheckBox("CSRF Protection"),
            'misconfigurations': QCheckBox("Misconfigurations")
        }

        # Set default checked options
        for checkbox in self.options.values():
            checkbox.setChecked(True)
            options_layout.addWidget(checkbox)

        options_group.setLayout(options_layout)
        self.layout.addWidget(options_group)

        # Progress Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.layout.addWidget(self.progress_bar)

        # Status Label
        self.status_label = QLabel("Ready to scan")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("color: #666; font-style: italic; padding: 10px;")
        self.layout.addWidget(self.status_label)

        # Results Tabs
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        # Create tabs for different vulnerability types
        self.setup_result_tabs()

        # Button layout
        button_layout = QHBoxLayout()

        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)

        self.save_button = QPushButton("Save Report")
        self.save_button.clicked.connect(self.save_report)

        button_layout.addStretch()
        button_layout.addWidget(self.clear_button)
        button_layout.addWidget(self.save_button)
        self.layout.addLayout(button_layout)

    def setup_result_tabs(self):
        """Setup tabs for different types of findings"""
        tab_names = [
            ("Info Gathering", "info_gathering"),
            ("Security Headers", "headers"),
            ("SSL/TLS", "ssl_tls"),
            ("XSS", "xss"),
            ("SQL Injection", "sql_injection"),
            ("Directory Traversal", "directory_traversal"),
            ("Open Redirect", "open_redirect"),
            ("CSRF", "csrf"),
            ("Misconfigurations", "misconfigurations")
        ]

        self.result_displays = {}

        for tab_name, key in tab_names:
            text_edit = QTextEdit()
            text_edit.setReadOnly(True)
            self.result_displays[key] = text_edit
            self.tabs.addTab(text_edit, tab_name)

    def start_scan(self):
        url = self.url_input.text().strip()
        if not url:
            QMessageBox.warning(self, "Input Error", "Please enter a URL to scan")
            return

        # Validate URL format
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$', url.split('://')[-1].split('/')[0]) and not url.startswith(('http://', 'https://')):
            reply = QMessageBox.question(
                self,
                "URL Format",
                "The URL doesn't appear to have a valid format. Add http:// prefix?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
            )
            if reply == QMessageBox.StandardButton.Yes:
                url = 'http://' + url
                self.url_input.setText(url)
            else:
                return

        # Get scan options
        scan_options = {key: checkbox.isChecked() for key, checkbox in self.options.items()}

        # Disable UI during scan
        self.scan_button.setEnabled(False)
        self.url_input.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Initializing scan...")

        # Clear previous results
        self.clear_results()

        # Start scanner thread
        self.scanner_thread = ScannerThread(url, scan_options)
        self.scanner_thread.update_signal.connect(self.update_status)
        self.scanner_thread.progress_signal.connect(self.update_progress)
        self.scanner_thread.finished_signal.connect(self.scan_finished)
        self.scanner_thread.start()

    def update_status(self, message):
        self.status_label.setText(message)

    def update_progress(self, value):
        self.progress_bar.setValue(value)

    def scan_finished(self, results):
        # Re-enable UI
        self.scan_button.setEnabled(True)
        self.url_input.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.status_label.setText("Scan completed!")

        # Display results
        self.display_results(results)

        # Show completion message
        total_findings = sum(len(findings) for findings in results.values())
        QMessageBox.information(
            self,
            "Scan Complete",
            f"Security scan completed!\n"
            f"Total findings: {total_findings}\n"
            f"Check the tabs for detailed results."
        )

    def display_results(self, results):
        """Display scan results in the appropriate tabs"""
        for key, findings in results.items():
            if key in self.result_displays:
                text_edit = self.result_displays[key]
                if findings:
                    html_content = self.format_findings_as_html(findings)
                    text_edit.setHtml(html_content)
                else:
                    text_edit.setHtml("<p><i>No findings detected for this category.</i></p>")

    def format_findings_as_html(self, findings):
        """Format findings as HTML for display"""
        if not findings:
            return "<p><i>No findings detected.</i></p>"

        html = """
        <style>
            .finding { margin-bottom: 15px; padding: 12px; border-left: 4px solid #ddd; background-color: #fafafa; }
            .finding.high { border-left-color: #d32f2f; background-color: #ffebee; }
            .finding.medium { border-left-color: #f57c00; background-color: #fff3e0; }
            .finding.low { border-left-color: #fbc02d; background-color: #fffde7; }
            .finding.info { border-left-color: #388e3c; background-color: #e8f5e8; }
            .type { font-weight: bold; color: #1976d2; font-size: 14px; }
            .detail { margin-top: 5px; color: #424242; }
            .severity { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-top: 5px; }
            .severity.high { background-color: #d32f2f; color: white; }
            .severity.medium { background-color: #f57c00; color: white; }
            .severity.low { background-color: #fbc02d; color: black; }
            .severity.info { background-color: #388e3c; color: white; }
            .error { border-left-color: #616161; background-color: #f5f5f5; }
        </style>
        """

        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            html += f"""
            <div class="finding {severity}">
                <div class="type">{finding.get('type', 'Unknown')}</div>
                <div class="detail">{finding.get('detail', 'No details available')}</div>
                <span class="severity {severity}">{finding.get('severity', 'Info')}</span>
            </div>
            """

        return html

    def clear_results(self):
        """Clear all result displays"""
        for text_edit in self.result_displays.values():
            text_edit.clear()
        self.status_label.setText("Ready to scan")

    def save_report(self):
        """Save scan results to a file"""
        from PyQt6.QtWidgets import QFileDialog

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Scan Report",
            f"web_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html",
            "HTML Files (*.html);;Text Files (*.txt);;All Files (*)"
        )

        if file_path:
            try:
                if file_path.endswith('.html'):
                    # Generate HTML report
                    html_content = self.generate_html_report()
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(html_content)
                else:
                    # Generate text report
                    text_content = self.generate_text_report()
                    with open(file_path, 'w', encoding='utf-8') as f:
                        f.write(text_content)

                QMessageBox.information(self, "Success", f"Report saved to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save report: {str(e)}")

    def generate_html_report(self):
        """Generate a comprehensive HTML report"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Web Vulnerability Scan Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
                .header {{ text-align: center; color: #0078d4; margin-bottom: 30px; }}
                .summary {{ background-color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .section {{ background-color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                .section-title {{ color: #0078d4; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }}
                .finding {{ margin-bottom: 15px; padding: 12px; border-left: 4px solid #ddd; background-color: #fafafa; }}
                .finding.high {{ border-left-color: #d32f2f; background-color: #ffebee; }}
                .finding.medium {{ border-left-color: #f57c00; background-color: #fff3e0; }}
                .finding.low {{ border-left-color: #fbc02d; background-color: #fffde7; }}
                .finding.info {{ border-left-color: #388e3c; background-color: #e8f5e8; }}
                .type {{ font-weight: bold; color: #1976d2; font-size: 14px; }}
                .detail {{ margin-top: 5px; color: #424242; }}
                .severity {{ display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 12px; font-weight: bold; margin-top: 5px; }}
                .severity.high {{ background-color: #d32f2f; color: white; }}
                .severity.medium {{ background-color: #f57c00; color: white; }}
                .severity.low {{ background-color: #fbc02d; color: black; }}
                .severity.info {{ background-color: #388e3c; color: white; }}
                .error {{ border-left-color: #616161; background-color: #f5f5f5; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat-box {{ text-align: center; padding: 15px; background-color: #e3f2fd; border-radius: 8px; min-width: 100px; }}
                .stat-number {{ font-size: 24px; font-weight: bold; color: #0078d4; }}
                .stat-label {{ font-size: 14px; color: #666; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Web Vulnerability Scan Report</h1>
                <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Target: {self.url_input.text()}</p>
            </div>
        """

        # Summary statistics
        total_findings = sum(len(findings) for findings in self.scanner_thread.results.values()) if self.scanner_thread else 0
        high_count = sum(1 for findings in (self.scanner_thread.results.values() if self.scanner_thread else [])
                        for f in findings if f.get('severity', '').lower() == 'high')
        medium_count = sum(1 for findings in (self.scanner_thread.results.values() if self.scanner_thread else [])
                          for f in findings if f.get('severity', '').lower() == 'medium')
        low_count = sum(1 for findings in (self.scanner_thread.results.values() if self.scanner_thread else [])
                       for f in findings if f.get('severity', '').lower() == 'low')
        info_count = sum(1 for findings in (self.scanner_thread.results.values() if self.scanner_thread else [])
                        for f in findings if f.get('severity', '').lower() == 'info')

        html += f"""
            <div class="summary">
                <h2>Scan Summary</h2>
                <div class="stats">
                    <div class="stat-box">
                        <div class="stat-number">{total_findings}</div>
                        <div class="stat-label">Total Findings</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{high_count}</div>
                        <div class="stat-label">High Severity</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{medium_count}</div>
                        <div class="stat-label">Medium Severity</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{low_count}</div>
                        <div class="stat-label">Low Severity</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-number">{info_count}</div>
                        <div class="stat-label">Info</div>
                    </div>
                </div>
            </div>
        """

        # Sections for each finding type
        section_names = [
            ("Info Gathering", "info_gathering"),
            ("Security Headers", "headers"),
            ("SSL/TLS", "ssl_tls"),
            ("XSS", "xss"),
            ("SQL Injection", "sql_injection"),
            ("Directory Traversal", "directory_traversal"),
            ("Open Redirect", "open_redirect"),
            ("CSRF", "csrf"),
            ("Misconfigurations", "misconfigurations")
        ]

        results = self.scanner_thread.results if self.scanner_thread else {}

        for section_name, key in section_names:
            findings = results.get(key, [])
            if findings:
                html += f'<div class="section"><h2 class="section-title">{section_name}</h2>'
                for finding in findings:
                    severity = finding.get('severity', 'info').lower()
                    html += f"""
                    <div class="finding {severity}">
                        <div class="type">{finding.get('type', 'Unknown')}</div>
                        <div class="detail">{finding.get('detail', 'No details available')}</div>
                        <span class="severity {severity}">{finding.get('severity', 'Info')}</span>
                    </div>
                    """
                html += '</div>'

        html += """
            <div class="section">
                <h2 class="section-title">Disclaimer</h2>
                <p>This report is generated by an automated security scanning tool and is intended for educational and defensive security purposes only.
                Always ensure you have proper authorization before scanning any website. The scanner may produce false positives and should not be
                relied upon as a comprehensive security assessment. For a thorough security evaluation, consider using professional security services
                and tools.</p>
            </div>
        </body>
        </html>
        """

        return html

    def generate_text_report(self):
        """Generate a text-based report"""

        report = []
        report.append("=" * 60)
        report.append("WEB VULNERABILITY SCAN REPORT")
        report.append("=" * 60)
        report.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        report.append(f"Target: {self.url_input.text()}")
        report.append("")

        # Summary
        total_findings = sum(len(findings) for findings in (self.scanner_thread.results.values() if self.scanner_thread else []))
        report.append(f"Total Findings: {total_findings}")
        report.append("")

        # Sections
        section_names = [
            ("Info Gathering", "info_gathering"),
            ("Security Headers", "headers"),
            ("SSL/TLS", "ssl_tls"),
            ("XSS", "xss"),
            ("SQL Injection", "sql_injection"),
            ("Directory Traversal", "directory_traversal"),
            ("Open Redirect", "open_redirect"),
            ("CSRF", "csrf"),
            ("Misconfigurations", "misconfigurations")
        ]

        results = self.scanner_thread.results if self.scanner_thread else {}

        for section_name, key in section_names:
            findings = results.get(key, [])
            report.append(f"{section_name.upper()}")
            report.append("-" * len(section_name))
            if findings:
                for i, finding in enumerate(findings, 1):
                    report.append(f"{i}. {finding.get('type', 'Unknown')}")
                    report.append(f"   Severity: {finding.get('severity', 'Info')}")
                    report.append(f"   Detail: {finding.get('detail', 'No details available')}")
                    report.append("")
            else:
                report.append("No findings detected.")
                report.append("")

        report.append("=" * 60)
        report.append("DISCLAIMER")
        report.append("=" * 60)
        report.append("This report is generated by an automated security scanning tool and is intended for")
        report.append("educational and defensive security purposes only. Always ensure you have proper")
        report.append("authorization before scanning any website. The scanner may produce false positives")
        report.append("and should not be relied upon as a comprehensive security assessment.")

        return "\n".join(report)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Web Vulnerability Scanner")
    app.setApplicationVersion("1.0")

    window = WebScannerGUI()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    # Disable SSL warnings for testing purposes (in production, handle SSL properly)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    main()