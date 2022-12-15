
"""Test functions for the Scanner class."""

import sys #The sys module in Python provides various functions and variables that are used to manipulate different parts of the Python runtime environment. It allows operating on the interpreter as it provides access to the variables and functions that interact strongly with the interpreter.
import pytest #Pytest is a Python testing framework that originated from the PyPy project. It can be used to write various types of software tests, including unit tests, integration tests, end-to-end tests, and functional tests. Its features include parametrized testing, fixtures, and assert re-writing.
import ipaddress #The python module ipaddress is used extensively to validate and categorize IP address to IPV4 and IPV6 type. It can also be used to do comparison of the IP address values as well as IP address arithmetic for manipulating the ip addresses.
from port_eye.scanner import Scanner, ScannerHandler
from port_eye.report import PortReport, HostReport, Report, Vulnerability
import threading #Threading in python is used to run multiple threads (tasks, function calls) at the same time. Note that this does not mean that they are executed on different CPUs. Python threads will NOT make your program faster if it already uses 100 % CPU time. In that case, you probably want to look into parallel programming.
import blessings #Blessings provides just one top-level object: Terminal. Instantiating a Terminal figures out whether you're on a terminal at all and, if so, does any necessary terminal setup. After that, you can proceed to ask it all sorts of things about the terminal.
import pyfiglet

if sys.version_info[0] == 2:  # pragma: no cover
    from Queue import Queue
else:
    from queue import Queue


def test_import():
    """Test that the correct version of queue/Queue is imported."""


def test_wrong_format():
    """Test that a wrong format for a host is detected."""
    with pytest.raises(TypeError):
        wrong_host = "fake"
        Scanner(wrong_host)


def test_correct_format():
    """Test that the create of a scanner works."""
    host = ipaddress.ip_address(u"192.168.0.1")
    scanner = Scanner(host, mock=True)
    assert scanner.raw_host == host
    assert scanner.host == u"192.168.0.1"


def test_detection_private_host():
    """Check the detection of private/public hosts."""
    private_host = ipaddress.ip_address(u"192.168.0.1")
    public_host = ipaddress.ip_address(u"216.58.201.238")
    private_ipv6 = ipaddress.ip_address(u"fe80::a00:27ff:fe8f:ec03")
    public_ipv6 = ipaddress.ip_address(u"2a00:1450:4007:80a::200e")

    scanner_private_ipv4 = Scanner(private_host, mock=True)
    scanner_public_ipv4 = Scanner(public_host, mock=True)
    scanner_private_ipv6 = Scanner(private_ipv6, mock=True)
    scanner_public_ipv6 = Scanner(public_ipv6, mock=True)

    assert scanner_private_ipv4.is_local() is True
    assert scanner_public_ipv4.is_local() is False
    assert scanner_private_ipv6.is_local() is True
    assert scanner_public_ipv6.is_local() is False


def test_reachable():
    """Check the detection of reachable hosts."""
    reachable_hosts = [
        ipaddress.ip_address(u"127.0.0.1"),
        ipaddress.ip_address(u"92.222.10.88"),
    ]
    unreachable_hosts = [ipaddress.ip_address(u"192.0.2.1")]

    for host in reachable_hosts:
        scanner = Scanner(host, mock=True)
        assert scanner.run_ping_test() is True

    for host in unreachable_hosts:
        scanner = Scanner(host, mock=True)
        assert scanner.run_ping_test() is False


def test_reachable_ipv6():
    """Check the detection of reachable hosts while IPV6."""
    reachable_host = ipaddress.ip_address(
        u"2a01:e0a:129:5ed0:211:32ff:fe2d:68da"
    )
    scanner = Scanner(reachable_host, True, mock=True)
    assert scanner.run_ping_test() is True


def test_protocol_verification():
    """Test that only acceptable protocols types are accepted."""
    host = ipaddress.ip_address(u"127.0.0.1")
    scanner = Scanner(host, mock=True)

    scanner.perform_scan()

    scanner.extract_ports("tcp")
    scanner.extract_ports("udp")
    scanner.extract_ports("TCP")
    scanner.extract_ports("UDP")

    with pytest.raises(ValueError):
        scanner.extract_ports("http")

    with pytest.raises(ValueError):
        scanner.extract_ports("ssl")


def test_ports_scanning():
    """Test the scanning of ports.

    Test is ran on a machine with at least ports 22/80/443 opened.
    """
    host = ipaddress.ip_address(u"92.222.10.88")
    scanner = Scanner(host, mock=True)

    assert scanner.is_local() is False
    assert scanner.run_ping_test() is True

    scanner.perform_scan()
    ports = scanner.extract_ports("tcp")

    assert len(ports) >= 3
    for port in ports:
        assert port.__class__ == PortReport

    expected_ports = [22, 80, 443]
    port_numbers = [port.port_number for port in ports]
    for expected_port in expected_ports:
        assert expected_port in port_numbers


def test_scanning_sudo():
    """Test scanning when necessary to run as sudo."""
    host = ipaddress.ip_address(u"82.64.28.100")
    scanner = Scanner(host, mock=True, sudo=False)

    assert scanner.run_ping_test() is False

    # Run a first time without sudo
    scanner.perform_scan()
    ports = scanner.extract_ports("tcp")
    assert len(ports) == 0

    # Run as sudo
    scanner2 = Scanner(host, mock=True, sudo=True)
    scanner2.perform_scan()
    ports = scanner2.extract_ports("tcp")

    expected_ports = [22, 80, 443]
    assert len(ports) >= 3
    for port in ports:
        assert port.__class__ == PortReport

    port_numbers = [port.port_number for port in ports]
    for expected_port in expected_ports:
        assert expected_port in port_numbers


def test_scanner_handler_sudo():
    """Test full scanning when necessary to run as sudo."""
    host = ipaddress.ip_address(u"82.64.28.100")

    ipv4_hosts = [host]
    handler = ScannerHandler(ipv4_hosts, [], [], [], True, True)

    report = handler.run_scans()

    assert report.nb_hosts == 1
    assert report.up == 1
    assert report.results[0].hostname == "acne.bad"
    assert len(report.results[0].ports) == 3

    ports = [port.port_number for port in report.results[0].ports]
    expected_ports = [22, 80, 443]
    for port in expected_ports:
        assert port in ports


def test_host_scanning():
    """Test the report extraction from a complete host."""
    host = ipaddress.ip_address(u"92.222.10.88")
    scanner = Scanner(host, mock=True)
    scanner.perform_scan()
    scanner.find_vulnerabilities()

    report = scanner.extract_host_report()
    assert report.__class__ == HostReport

    assert report.hostname == "example.com"
    assert report.ip == "92.222.10.88"
    assert report.mac == ""
    assert report.state == "up"
    assert len(report.ports) >= 3
    assert report.operating_system == ""
    assert report.operating_system_accuracy == ""

    for port in report.ports:
        assert port.__class__ == PortReport
        if port.port_number == 443:
            assert len(port.vulnerabilities) == 1
            assert port.vulnerabilities[0].cve == "CVE-2007-6750"

    expected_ports = [22, 80, 443]
    port_numbers = [port.port_number for port in report.ports]
    for expected_port in expected_ports:
        assert expected_port in port_numbers


def test_os_detection():
    """Test the os detection from a host."""
    host = ipaddress.ip_address(u"92.222.10.88")
    scanner = Scanner(host, mock=True, sudo=True)
    scanner.perform_scan()

    report = scanner.extract_host_report()
    assert report.operating_system == "linux 3.7 - 3.10"
    assert report.operating_system_accuracy == "100"


def test_host_scanning_ipv6():
    """Test the report extraction from an IPV6 host."""
    host = ipaddress.ip_address(u"::1")
    scanner = Scanner(host, True, mock=True)
    scanner.perform_scan()

    report = scanner.extract_host_report()
    assert report.__class__ == HostReport

    assert report.hostname == "localhost"
    assert report.ip == "::1"
    assert report.state == "up"
    assert len(report.ports) >= 0


def test_scanning_handling_unreachable():
    """Test scanning a host when we are sure it's unreachable."""
    host = ipaddress.ip_address(u"192.0.2.1")
    scanner_handler = ScannerHandler([host], [], [], [], mock=True, sudo=True)
    result = scanner_handler.run_scans()

    assert result.nb_hosts == 1
    assert result.up == 0


def test_scanning_handling_skip_ping():
    """Test scanning a host when we are not sure whether up or not."""
    host = ipaddress.ip_address(u"82.64.28.100")
    scanner_handler = ScannerHandler([host], [], [], [], mock=True, sudo=False)
    result = scanner_handler.run_scans()

    assert result.nb_hosts == 1
    assert result.up == 1


def test_scanner_handler_creation():
    """Test the creation of a ScannerHandler object."""
    ipv4_hosts = [
        ipaddress.ip_address(u"127.0.0.1"),
        ipaddress.ip_address(u"92.222.10.88"),
    ]
    ipv6_hosts = [ipaddress.ip_address(u"::1")]
    ipv4_networks = [ipaddress.ip_network(u"192.168.0.0/30")]
    ipv6_networks = [
        ipaddress.ip_network(u"2a01:0e0a:0129:5ed0:0211:32ff:fe2d:6800/120")
    ]

    scanner_handler = ScannerHandler(
        ipv4_hosts, ipv6_hosts, ipv4_networks, ipv6_networks, mock=True
    )

    assert len(scanner_handler.ipv4_hosts) == 2
    assert len(scanner_handler.ipv6_hosts) == 1
    assert len(scanner_handler.ipv4_networks) == 1
    assert len(scanner_handler.ipv6_networks) == 1

    for host in scanner_handler.ipv4_hosts:
        assert host.__class__ == ipaddress.IPv4Address
    for host in scanner_handler.ipv6_hosts:
        assert host.__class__ == ipaddress.IPv6Address
    for host in scanner_handler.ipv4_networks:
        assert host.__class__ == ipaddress.IPv4Network
    for host in scanner_handler.ipv6_networks:
        assert host.__class__ == ipaddress.IPv6Network

    assert len(scanner_handler.scanners) == 260
    for scanner in scanner_handler.scanners:
        assert scanner.__class__ == Scanner


def test_scan_handling():
    """Test that scanning is performed without issue."""
    ipv4_hosts = [
        ipaddress.ip_address(u"127.0.0.1"),
        ipaddress.ip_address(u"192.0.2.1"),
    ]
    scanner_handler = ScannerHandler(ipv4_hosts, [], [], [], mock=True)
    hosts_queue = Queue()
    lock = threading.Lock()
    term = blessings.Terminal()
    sem = threading.Semaphore(4)

    scanner_handler.run_scan(
        scanner_handler.scanners[0], hosts_queue, lock, term, sem
    )

    assert hosts_queue.qsize() == 1
    assert hosts_queue.get().__class__ == HostReport


def test_running_scans():
    """Test running full scans."""
    ipv4_hosts = [ipaddress.ip_address(u"127.0.0.1")]
    # ipv6_hosts = [
    # ipaddress.ip_address(u"::1")
    # ]

    scanner_handler = ScannerHandler(ipv4_hosts, [], [], [], mock=True)
    report = scanner_handler.run_scans()

    assert report.__class__ == Report
    assert report.nb_hosts == 1
    assert report.up == 1
    assert type(report.duration) == str
    assert "127.0.0.1" in [x.ip for x in report.results]
    # assert "::1" in [x.ip for x in report.results]


def test_finding_vulnerabilities():
    """Test using the scanner for vulnerabilities."""
    host = ipaddress.ip_address(u"92.222.10.88")

    scanner = Scanner(host, mock=True)
    scanner.perform_scan()
    scanner.find_vulnerabilities()

    for vulnerability in scanner.vulnerabilities[443]:
        assert vulnerability.__class__ == Vulnerability

    assert len(scanner.vulnerabilities[22]) == 0
    assert len(scanner.vulnerabilities[80]) == 0
    assert len(scanner.vulnerabilities[443]) == 1

    vulnerability = scanner.vulnerabilities[443][0]
    assert vulnerability.service == "nginx"
    assert vulnerability.cve == "CVE-2007-6750"
    assert vulnerability.description == "Slowloris DOS attack"
    assert (
        vulnerability.link
        == "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750"
    )


def test_finding_vulnerabilities_ipv6():
    """Test running the scanner for vulnerabilities on IPV6 host."""
    host = ipaddress.ip_address(u"::1")

    scanner = Scanner(host, mock=True, is_ipv6=True)
    scanner.find_vulnerabilities()

    assert scanner.vulnerabilities == {}


def test_finding_vulnerabilities_invalid_host():
    """Test running the vulnerability scanner on unreachable host."""
    host = ipaddress.ip_address(u"192.0.2.1")
    scanner = Scanner(host, mock=True)
    scanner.find_vulnerabilities()
    assert scanner.scanner._scan_result == {}

#first step : analysis code is not complete
#second step : searching and more data about line by line 
#third step : debug it !!!