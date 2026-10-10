"""Bounded A/AAAA lookups through the VM/container's configured DNS resolver."""
import ipaddress

import dns.exception
import dns.resolver


def resolve_host(host):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1
    addresses, failures = set(), []
    for record_type in ('A', 'AAAA'):
        try:
            answer = resolver.resolve(host + '.', record_type, lifetime=1.5, search=False)
            addresses.update(str(ipaddress.ip_address(record.address)) for record in answer)
        except dns.resolver.NXDOMAIN:
            break
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.Timeout:
            failures.append('timeout')
        except dns.exception.DNSException:
            failures.append('error')
    ips = sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version, int(ipaddress.ip_address(value))))
    status = ('partial' if failures else 'resolved') if ips else ('timeout' if 'timeout' in failures else 'error') if failures else 'no_records'
    return ips, status
