TLSFetch
----
...SUPER SPEED...
Small Go client to fetch SSL certs and extract host names.

Usage:
---
Fetch for a single host (takes CIDR Notation as well):
* tlsfetchgo -t 10.10.10.1
* tlsfetchgo -t 10.10.10.1/24

Fetch for a list of hosts (one per line)
* tlsfetchgo -iL hosts.txt

To check the SSL signature and if SSLv2 and SSLv3 are supported:
* tlsfetchgo -iL hosts.txt -sig -ssl

You can also specify custom port(s) with the -p
* tlsfetchgo -iL hosts.txt -p 443,8443,9443

Cheers
---
