libpcap-gzip
============

This package creates a shared library that acts as a plugin that
adds gzip file reading support to a modified version of libpcap.

Enabling the plugin requires setting the `PCAP_PLUGIN_READ` to
the location of the shared library before running any libpcap-
based application.

TODO
----

- Add compression settings support
