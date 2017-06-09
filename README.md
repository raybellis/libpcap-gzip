libpcap-gzip
============

This package creates a shared library that acts as a plugin that
adds gzip file reading and writing support to a modified version
of libpcap.

Enabling the plugin requires setting the `PCAP_IOPLUGIN_READ`
and/or `PCAP_IOPLUGIN_WRITE` environment variables to the location
of the shared library before running any libpcap-based application.

TODO
----

- Add compression settings support
