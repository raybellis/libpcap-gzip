#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <zlib.h>
#include <pcap.h>

#if HAVE_FUNOPEN

static int gzip_cookie_read(void *cookie, char *buf, int size)
{
	return gzread((gzFile)cookie, (voidp)buf, (unsigned)size);
}

static int gzip_cookie_write(void *cookie, const char *buf, int size)
{
	return gzwrite((gzFile)cookie, (voidpc)buf, (unsigned)size);
}

static int gzip_cookie_close(void *cookie) {
	return gzclose((gzFile)cookie);
}

#elif HAVE_FOPENCOOKIE

static ssize_t gzip_cookie_read(void *cookie, char *buf, size_t size)
{
	return gzread((gzFile)cookie, (voidp)buf, (unsigned)size);
}

static ssize_t gzip_cookie_write(void *cookie, const char *buf, size_t size)
{
	return gzwrite((gzFile)cookie, (voidpc)buf, (unsigned)size);
}

static int gzip_cookie_close(void *cookie) {
	return gzclose((gzFile)cookie);
}

static cookie_io_functions_t gzip_read_funcs = {
	.read = gzip_cookie_read,
	.close = gzip_cookie_close
};

static cookie_io_functions_t gzip_write_funcs = {
	.write = gzip_cookie_write,
	.close = gzip_cookie_close
};

#else

#error "no funopen() or fopencookie() available"

#endif

static FILE *gzip_open_read(const char *fname, char *errbuf)
{
	int			 fd = -1;
	gzFile		 cookie;
	FILE		*fp;

	if (strcmp(fname, "-") == 0) {
		/*
		 * dup so that zlib or libpcap don't close the real stdin.
		 *
		 * not sure why, but libpcap refuses to close stdin itself,
		 * perhaps to avoid a SIGPIPE
		 */
		fd = dup(fileno(stdin));
		if (fd < 0) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: dup: %s",
							fname, pcap_strerror(errno));
			return NULL;
		}
	} else {
		fd = open(fname, O_RDONLY);
		if (fd < 0) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: open: %s",
							fname, pcap_strerror(errno));
			return NULL;
		}
	}

	cookie = gzdopen(fd, "r");
	if (!cookie) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: gzdopen: %s",
							fname, pcap_strerror(errno));
		goto fail;
	}

#if HAVE_FUNOPEN
	fp = funopen(cookie, gzip_cookie_read, NULL, NULL, gzip_cookie_close);
	if (!fp) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: funopen: %s",
							fname, pcap_strerror(errno));
		goto fail;
	}
#elif HAVE_FOPENCOOKIE
	fp = fopencookie(cookie, "r", gzip_read_funcs);
	if (!fp) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: fopencookie: %s",
							fname, pcap_strerror(errno));
		goto fail;
	}
#endif

	return fp;

fail:
	if (cookie) {
		gzclose(cookie);
	} else if (fd >= 0) {
		close(fd);
	}

	return NULL;
}

static FILE *gzip_open_write(const char *fname, char *errbuf)
{
	int			 fd = -1;
	gzFile		 cookie;
	FILE		*fp;

	if (strcmp(fname, "-") == 0) {
		fd = fileno(stdout);
		if (fd < 0) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: fileno: %s",
							fname, pcap_strerror(errno));
			return NULL;
		}
	} else {
		fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		if (fd < 0) {
			snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: open: %s",
							fname, pcap_strerror(errno));
			return NULL;
		}
	}

	cookie = gzdopen(fd, "w");
	if (!cookie) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: gzdopen: %s",
							fname, pcap_strerror(errno));
		goto fail;
	}

	/* TODO: extra option support */

#if HAVE_FUNOPEN
	fp = funopen(cookie, NULL, gzip_cookie_write, NULL, gzip_cookie_close);
	if (!fp) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: funopen: %s",
							fname, pcap_strerror(errno));
		goto fail;
	}
#elif HAVE_FOPENCOOKIE
	fp = fopencookie(cookie, "w", gzip_write_funcs);
	if (!fp) {
		snprintf(errbuf, PCAP_ERRBUF_SIZE, "%s: fopencookie: %s",
							fname, pcap_strerror(errno));
		goto fail;
	}
#endif

	return fp;

fail:
	if (cookie) {
		gzclose(cookie);
	} else if (fd >= 0) {
		close(fd);
	}

	return NULL;
}

const pcap_ioplugin_t* ioplugin_init() {

	static pcap_ioplugin_t plugin = {
		.open_read = gzip_open_read,
		.open_write = gzip_open_write
	};

	return &plugin;
}
