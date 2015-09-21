xlator_LTLIBRARIES = gfrichacl.la
xlatordir = $(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/system
gfrichacl_la_LDFLAGS = -module -avoid-version
gfrichacl_la_SOURCES = gfrichacl.c gfrichacl-xattr.c
gfrichacl_la_LIBADD = $(top_builddir)/libglusterfs/src/libglusterfs.la  -lrichacl

noinst_HEADERS = gfrichacl.h gfrichacl-xattr.h gfrichacl-mem-types.h

AM_CPPFLAGS = $(GF_CPPFLAGS) -I$(top_srcdir)/libglusterfs/src

AM_CFLAGS = -Wall $(GF_CFLAGS)

AM_LDFLAGS = -L$(xlatordir)

CLEANFILES =

gfrichacl-compat:
	mkdir -p $(DESTDIR)$(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features
	rm -rf $(DESTDIR)$(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features/gfrichacl.so
	ln -s ../system/gfrichacl.so $(DESTDIR)$(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features/gfrichacl.so


install-exec-local: gfrichacl-compat

uninstall-local:
	rm -f $(DESTDIR)$(libdir)/glusterfs/$(PACKAGE_VERSION)/xlator/features/gfrichacl.so
