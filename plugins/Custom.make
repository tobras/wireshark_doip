#
# $Id$
#

_CUSTOM_SUBDIRS_ = \
	doip \
	uds

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/doip/doip.la \
	-dlopen plugins/uds/uds.la
