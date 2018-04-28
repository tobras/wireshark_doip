#
# $Id$
#

_CUSTOM_SUBDIRS_ = \
	epan/doip

_CUSTOM_EXTRA_DIST_ = \
	Custom.m4 \
	Custom.make

_CUSTOM_plugin_ldadd_ = \
	-dlopen plugins/epan/doip/doip.la


