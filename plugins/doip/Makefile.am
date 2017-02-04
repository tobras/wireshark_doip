# Makefile.am
# Automake file for DoIP plugin
#
# $Id$
#
# Wireshark - Network traffic analyzer
# By Gerald Combs <gerald@wireshark.org>
# Copyright 1998 Gerald Combs
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

include $(top_srcdir)/Makefile.am.inc
include ../Makefile.am.inc

# the name of the plugin
PLUGIN_NAME = doip

# Non-generated sources to be scanned for registration routines
NONGENERATED_REGISTER_C_FILES = \
	diagnostic_message_ack.c \
	diagnostic_message_nack.c \
	diagnostic_message.c \
	generic_header_nack.c \
	packet-doip.c \
	routing_activation_request.c \
	routing_activation_response.c \
	vehicle_announcement_message.c \
	vehicle_identification_eid.c \
	vehicle_identification_vin.c

# Non-generated sources
NONGENERATED_C_FILES = \
	$(NONGENERATED_REGISTER_C_FILES)

# Headers.
CLEAN_HEADER_FILES =	

HEADER_FILES = \
	$(FLEX_GENERATED_HEADER_FILES) \
	$(CLEAN_HEADER_FILES)

plugin_LTLIBRARIES = doip.la

doip_la_SOURCES = \
	plugin.c \
	moduleinfo.h \
	$(SRC_FILES)	\
	$(HEADER_FILES)

doip_la_CPPFLAGS = $(AM_CPPFLAGS) $(PLUGIN_CPPFLAGS)

doip_la_CFLAGS = $(AM_CFLAGS) $(PLUGIN_CFLAGS)

doip_la_LDFLAGS = $(PLUGIN_LDFLAGS)

CLEANFILES = \
	doip \
	*~

MAINTAINERCLEANFILES = \
	Makefile.in \
	plugin.c

EXTRA_DIST = \
	plugin.rc.in		\
	README			\
	CMakeLists.txt
