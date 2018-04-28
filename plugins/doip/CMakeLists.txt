# CMakeLists.txt
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

include(WiresharkPlugin)

# Plugin name and version info (major minor micro extra)
set_module_info(doip 1 2 0 0)

set(DISSECTOR_SRC
	doip.c
)

set(DISSECTOR_SUPPORT_SRC
	generic_header_nack.c
	vehicle_announcement_message.c
	vehicle_identification_eid.c
	vehicle_identification_vin.c
	routing_activation_request.c
	routing_activation_response.c
	diagnostic_message.c
	diagnostic_message_ack.c
	diagnostic_message_nack.c
)


set(PLUGIN_FILES
	plugin.c
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

set(CLEAN_FILES
	${PLUGIN_FILES}
)

if (WERROR_COMMON_FLAGS)
	set_source_files_properties(
		${CLEAN_FILES}
		PROPERTIES
		COMPILE_FLAGS ${WERROR_COMMON_FLAGS}
	)
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

register_plugin_files(plugin.c
	plugin
	${DISSECTOR_SRC}
	${DISSECTOR_SUPPORT_SRC}
)

add_plugin_library(doip epan)

target_link_libraries(doip epan)

install_plugin(doip epan)

file(GLOB DISSECTOR_HEADERS RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" "*.h")
CHECKAPI(
	NAME
	  doip
	SWITCHES
	  -g abort -g termoutput -build
	SOURCES
	  ${DISSECTOR_SRC}
#	  ${DISSECTOR_SUPPORT_SRC}
	  ${DISSECTOR_HEADERS}
)
