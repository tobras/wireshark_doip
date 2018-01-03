/* packet-uds.c
 * Routines for UDS packet disassembly
 *
 * Copyright (c) 2015 by Diadrom AB
 *
 * Author: Tobias Rasmusson
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Include files */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include <epan/prefs.h>

#include "diagnostic_session_control.h"
#include "ecu_reset.h"
#include "tester_present.h"
#include "read_data_by_identifier.h"
#include "write_data_by_identifier.h"
#include "negative_response.h"
#include "security_access.h"
#include "routine_control.h"
#include "request_download.h"
#include "transfer_data.h"
#include "request_transfer_exit.h"

static const value_string uds_services[] = {
    { 0x10, "DiagnosticSessionControl" },
    { 0x11, "ECUReset" },
    { 0x14, "ClearDiagnosticInformation" },
    { 0x19, "ReadDTCInformation" },
    { 0x22, "ReadDataByIdentifier" }, 
    { 0x23, "ReadMemoryByAddress" },
    { 0x24, "ReadScalingDataByIdentifier" },
    { 0x27, "SecurityAccess" },
    { 0x28, "CommunicationControl" },
    { 0x2A, "ReadDataByPeriodicIdentifier" },
    { 0x2C, "DynamicallyDefineDataIdentifier" },
    { 0x2E, "WriteDataByIdentifier" },
    { 0x2F, "InputOutputControlByIdentifier" },
    { 0x31, "RoutineControl" },
    { 0x34, "RequestDownload" },
    { 0x35, "RequestUpload" },
    { 0x36, "TransferData" },
    { 0x37, "RequestTransferExit" },
    { 0x3D, "WriteMemoryByAddress" },

    { 0x3E, "TesterPresent" },

    { 0x83, "AccessTimingParameter" },
    { 0x84, "SecuredDataTransmission" },
    { 0x85, "ControlDTCSetting" },
    { 0x86, "ResponseOnEvent" },
    { 0x87, "LinkControl" },


    { 0x50, "DiagnosticSessionControl Response" },
    { 0x51, "ECUReset Response" },
    { 0x54, "ClearDiagnosticInformation Response" },
    { 0x59, "ReadDTCInformation Response" },    
    { 0x62, "ReadDataByIdentifier Response" },

    { 0x63, "ReadMemoryByAddress Response" },
    { 0x64, "ReadScalingDataByIdentifier Response" },
    { 0x67, "SecurityAccess Response" },
    { 0x68, "CommunicationControl Response" },
    { 0x6A, "ReadDataByPeriodicIdentifier Response" },
    { 0x6C, "DynamicallyDefineDataIdentifier Response" },
    { 0x6E, "WriteDataByIdentifier Response" },
    { 0x6F, "InputOutputControlByIdentifier Response" },
    { 0x71, "RoutineControl Response" },
    { 0x74, "RequestDownload Response" },
    { 0x75, "RequestUpload Response" },
    { 0x76, "TransferData Response" },
    { 0x77, "RequestTransferExit Response" },
    { 0x7D, "WriteMemoryByAddress Response" },
    { 0x7E, "TesterPresent Response" },
    { 0x7F, "Negative Response" },

    { 0xC3, "AccessTimingParameter Response" },
    { 0xC4, "SecuredDataTransmission Response" },
    { 0xC5, "ControlDTCSetting Response" },
    { 0xC6, "ResponseOnEvent Response" },
    { 0xC7, "LinkControl Response" },
    { 0, NULL }
};


static gint proto_uds    = -1;
static gint ett_uds = -1;

// Header
static int hf_uds_service = -1;

gint add_header(proto_tree *uds_tree, tvbuff_t *tvb)
{
    proto_tree_add_item(uds_tree, hf_uds_service, tvb, 0, 1, ENC_BIG_ENDIAN);

    return 1;
}

/* Uds protocol dissector */
static int dissect_uds_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    gint offset = 0;
    guint8 service = 0;
    proto_tree *uds_tree = NULL;

    service = tvb_get_guint8(tvb, 0);
    
    col_clear(pinfo->cinfo, COL_PROTOCOL);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDS"); // The protocol column will say UDS

    // Clear out stuff in the info column
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(service, uds_services, "0x%02x Unknown service"));

    offset++; // Service consumed

    if (tree)
    {
        // we are being asked for details
        proto_item *ti = NULL;

        ti = proto_tree_add_item(tree, proto_uds, tvb, 0, -1, ENC_NA);
        uds_tree = proto_item_add_subtree(ti, ett_uds);
	add_header(uds_tree, tvb);
    }

    switch (service)
    {
		case 0x10:
			add_diagnostic_session_control_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x50:
			add_diagnostic_session_control_response_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x11:
			add_ecu_reset_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x51:
			add_ecu_reset_response_fields(uds_tree, pinfo, tvb, offset);
			break;		
		case 0x22:
			add_read_data_by_identifier_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x62:
			add_read_data_by_identifier_response_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x27:
			add_security_access_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x67:
			add_security_access_response_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x2E:
			add_write_data_by_identifier_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x6E:
			add_write_data_by_identifier_response_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x31:
			add_routine_control_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x71:
			add_routine_control_response_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x34:
			add_request_download_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x74:
			add_request_download_response_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x36:
			add_transfer_data_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x76:
			add_transfer_data_response_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x37:
			add_request_transfer_exit_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x77:
			add_request_transfer_exit_response_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x3E:
			add_tester_present_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x7E:
			add_tester_present_response_fields(uds_tree, pinfo, tvb, offset);
			break;
		case 0x7F:
			add_negative_response_fields(uds_tree, pinfo, tvb, offset);
			break;
			
    }
    
    return tvb_captured_length(tvb);
}

/* Register Uds Protocol header */
void proto_register_uds_header(void)
{
    static hf_register_info hf[] = {
        { &hf_uds_service,
	  { "Service", "uds.service",
	    FT_UINT8, BASE_HEX,
            VALS(uds_services), 0x00,
            NULL, HFILL }
        }
    };

    proto_register_field_array(proto_uds, hf, array_length(hf));
}


void proto_register_uds(void)
{
    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_uds
    };

    proto_uds = proto_register_protocol (
	"UDS Protocol", /* name       */
	"UDS_DoIP",              /* short name */
	"uds_doip"                      /* abbrev     */
	);

 

    proto_register_uds_header();

    proto_register_diagnostic_session_control(proto_uds);
    proto_register_diagnostic_session_control_response(proto_uds);

    proto_register_ecu_reset(proto_uds);
    proto_register_ecu_reset_response(proto_uds);

    proto_register_tester_present(proto_uds);
    proto_register_tester_present_response(proto_uds);

    proto_register_read_data_by_identifier(proto_uds);
    proto_register_read_data_by_identifier_response(proto_uds);

    proto_register_write_data_by_identifier(proto_uds);
    proto_register_write_data_by_identifier_response(proto_uds);

    proto_register_security_access(proto_uds);
    proto_register_security_access_response(proto_uds);

    proto_register_routine_control(proto_uds);
    proto_register_routine_control_response(proto_uds);
    
    proto_register_request_download(proto_uds);
    proto_register_request_download_response(proto_uds);

    proto_register_transfer_data(proto_uds);
    proto_register_transfer_data_response(proto_uds);

    proto_register_request_transfer_exit(proto_uds);
    proto_register_request_transfer_exit_response(proto_uds);

    
    proto_register_negative_response(proto_uds);
    
    proto_register_subtree_array(ett, array_length(ett));
    register_dissector("uds", dissect_uds_message, proto_uds);
}

