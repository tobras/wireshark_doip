/* packet-doip.c
 * Routines for DoIP TCP and UDP packet disassembly
 *
 * Copyright (c) 2014 by Diadrom AB
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
#include "generic_header_nack.h"

#include "vehicle_identification_eid.h"

#include "vehicle_identification_vin.h"
#include "vehicle_announcement_message.h"

#include "routing_activation_request.h"
#include "routing_activation_response.h"

#include "diagnostic_message.h"
#include "diagnostic_message_ack.h"
#include "diagnostic_message_nack.h"

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/prefs.h>

#include <epan/dissectors/packet-ssl.h>

#define DOIP_PORT 13400

#define DOIP_HEADER_SIZE 8

static gint proto_doip    = -1;
static gint ett_doip = -1;

// Header
static int hf_doip_version = -1;
static int hf_doip_inv_version = -1;
static int hf_doip_type = -1;
static int hf_doip_length = -1;
static gboolean doip_desegment = TRUE;

static dissector_handle_t uds_handle = 0;
static dissector_handle_t doip_handle;

static const value_string doip_payloads[] = 
{
    { 0x0000, "Generic DoIP header NACK" },
    { 0x0001, "Vehicle identification request" },
    { 0x0002, "Vehicle identification request with EID" },
    { 0x0003, "Vehicle identification request with VIN" },
    { 0x0004, "Vehicle announcement message/vehicle identification response message" },
    { 0x0005, "Routing activation request" },
    { 0x0006, "Routing activation response" },
    { 0x0007, "Alive check request" },
    { 0x0008, "Alive check response" },
    { 0x4001, "DoIP entity status request" },
    { 0x4002, "DoIP entity status response" },
    { 0x4003, "Diagnostic power mode information request" },
    { 0x4004, "Diagnostic power mode information response" },
    { 0x8001, "Diagnostic message" },
    { 0x8002, "Diagnostic message ACK" },
    { 0x8003, "Diagnostic message NACK" },
    { 0, NULL }
};



gint add_header(proto_tree *doip_tree, tvbuff_t *tvb)
{
    proto_tree_add_item(doip_tree, hf_doip_version, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(doip_tree, hf_doip_inv_version, tvb, 1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(doip_tree, hf_doip_type, tvb, 2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(doip_tree, hf_doip_length, tvb, 4, 4, ENC_BIG_ENDIAN);

    return DOIP_HEADER_SIZE;
}



/* DoIP protocol dissector */
static void dissect_doip_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    gint offset = 0;
    
    guint8 version = tvb_get_guint8(tvb, 0);
    guint16 payload_type = tvb_get_ntohs(tvb, 2);
    //guint lenght = tvb_get_ntohl(tvb, 4);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "DoIP");
    if (version == 0xFF && (payload_type > 0 && payload_type < 4))
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(payload_type, doip_payloads, "0x%04x Unknown payload"));	
    }
    else if (version != 0x02)
    {
	col_set_str(pinfo->cinfo, COL_INFO, "DoIP version not supported");
	return;
    }
    else
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s", val_to_str(payload_type, doip_payloads, "0x%04x Unknown payload"));
	if (payload_type == 0x8001 && tree == NULL)
	{
	    // Add UDS info to info column when not viewing details
	    set_uds_info(tvb, pinfo, DOIP_HEADER_SIZE, uds_handle, NULL);
	}
    }
    

    if (tree) { /* we are being asked for details */
        proto_item *ti = NULL;
        proto_tree *doip_tree = NULL;

        ti = proto_tree_add_item(tree, proto_doip, tvb, 0, -1, ENC_NA);
        doip_tree = proto_item_add_subtree(ti, ett_doip);

        offset = add_header(doip_tree, tvb);
	
        switch (payload_type)
	{
	case 0x0000:
	    add_generic_header_nack_fields(doip_tree, tvb, offset); 
	    break;
	case 0x0002:
	    add_vehicle_identification_eid_fields(doip_tree, tvb, offset); 
	    break;
	case 0x0003:
	    add_vehicle_identification_vin_fields(doip_tree, tvb, offset); 
	    break;
	case 0x0004:
	    add_vehicle_announcement_message_fields(doip_tree, tvb, offset); 
	    break;
        case 0x0005:
	    add_routing_activation_request_fields(doip_tree, tvb, offset); 
	    break;
	case 0x0006:
	    add_routing_activation_response_fields(doip_tree, tvb, offset); 
	    break;
	case 0x8001:
	    offset = add_diagnostic_message_fields(doip_tree, tvb, pinfo, offset, uds_handle, tree);
	    break;
	    case 0x8002:
	    add_diagnostic_message_ack_fields(doip_tree, tvb, offset); 
	    break;
	case 0x8003:
	    add_diagnostic_message_nack_fields(doip_tree, tvb, offset); 
	    break;
	}	
    }
}

// determine PDU length of protocol DoIP
static guint get_doip_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *p)
{
    const guint DOIP_HEADER_LEN = 8;
    return (guint)tvb_get_ntohl(tvb, offset+4) + DOIP_HEADER_LEN; // length is at offset 4 and is 4 bytes
}

static int dissect_doip_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    dissect_doip_message(tvb, pinfo, tree);
    return tvb_captured_length(tvb);
}


static int dissect_doip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    const guint DOIP_HEADER_LEN = 8; // DoIP header length - must get length
    tcp_dissect_pdus(tvb, pinfo, tree, doip_desegment, DOIP_HEADER_LEN, get_doip_message_len, dissect_doip_pdu, data);
    return tvb_captured_length(tvb);
}


/* Register DoIP Protocol header */
void register_doip_header(void)
{
    static hf_register_info hf[] = {
        { &hf_doip_version,
	  { "Version", "doip.version",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_doip_inv_version,
	  { "Inverse version", "doip.inverse",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
	{ &hf_doip_type,
	  { "Type", "doip.type",
            FT_UINT16, BASE_HEX,
            VALS(doip_payloads), 0x0,
            NULL, HFILL }
        },
	{ &hf_doip_length,
	  { "Length", "doip.length",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        }
    };

    proto_register_field_array(proto_doip, hf, array_length(hf));
}


/* Register DoIP Protocol */
void proto_register_doip(void)
{
    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_doip
    };

    module_t *doip_module;   

    proto_doip = proto_register_protocol (
	"DoIP Protocol", /* name       */
	"DoIP",              /* short name */
	"doip"                      /* abbrev     */
	);

    doip_module = prefs_register_protocol(proto_doip, NULL); 

    prefs_register_bool_preference(doip_module, "desegment",
    "Reassemble DoIP messages spanning multiple TCP segments",
    "Whether the DoIP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable"
    " \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &doip_desegment);

    register_doip_header();
    
    register_generic_header_nack(proto_doip);
    
    register_vehicle_identification_eid(proto_doip);
    register_vehicle_identification_vin(proto_doip);

    register_vehicle_announcement_message(proto_doip);
    
    register_routing_activation_request(proto_doip);
    register_routing_activation_response(proto_doip);

    register_diagnostic_message(proto_doip);
    register_diagnostic_message_ack(proto_doip);
    register_diagnostic_message_nack(proto_doip);

    proto_register_subtree_array(ett, array_length(ett));
}

/* Register DoIP Protocol handler */
void proto_reg_handoff_doip(void)
{
    doip_handle = create_dissector_handle(dissect_doip, proto_doip);
    dissector_add_uint("udp.port", DOIP_PORT, doip_handle);
    dissector_add_uint("tcp.port", DOIP_PORT, doip_handle);
//    ssl_dissector_add(DOIP_PORT, "doip", TRUE);

    uds_handle = find_dissector("uds");
}
