// routing_activation_response.c

#include "routing_activation_response.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_tester_logical_address = -1;
static int hf_entity_logical_address = -1;
static int hf_response_code = -1;
static int hf_reserved_iso = -1;
static int hf_reserved_oem = -1;


gint add_routing_activation_response_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset)
{
	proto_tree_add_item(doip_tree, hf_tester_logical_address, tvb, offset + 0, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_entity_logical_address, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_response_code, tvb, offset + 4, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_reserved_iso, tvb, offset + 5, 4, ENC_BIG_ENDIAN);
	if ( tvb_bytes_exist(tvb, offset, 13) )
	{
	    proto_tree_add_item(doip_tree, hf_reserved_oem, tvb, offset + 9, 4, ENC_BIG_ENDIAN);

	    return offset + 13;
	}

	return offset + 9;
}

static const value_string activation_codes[] = {
    { 0x00, "Routing activation denied due to unknown source address." },
    { 0x01, "Routing activation denied because all concurrently supported TCP_DATA sockets are registered and active." },
    { 0x02, "Routing activation denied because an SA different from the table connection entry was received on the already activated TCP_DATA socket." },
    { 0x03, "Routing activation denied because the SA is already registered and active on a different TCP_DATA socket." },
    { 0x04, "Routing activation denied due to missing authentication." },
    { 0x05, "Routing activation denied due to rejected confirmation." },
    { 0x06, "Routing activation denied due to unsupported routing activation type." },
    { 0x07, "Reserved by ISO 13400." },
    { 0x08, "Reserved by ISO 13400." },
    { 0x09, "Reserved by ISO 13400." },
    { 0x0A, "Reserved by ISO 13400." },
    { 0x0B, "Reserved by ISO 13400." },
    { 0x0C, "Reserved by ISO 13400." },
    { 0x0D, "Reserved by ISO 13400." },
    { 0x0E, "Reserved by ISO 13400." },
    { 0x0F, "Reserved by ISO 13400." },
    { 0x10, "Routing successfully activated." },
    { 0x11, "Routing will be activated; confirmation required." },
    { 0, NULL }
};

void proto_register_routing_activation_response(gint proto_doip)
{
	static hf_register_info hf_routing_activation_response[] = 
	{
		{
			&hf_tester_logical_address,
			{
				"Logical address of external tester", "doip.tester_logical_address",
				FT_UINT16, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_entity_logical_address,
			{
				"Logical address of DoIP entity", "doip.entity_logical_address",
				FT_UINT16, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_response_code,
			{
				"Routing activation response code", "doip.response_code",
				FT_UINT8, BASE_HEX,
				VALS(activation_codes), 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_reserved_iso,
			{
				"Reserved by ISO", "doip.reserved_iso",
				FT_UINT32, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_reserved_oem,
			{
				"Reserved by OEM", "doip.reserved_oem",
				FT_UINT32, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_doip, hf_routing_activation_response, array_length(hf_routing_activation_response));
}
