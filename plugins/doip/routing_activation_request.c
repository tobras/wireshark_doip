// routing_activation_request.c

#include "routing_activation_request.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_source_address = -1;
static int hf_activation_type = -1;
static int hf_reserved_iso = -1;
static int hf_reserved_oem = -1;


gint add_routing_activation_request_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset)
{
	proto_tree_add_item(doip_tree, hf_source_address, tvb, offset + 0, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_activation_type, tvb, offset + 2, 1, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_reserved_iso, tvb, offset + 3, 4, ENC_BIG_ENDIAN);

	if ( tvb_bytes_exist(tvb, offset, 11) )
	{
	    proto_tree_add_item(doip_tree, hf_reserved_oem, tvb, offset + 7, 4, ENC_BIG_ENDIAN);

	    return offset + 11;
	}

	return offset + 7;
}

static const value_string activation_types[] = {
    { 0x00, "Default" },
    { 0x01, "WWH-OBD" },
    { 0xE0, "Central security" },
    { 0, NULL }
};

void proto_register_routing_activation_request(gint proto_doip)
{
	static hf_register_info hf_routing_activation_request[] = 
	{
		{
			&hf_source_address,
			{
				"Source Address", "doip.source_address",
				FT_UINT16, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_activation_type,
			{
				"Activation type", "doip.activation_type",
				FT_UINT8, BASE_HEX,
				VALS(activation_types), 0x00,
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

	proto_register_field_array(proto_doip, hf_routing_activation_request, array_length(hf_routing_activation_request));
}
