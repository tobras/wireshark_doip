// diagnostic_message_nack.c

#include "diagnostic_message_nack.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_source_address = -1;
static int hf_target_address = -1;
static int hf_nack_code = -1;
static int hf_previous = -1;


gint add_diagnostic_message_nack_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset)
{
	gint remaining = 0;
	proto_tree_add_item(doip_tree, hf_source_address, tvb, offset + 0, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_target_address, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_nack_code, tvb, offset + 4, 1, ENC_BIG_ENDIAN);

	remaining = tvb_captured_length_remaining(tvb, offset + 5);
	if (remaining > 0)
	{
	    proto_tree_add_item(doip_tree, hf_previous, tvb, offset + 5, remaining, ENC_BIG_ENDIAN);
	}

	return offset + 5 + remaining;
}


static const value_string nack_codes[] = {
    { 0x00, "Reserved by ISO 13400" },
    { 0x01, "Reserved by ISO 13400" },
    { 0x02, "Invalid source address" },
    { 0x03, "Unknown target address" },
    { 0x04, "Diagnostic message too large" },
    { 0x05, "Out of memory" },
    { 0x06, "Target unreachable" },
    { 0x07, "Unknown network" },
    { 0x08, "Transport protocol error" },
    { 0, NULL }
};



void proto_register_diagnostic_message_nack(gint proto_doip)
{
	static hf_register_info hf_diagnostic_message_nack[] = 
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
			&hf_target_address,
			{
				"Target Address", "doip.target_address",
				FT_UINT16, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_nack_code,
			{
				"NACK code", "doip.nack_code",
				FT_UINT8, BASE_HEX,
				VALS(nack_codes), 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_previous,
			{
				"Previous message", "doip.previous",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_doip, hf_diagnostic_message_nack, array_length(hf_diagnostic_message_nack));
}
