// diagnostic_message_ack.c

#include "diagnostic_message_ack.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_source_address = -1;
static int hf_target_address = -1;
static int hf_ack_code = -1;
static int hf_previous = -1;


gint add_diagnostic_message_ack_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset)
{
	gint remaining = 0;
	proto_tree_add_item(doip_tree, hf_source_address, tvb, offset + 0, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_target_address, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_ack_code, tvb, offset + 4, 1, ENC_BIG_ENDIAN);

	remaining = tvb_captured_length_remaining(tvb, offset + 5);
	if (remaining > 0)
	{
	    proto_tree_add_item(doip_tree, hf_previous, tvb, offset + 5, remaining, ENC_BIG_ENDIAN);
	}

	return offset + 5 + remaining;
}


static const value_string diag_ack_codes[] = {
    { 0x00, "ACK" },
    { 0, NULL }
};


void proto_register_diagnostic_message_ack(gint proto_doip)
{

	static hf_register_info hf_diagnostic_message_ack[] = 
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
			&hf_ack_code,
			{
				"ACK code", "doip.ack_code",
				FT_UINT8, BASE_HEX,
				VALS(diag_ack_codes), 0x00,
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

	proto_register_field_array(proto_doip, hf_diagnostic_message_ack, array_length(hf_diagnostic_message_ack));
}
