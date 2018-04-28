// generic_header_nack.c

#include "generic_header_nack.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_generic_nack_code = -1;


gint add_generic_header_nack_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset)
{
	proto_tree_add_item(doip_tree, hf_generic_nack_code, tvb, offset + 0, 1, ENC_BIG_ENDIAN);

	return offset + 1;
}

static const value_string nack_codes[] = {
    { 0x00, "Incorrect pattern format" },
    { 0x01, "Unknown payload type" },
    { 0x02, "Message too large" },
    { 0x03, "Out of memory" },
    { 0x04, "Invalid payload length" },
    { 0, NULL }
};


void register_generic_header_nack(gint proto_doip)
{
	static hf_register_info hf_generic_header_nack[] = 
	{
		{
			&hf_generic_nack_code,
			{
				"DoIP Header NACK code", "doip.nack_code",
				FT_UINT8, BASE_HEX,
				VALS(nack_codes), 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_doip, hf_generic_header_nack, array_length(hf_generic_header_nack));
}
