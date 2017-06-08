// diagnostic_message.c

#include "diagnostic_message.h"

#include  "config.h"
#include <epan/packet.h>

static int hf_source_address = -1;
static int hf_target_address = -1;
static int hf_data = -1;

#define DIAG_MESSAGE_HEADER_SIZE 4

void set_uds_info(tvbuff_t *tvb, packet_info *pinfo, gint offset, dissector_handle_t uds_handle, proto_tree *parent_tree)
{
    if (uds_handle != 0)
    {
	call_dissector(uds_handle, tvb_new_subset_length_caplen(tvb, offset + DIAG_MESSAGE_HEADER_SIZE, -1, -1), pinfo, parent_tree);
    }
}

gint add_diagnostic_message_fields(proto_tree *doip_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, dissector_handle_t uds_handle, proto_tree *parent_tree)
{    
    proto_tree_add_item(doip_tree, hf_source_address, tvb, offset + 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(doip_tree, hf_target_address, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

    set_uds_info(tvb, pinfo, offset, uds_handle, parent_tree);
    
    if (uds_handle == 0 && tvb_bytes_exist(tvb, offset, 5))
    {
	proto_tree_add_item(doip_tree, hf_data, tvb, offset + 4, tvb_captured_length_remaining(tvb, offset + 4), ENC_BIG_ENDIAN);
    }

    return offset + 4 + tvb_captured_length_remaining(tvb, offset + 4);
}


void proto_register_diagnostic_message(gint proto_doip)
{
	static hf_register_info hf_diagnostic_message[] = 
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
			&hf_data,
			{
				"User data", "doip.data",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_doip, hf_diagnostic_message, array_length(hf_diagnostic_message));
}
