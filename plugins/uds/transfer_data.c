// transfer_data.c


// TODO: Add multi DID request handling

#include "transfer_data.h"

#include  "config.h"
#include <epan/packet.h>


static int hf_sequence = -1;
static int hf_parameters = -1;

static int hf_sequence_response = -1;
static int hf_parameters_response = -1;


gint add_transfer_data_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	guint8 sequence = tvb_get_guint8(tvb, offset);
	gint remaining = tvb_captured_length_remaining(tvb, offset + 1);

	col_append_fstr(pinfo->cinfo, COL_INFO, " Seq: 0x%02x Len: %u", sequence, remaining);

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_sequence, tvb, offset, 1, ENC_BIG_ENDIAN);
		
		if (remaining > 0)
		{
		  proto_tree_add_item(uds_tree, hf_parameters, tvb, offset + 1, remaining, ENC_BIG_ENDIAN);
		}
	}

	return offset + 1 + remaining;
}


gint add_transfer_data_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	gint remaining = 0;
	guint8 sequence = tvb_get_guint8(tvb, offset); 

	col_append_fstr(pinfo->cinfo, COL_INFO, " Seq: 0x%02x", sequence);

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_sequence_response, tvb, offset, 1, ENC_BIG_ENDIAN);
		remaining = tvb_captured_length_remaining(tvb, offset + 1);
		if (remaining > 0)
		{
		  proto_tree_add_item(uds_tree, hf_parameters_response, tvb, offset + 1, remaining, ENC_BIG_ENDIAN);
		}
	}

	return offset + 1 + remaining;
}


void proto_register_transfer_data(gint proto_uds)
{
	static hf_register_info hf_transfer_data[] = 
	{
		{
			&hf_sequence,
			{
				"Block Sequence Counter", "uds.transfer_data.blockSequenceCounter",
				FT_UINT8, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_parameters,
			{
				"Parameter Record", "uds.transfer_data.transferRequestParameterRecord",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_transfer_data, array_length(hf_transfer_data));
}

void proto_register_transfer_data_response(gint proto_uds)
{
	static hf_register_info hf_transfer_data_response[] =
	{
		{
			&hf_sequence_response,
			{
				"Block Sequence Counter", "uds.transfer_data.blockSequenceCounter",
				FT_UINT8, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_parameters_response,
			{
				"Parameter Record", "uds.transfer_data.transferRequestParameterRecord",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_transfer_data_response, array_length(hf_transfer_data_response));
}

