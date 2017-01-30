// request_transfer_exit.c


// TODO: Add multi DID request handling

#include "request_transfer_exit.h"

#include  "config.h"
#include <epan/packet.h>

static int hf_parameters = -1;

static int hf_parameters_response = -1;

gint add_request_transfer_exit_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	gint remaining = 0;

	if (uds_tree)
	{
		remaining = tvb_captured_length_remaining(tvb, offset);
		if (remaining > 0)
		{
		  proto_tree_add_item(uds_tree, hf_parameters, tvb, offset, remaining, ENC_BIG_ENDIAN);
		}
	}

	return offset + remaining;
}


gint add_request_transfer_exit_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	gint remaining = 0;

	if (uds_tree)
	{
		remaining = tvb_captured_length_remaining(tvb, offset);
		if (remaining > 0)
		{
		  proto_tree_add_item(uds_tree, hf_parameters_response, tvb, offset, remaining, ENC_BIG_ENDIAN);
		}
	}

	return offset + remaining;
}


void proto_register_request_transfer_exit(gint proto_uds)
{
	static hf_register_info hf_request_transfer_exit[] = 
	{
		{
			&hf_parameters,
			{
				"Parameter Record", "uds.request_transfer_exit.transferRequestParameterRecord",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_request_transfer_exit, array_length(hf_request_transfer_exit));
}

void proto_register_request_transfer_exit_response(gint proto_uds)
{
	static hf_register_info hf_request_transfer_exit_response[] =
	{
		{
			&hf_parameters_response,
			{
				"Parameter Record", "uds.transfer_exit.transferRequestParameterRecord",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_request_transfer_exit_response, array_length(hf_request_transfer_exit_response));
}

