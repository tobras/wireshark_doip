// security_access.c

#include "security_access.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_sub_function = -1;
static int hf_suppress_pos_rsp_msg_indication_bit = -1;
static int hf_data = -1;
static int hf_key = -1;
static int hf_sub_function_response = -1;
static int hf_seed = -1;

static const value_string sub_function[] = {
	{ 0x0, "ISOSAEReserved" },
	{ 0x1, "requestSeed" },
	{ 0x2, "sendKey" },
	{ 0x3, "requestSeed" },
	{ 0x4, "sendKey" },
	{ 0x5, "requestSeed" },
	{ 0x6, "sendKey" },
	{ 0x7, "requestSeed" },
	{ 0x8, "sendKey" },
	{ 0x9, "requestSeed" },
	{ 0xA, "sendKey" },
	{ 0xB, "requestSeed" },
	{ 0xC, "sendKey" },
	{ 0xD, "requestSeed" },
	{ 0xE, "sendKey" },
	{ 0xF, "requestSeed" },
	{ 0x10, "sendKey" },
	{ 0x7F, "ISOSAEReserved" },
	{ 0, NULL }
};


gint add_security_access_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
        gint remaining = 0;
	guint8 sf = tvb_get_guint8(tvb, offset) & 0x7F;
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(sf, sub_function, "0x%02x Unknown sub-function"));

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_suppress_pos_rsp_msg_indication_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_sub_function, tvb, offset, 1, ENC_BIG_ENDIAN);

		remaining = tvb_captured_length_remaining(tvb, offset + 1);

		if (remaining > 0)
		{
		  if (sf > 0 && sf < 61)
		  {
		    if (sf % 2)
		    {
		      proto_tree_add_item(uds_tree, hf_data, tvb, offset + 1, remaining, ENC_BIG_ENDIAN);
		    }
		    else
		    {
		      proto_tree_add_item(uds_tree, hf_key, tvb, offset + 1, remaining, ENC_BIG_ENDIAN);
		    }
		  }
		}
	}

	return offset + 1 + remaining;
}


gint add_security_access_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	gint remaining = 0;
	guint8 sf = tvb_get_guint8(tvb, offset) & 0x7F;
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(sf, sub_function, "0x%02x Unknown sub-function"));

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_sub_function_response, tvb, offset, 1, ENC_BIG_ENDIAN);

		remaining = tvb_captured_length_remaining(tvb, offset + 1);

		if (remaining > 0)
		{
		  if (sf > 0 && sf < 61)
		  {
		    if (sf % 2)
		    {
		      proto_tree_add_item(uds_tree, hf_seed, tvb, offset + 1, remaining, ENC_BIG_ENDIAN);
		    }
		  }
		}
	}

	return offset + 1 + remaining;
}


void proto_register_security_access(gint proto_uds)
{
	static hf_register_info hf_security_access[] = 
	{
		{
			&hf_suppress_pos_rsp_msg_indication_bit,
			{ "Suppress positive response", "uds.suppressPosRspMsgIndicationBit",
			FT_BOOLEAN, 8, // lenght in bits
			NULL, 0x80, // mask
			NULL, HFILL
			}
		},
		{
			&hf_sub_function,
			{
				"Sub Function", "uds.security_access.sub-function",
				FT_UINT8, BASE_HEX,
				VALS(sub_function), 0x7F,
				NULL, HFILL
			}
		},
		{
			&hf_data,
			{
				"Security Access Data Record", "uds.security_access.securityAccessDataRecord",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_key,
			{
				"Security Key", "uds.security_access.securityKey",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}


	};

	proto_register_field_array(proto_uds, hf_security_access, array_length(hf_security_access));
}

void proto_register_security_access_response(gint proto_uds)
{
	static hf_register_info hf_security_access_response[] =
	{
		{
			&hf_sub_function_response,
			{
				"Sub Function", "uds.security_access.sub-function",
				FT_UINT8, BASE_HEX,
				VALS(sub_function), 0x7F,
				NULL, HFILL
			}
		},
		{
			&hf_seed,
			{
				"Security Seed", "uds.security_access.securitySeed",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		
		}
	};

	proto_register_field_array(proto_uds, hf_security_access_response, array_length(hf_security_access_response));
}

