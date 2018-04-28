// tester_present.c

#include "tester_present.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_tp_type = -1;
static int hf_suppress_pos_rsp_msg_indication_bit = -1;
static int hf_tp_type_response = -1;

static const value_string sub_function[] = {
	{ 0x0, "zeroSubFunction" },
	{ 0, NULL }
};


gint add_tester_present_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	guint8 sf = tvb_get_guint8(tvb, offset) & 0x7F;
	if (sf != 0x00)
	{
	    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(sf, sub_function, "0x%02x Unknown sub-function"));
	}

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_suppress_pos_rsp_msg_indication_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_tp_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	}

	return offset + 1;
}


gint add_tester_present_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	guint8 sf = tvb_get_guint8(tvb, offset) & 0x7F;
	if (sf != 0x00)
	{
	    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(sf, sub_function, "0x%02x Unknown sub-function"));
	}

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_tp_type_response, tvb, offset, 1, ENC_BIG_ENDIAN);
	}

	return offset + 1;
}


void proto_register_tester_present(gint proto_uds)
{
	static hf_register_info hf_tester_present[] = 
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
			&hf_tp_type,
			{
				"Sub Function", "uds.tester_present.subFunction",
				FT_UINT8, BASE_HEX,
				VALS(sub_function), 0x7F,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_tester_present, array_length(hf_tester_present));
}

void proto_register_tester_present_response(gint proto_uds)
{
	static hf_register_info hf_tester_present_response[] =
	{
		{
			&hf_tp_type_response,
			{
				"Sub Function", "uds.tester_present.subFunction",
				FT_UINT8, BASE_HEX,
				VALS(sub_function), 0x7F,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_tester_present_response, array_length(hf_tester_present_response));
}

