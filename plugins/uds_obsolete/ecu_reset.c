// ecu_reset.c

#include "ecu_reset.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_reset_type = -1;
static int hf_suppress_pos_rsp_msg_indication_bit = -1;

static int hf_reset_type_response = -1;

static const value_string sub_function[] = {
	{ 0x0, "ISOSAEReserved" },
	{ 0x1, "hardReset" },
	{ 0x2, "keyOffOnReset" },
	{ 0x3, "softReset" },
	{ 0x4, "enableRapidPowerShutDown" },
	{ 0x5, "disableRapidPowerShutDown" },
	{ 0, NULL }
};


gint add_ecu_reset_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	guint8 sf = tvb_get_guint8(tvb, offset) & 0x7F;
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(sf, sub_function, "0x%02x Unknown sub-function"));

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_suppress_pos_rsp_msg_indication_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_reset_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	}

	return offset + 1;
}


gint add_ecu_reset_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	guint8 sf = tvb_get_guint8(tvb, offset) & 0x7F;
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(sf, sub_function, "0x%02x Unknown sub-function"));

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_reset_type_response, tvb, offset, 1, ENC_BIG_ENDIAN);

		if (sf == 0x4) // This parameter is present if the sub-function parameter is set to the enableRapidPowerShutDown value (04hex)
		{
			// TODO: Add this to tree
			return offset + 2;
		}
	}

	return offset + 1;
}


void proto_register_ecu_reset(gint proto_uds)
{
	static hf_register_info hf_ecu_reset[] = 
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
			&hf_reset_type,
			{
				"resetType", "uds.ecu_reset.resetType",
				FT_UINT8, BASE_HEX,
				VALS(sub_function), 0x7F,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_ecu_reset, array_length(hf_ecu_reset));
}

void proto_register_ecu_reset_response(gint proto_uds)
{
	static hf_register_info hf_ecu_reset_response[] =
	{
		{
			&hf_reset_type_response,
			{
				"resetType", "uds.ecu_reset.resetType",
				FT_UINT8, BASE_HEX,
				VALS(sub_function), 0x7F,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_ecu_reset_response, array_length(hf_ecu_reset_response));
}

