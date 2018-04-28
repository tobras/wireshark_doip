// diagnostic_session_control.c

#include "diagnostic_session_control.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_session = -1;
static int hf_suppress_pos_rsp_msg_indication_bit = -1;

static int hf_session_response = -1;


static const value_string sub_function[] = {
	{ 0x0, "ISOSAEReserved" },
	{ 0x1, "defaultSession" },
	{ 0x2, "programmingSession" },
	{ 0x3, "extendedDiagnosticSession" },
	{ 0, NULL }
};

gint add_diagnostic_session_control_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
    guint8 sf = tvb_get_guint8(tvb, offset) & 0x7F;
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(sf, sub_function, "0x%02x Unknown sub-function"));
    
    if (uds_tree)
    {
	proto_tree_add_item(uds_tree, hf_suppress_pos_rsp_msg_indication_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(uds_tree, hf_session, tvb, offset, 1, ENC_BIG_ENDIAN);
    }

    return offset + 1;
}


gint add_diagnostic_session_control_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
    guint8 sf = tvb_get_guint8(tvb, offset) & 0x7F;
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(sf, sub_function, "0x%02x Unknown sub-function"));

    if (uds_tree)
    {
	proto_tree_add_item(uds_tree, hf_session_response, tvb, offset, 1, ENC_BIG_ENDIAN);
    }

    return offset + 1;
}

void proto_register_diagnostic_session_control(gint proto_uds)
{
	static hf_register_info hf_diagnostic_session_control[] = 
	{
	        {
		    &hf_suppress_pos_rsp_msg_indication_bit,
		          {"Suppress positive response", "uds.suppressPosRspMsgIndicationBit",
			   FT_BOOLEAN, 8, // lenght in bits
			   NULL, 0x80, // mask
			   NULL, HFILL
			  }
		},
		{
			&hf_session,
			{
				"Requested session", "uds.diagnostic_session_control.session",
				FT_UINT8, BASE_HEX,
				VALS(sub_function), 0x7F,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_diagnostic_session_control, array_length(hf_diagnostic_session_control));
}

void proto_register_diagnostic_session_control_response(gint proto_uds)
{
	static hf_register_info hf_diagnostic_session_control[] = 
	{
		{
			&hf_session_response,
			{
				"Requested session", "uds.diagnostic_session_control.session",
				FT_UINT8, BASE_HEX,
				VALS(sub_function), 0x7F,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_diagnostic_session_control, array_length(hf_diagnostic_session_control));
}
