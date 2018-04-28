// routine_control.c

#include "routine_control.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_routine_control_type = -1;
static int hf_suppress_pos_rsp_msg_indication_bit = -1;
static int hf_data_identifier = -1;
static int hf_option_record = -1;

static int hf_routine_control_type_response = -1;
static int hf_data_identifier_response = -1;
static int hf_status_record = -1;

static const value_string sub_function[] = {
	{ 0x1, "startRoutine" },
	{ 0x2, "stopRoutine" },
	{ 0x3, "requestRoutineResults" },
	{ 0, NULL }
};


gint add_routine_control_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	gint remaining = 0;
	guint8 sf = tvb_get_guint8(tvb, offset) & 0x7F;
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(sf, sub_function, "0x%02x ISOSAEReserved"));	
	
	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_suppress_pos_rsp_msg_indication_bit, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_routine_control_type, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_data_identifier, tvb, offset + 1, 2, ENC_BIG_ENDIAN);

		remaining = tvb_captured_length_remaining(tvb, offset + 3);

		if (remaining > 0)
		{
		  proto_tree_add_item(uds_tree, hf_option_record, tvb, offset + 3, remaining, ENC_BIG_ENDIAN);
		}
	}

	return offset + 3 + remaining;
}


gint add_routine_control_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	gint remaining = 0;
	guint8 sf = tvb_get_guint8(tvb, offset) & 0x7F;
	col_append_fstr(pinfo->cinfo, COL_INFO, " %s", val_to_str(sf, sub_function, "0x%02x Unknown sub-function"));

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_routine_control_type_response, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_data_identifier_response, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
		
		remaining = tvb_captured_length_remaining(tvb, offset + 3);

		if (remaining > 0)
		{
		  proto_tree_add_item(uds_tree, hf_status_record, tvb, offset + 3, remaining, ENC_BIG_ENDIAN);
		}
	}

	return offset + 3 + remaining;
}


void proto_register_routine_control(gint proto_uds)
{
	static hf_register_info hf_routine_control[] = 
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
			&hf_routine_control_type,
			{
				"Routine Control Type", "uds.routine_control.routineControlType",
				FT_UINT8, BASE_HEX,
				VALS(sub_function), 0x7F,
				NULL, HFILL
			}
		},
		{
			&hf_data_identifier,
			{
				"Data Identifier", "uds.routine_control.dataIdentifier",
				FT_UINT16, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_option_record,
			{
				"Option Record", "uds.routine_control.routineControlOptionRecord",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_routine_control, array_length(hf_routine_control));
}

void proto_register_routine_control_response(gint proto_uds)
{
	static hf_register_info hf_routine_control_response[] =
	{
		{
			&hf_routine_control_type_response,
			{
				"Routine Control Type", "uds.routine_control.routineControlType",
				FT_UINT8, BASE_HEX,
				VALS(sub_function), 0x7F,
				NULL, HFILL
			}
		},
		{
			&hf_data_identifier_response,
			{
				"Data Identifier", "uds.routine_control.dataIdentifier",
				FT_UINT16, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_status_record,
			{
				"Status Record", "uds.routine_control.routineStatusRecord",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_routine_control_response, array_length(hf_routine_control_response));
}

