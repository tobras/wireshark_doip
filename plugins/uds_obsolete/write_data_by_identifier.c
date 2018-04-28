// write_data_by_identifier.c



#include "write_data_by_identifier.h"

#include  "config.h"
#include <epan/packet.h>


static int hf_data_identifier = -1;
static int hf_value = -1;

static int hf_data_identifier_response = -1;




gint add_write_data_by_identifier_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	gint remaining = 0;
	guint16 id = tvb_get_ntohs(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%04x", id);

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_data_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
		if (remaining > 0)
		{
		  proto_tree_add_item(uds_tree, hf_value, tvb, offset + 2, remaining, ENC_BIG_ENDIAN);
		}
	}

	return offset + 2 + remaining;
}


gint add_write_data_by_identifier_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
	guint16 id = tvb_get_ntohs(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO, " 0x%04x", id);

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_data_identifier_response, tvb, offset, 2, ENC_BIG_ENDIAN);
	}

	return offset + 2;
}


void proto_register_write_data_by_identifier(gint proto_uds)
{
	static hf_register_info hf_write_data_by_identifier[] = 
	{
		{
			&hf_data_identifier,
			{
				"Data Identifier", "uds.write_data_by_identifier.dataIdentifier",
				FT_UINT16, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_value,
			{
				"Data Record", "uds.write_data_by_identifier.dataRecord",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_write_data_by_identifier, array_length(hf_write_data_by_identifier));
}

void proto_register_write_data_by_identifier_response(gint proto_uds)
{
	static hf_register_info hf_write_data_by_identifier_response[] =
	{
		{
			&hf_data_identifier_response,
			{
				"Data Identifier", "uds.write_data_by_identifier.dataIdentifier",
				FT_UINT16, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_write_data_by_identifier_response, array_length(hf_write_data_by_identifier_response));
}

