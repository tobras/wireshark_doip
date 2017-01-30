// vehicle_identification_eid.c

#include "vehicle_identification_eid.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_eid = -1;


gint add_vehicle_identification_eid_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset)
{
	proto_tree_add_item(doip_tree, hf_eid, tvb, offset + 0, 6, ENC_BIG_ENDIAN);

	return offset + 6;
}


void proto_register_vehicle_identification_eid(gint proto_doip)
{
	static hf_register_info hf_vehicle_identification_eid[] = 
	{
		{
			&hf_eid,
			{
				"EID", "doip.eid",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_doip, hf_vehicle_identification_eid, array_length(hf_vehicle_identification_eid));
}
