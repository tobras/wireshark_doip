// vehicle_identification_vin.c

#include "vehicle_identification_vin.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_vin = -1;


gint add_vehicle_identification_vin_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset)
{
	proto_tree_add_item(doip_tree, hf_vin, tvb, offset + 0, 17, ENC_BIG_ENDIAN);

	return offset + 17;
}


void proto_register_vehicle_identification_vin(gint proto_doip)
{
	static hf_register_info hf_vehicle_identification_vin[] = 
	{
		{
			&hf_vin,
			{
				"VIN", "doip.vin",
				FT_STRING, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_doip, hf_vehicle_identification_vin, array_length(hf_vehicle_identification_vin));
}
