// vehicle_announcement_message.c

#include "vehicle_announcement_message.h"

#include  "config.h"
#include <epan/packet.h>



static int hf_vin = -1;
static int hf_logical_address = -1;
static int hf_eid = -1;
static int hf_gid = -1;
static int hf_futher_action = -1;
static int hf_sync_status = -1;


gint add_vehicle_announcement_message_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset)
{
	proto_tree_add_item(doip_tree, hf_vin, tvb, offset + 0, 17, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_logical_address, tvb, offset + 17, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_eid, tvb, offset + 19, 6, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_gid, tvb, offset + 25, 6, ENC_BIG_ENDIAN);

	proto_tree_add_item(doip_tree, hf_futher_action, tvb, offset + 31, 1, ENC_BIG_ENDIAN);

	if ( tvb_bytes_exist(tvb, offset, 33) )
	{
	    proto_tree_add_item(doip_tree, hf_sync_status, tvb, offset + 32, 1, ENC_BIG_ENDIAN);

	    return offset + 33;
	}

	return 32;
}

static const value_string action_codes[] = {
    { 0x00, "No further action required" },
    { 0x01, "Reserved by ISO 13400" },
    { 0x02, "Reserved by ISO 13400" },
    { 0x03, "Reserved by ISO 13400" },
    { 0x04, "Reserved by ISO 13400" },
    { 0x05, "Reserved by ISO 13400" },
    { 0x06, "Reserved by ISO 13400" },
    { 0x07, "Reserved by ISO 13400" },
    { 0x08, "Reserved by ISO 13400" },
    { 0x09, "Reserved by ISO 13400" },
    { 0x0A, "Reserved by ISO 13400" },
    { 0x0B, "Reserved by ISO 13400" },
    { 0x0C, "Reserved by ISO 13400" },
    { 0x0D, "Reserved by ISO 13400" },
    { 0x0E, "Reserved by ISO 13400" },
    { 0x0F, "Reserved by ISO 13400" },
    { 0x10, "Routing activation required to initiate central security" },
    { 0, NULL }
};


void proto_register_vehicle_announcement_message(gint proto_doip)
{
	static hf_register_info hf_vehicle_announcement_message[] = 
	{
		{
			&hf_vin,
			{
				"VIN", "doip.vin",
				FT_STRING, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_logical_address,
			{
				"Logical Address", "doip.logical_address",
				FT_UINT16, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_eid,
			{
				"EID", "doip.eid",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_gid,
			{
				"GID", "doip.gid",
				FT_BYTES, BASE_NONE,
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_futher_action,
			{
				"Further action required", "doip.futher_action",
				FT_UINT8, BASE_HEX,
				VALS(action_codes), 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_sync_status,
			{
				"VIN/GID sync. status", "doip.sync_status",
				FT_UINT8, BASE_HEX,
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_doip, hf_vehicle_announcement_message, array_length(hf_vehicle_announcement_message));
}
