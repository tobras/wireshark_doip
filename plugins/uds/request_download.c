// request_download.c


#include "request_download.h"

#include  "config.h"
#include <epan/packet.h>


static int hf_compression = -1;
static int hf_encrypting = -1;
static int hf_length_format = -1;
static int hf_address_format = -1;
static int hf_address = -1;
static int hf_length = -1;

static int hf_length_format_response = -1;
static int hf_block_length = -1;

static const value_string compression_encrypting[] = {
	{ 0x0, "no" },
	{ 0, NULL }
};

gint add_request_download_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
    (void) pinfo;
        //guint8 data_format = tvb_get_guint8(tvb, offset);
	guint8 length_address_format = tvb_get_guint8(tvb, offset + 1);
	guint8 length_lenght = (length_address_format & 0xF0) >> 4;
	guint8 address_lenght = length_address_format & 0x0F;
	

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_compression, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_encrypting, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_length_format, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_address_format, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_address, tvb, offset + 2, address_lenght, ENC_BIG_ENDIAN); 
		proto_tree_add_item(uds_tree, hf_length, tvb, offset + 2 + address_lenght, length_lenght, ENC_BIG_ENDIAN);		
	}

	return offset + 2 + address_lenght + length_lenght;
}


gint add_request_download_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset)
{
    (void) pinfo;

        guint8 length_address_format = tvb_get_guint8(tvb, offset);
	guint8 length_lenght = (length_address_format & 0xF0) >> 4;

	if (uds_tree)
	{
		proto_tree_add_item(uds_tree, hf_length_format_response, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(uds_tree, hf_block_length, tvb, offset + 1, length_lenght, ENC_BIG_ENDIAN);		
	}

	return offset + 2 + length_lenght;
}


void proto_register_request_download(gint proto_uds)
{
	static hf_register_info hf_request_download[] = 
	{
		{
			&hf_compression,
			{
				"Compression", "uds.request_download.compression",
				FT_UINT8, BASE_HEX,
				VALS(compression_encrypting), 0xF0,
				NULL, HFILL
			}
		},
		{
			&hf_encrypting,
			{
				"Encrypting", "uds.request_download.encrypting",
				FT_UINT8, BASE_HEX,
				VALS(compression_encrypting), 0x0F,
				NULL, HFILL
			}
		},
		{
			&hf_length_format,
			{
				"Memory Size Format", "uds.request_download.memorySizeFormat",
				FT_UINT8, BASE_DEC,
				NULL, 0xF0,
				NULL, HFILL
			}
		},
		{
			&hf_address_format,
			{
				"Memory Address Format", "uds.request_download.memoryAddressFormat",
				FT_UINT8, BASE_DEC,
				NULL, 0x0F,
				NULL, HFILL
			}
		},
		{
			&hf_address,
			{
				"Memory Address", "uds.request_download.memoryAddress",
				FT_BYTES, BASE_NONE, 
				NULL, 0x00,
				NULL, HFILL
			}
		},
		{
			&hf_length,
			{
				"Memory Size", "uds.request_download.memorySize",
				FT_BYTES, BASE_NONE, 
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

	proto_register_field_array(proto_uds, hf_request_download, array_length(hf_request_download));
}

void proto_register_request_download_response(gint proto_uds)
{
        static hf_register_info hf_request_download_response[] =
	{
		{
			&hf_length_format_response,
			{
				"Length Format Identifier", "uds.request_download.lengthFormatIdentifier",
				FT_UINT8, BASE_DEC,
				NULL, 0xF0,
				NULL, HFILL
			}
		},
		{
			&hf_block_length,
			{
				"Max Number Of Block Length", "uds.request_download.maxNumberOfBlockLength",
				FT_BYTES, BASE_NONE, 
				NULL, 0x00,
				NULL, HFILL
			}
		}
	};

proto_register_field_array(proto_uds, hf_request_download_response, array_length(hf_request_download_response));
}

