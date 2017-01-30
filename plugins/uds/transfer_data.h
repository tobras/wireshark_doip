// transfer_data.h

#ifndef TRANSFER_DATA
#define TRANSFER_DATA

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

struct _packet_info;
typedef struct _packet_info packet_info;


typedef int gint;

gint add_transfer_data_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);
gint add_transfer_data_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);

void proto_register_transfer_data(gint proto_uds);
void proto_register_transfer_data_response(gint proto_uds);

#endif // TRANSFER_DATA
