// write_data_by_identifier.h

#ifndef WRITE_DATA_BY_IDENTIFIER
#define WRITE_DATA_BY_IDENTIFIER

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

struct _packet_info;
typedef struct _packet_info packet_info;


typedef int gint;

gint add_write_data_by_identifier_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);
gint add_write_data_by_identifier_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);

void proto_register_write_data_by_identifier(gint proto_uds);
void proto_register_write_data_by_identifier_response(gint proto_uds);

#endif // WRITE_DATA_BY_IDENTIFIER
