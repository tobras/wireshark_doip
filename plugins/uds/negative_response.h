// negative.h

#ifndef NEGATIVE_RESPONSE
#define NEGATIVE_RESPONSE

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

struct _packet_info;
typedef struct _packet_info packet_info;


typedef int gint;

gint add_negative_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);

void proto_register_negative_response(gint proto_uds);

#endif // NEGATIVE_RESPONSE
