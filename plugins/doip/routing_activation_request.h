// routing_activation_request.h

#ifndef ROUTING_ACTIVATION_REQUEST
#define ROUTING_ACTIVATION_REQUEST

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

typedef int gint;

gint add_routing_activation_request_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset);
void proto_register_routing_activation_request(gint proto_doip);

#endif // ROUTING_ACTIVATION_REQUEST
