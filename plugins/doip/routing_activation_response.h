// routing_activation_response.h

#ifndef ROUTING_ACTIVATION_RESPONSE
#define ROUTING_ACTIVATION_RESPONSE

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

typedef int gint;

gint add_routing_activation_response_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset);
void proto_register_routing_activation_response(gint proto_doip);

#endif // ROUTING_ACTIVATION_RESPONSE
