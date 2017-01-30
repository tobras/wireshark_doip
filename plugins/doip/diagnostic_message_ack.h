// diagnostic_message_ack.h

#ifndef DIAGNOSTIC_MESSAGE_ACK
#define DIAGNOSTIC_MESSAGE_ACK

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

typedef int gint;

gint add_diagnostic_message_ack_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset);
void proto_register_diagnostic_message_ack(gint proto_doip);

#endif // DIAGNOSTIC_MESSAGE_ACK
