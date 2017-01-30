// diagnostic_message_nack.h

#ifndef DIAGNOSTIC_MESSAGE_NACK
#define DIAGNOSTIC_MESSAGE_NACK

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

typedef int gint;

gint add_diagnostic_message_nack_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset);
void proto_register_diagnostic_message_nack(gint proto_doip);

#endif // DIAGNOSTIC_MESSAGE_NACK
