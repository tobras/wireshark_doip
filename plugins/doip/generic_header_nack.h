// generic_header_nack.h

#ifndef GENERIC_HEADER_NACK
#define GENERIC_HEADER_NACK

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

typedef int gint;

gint add_generic_header_nack_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset);
void register_generic_header_nack(gint proto_doip);

#endif // GENERIC_HEADER_NACK
