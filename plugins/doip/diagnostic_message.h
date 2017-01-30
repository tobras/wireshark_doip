// diagnostic_message.h

#ifndef DIAGNOSTIC_MESSAGE
#define DIAGNOSTIC_MESSAGE

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

struct _packet_info;
typedef struct _packet_info packet_info;

typedef int gint;


struct dissector_handle;
typedef struct dissector_handle *dissector_handle_t;

void set_uds_info(tvbuff_t *tvb, packet_info *pinfo, gint offset, dissector_handle_t uds_handle, proto_tree *parent_tree);

gint add_diagnostic_message_fields(proto_tree *doip_tree, tvbuff_t *tvb, packet_info *pinfo, gint offset, dissector_handle_t uds_handle, proto_tree *parent_tree);
void proto_register_diagnostic_message(gint proto_doip);

#endif // DIAGNOSTIC_MESSAGE
