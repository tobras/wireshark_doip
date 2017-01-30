// security_access.h

#ifndef SECURITY_ACCESS
#define SECURITY_ACCESS

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

struct _packet_info;
typedef struct _packet_info packet_info;


typedef int gint;

gint add_security_access_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);
gint add_security_access_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);

void proto_register_security_access(gint proto_uds);
void proto_register_security_access_response(gint proto_uds);

#endif // SECURITY_ACCESS
