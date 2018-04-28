// tester_present.h

#ifndef TESTER_PRESENT
#define TESTER_PRESENT

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

struct _packet_info;
typedef struct _packet_info packet_info;


typedef int gint;

gint add_tester_present_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);
gint add_tester_present_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);

void proto_register_tester_present(gint proto_uds);
void proto_register_tester_present_response(gint proto_uds);

#endif // TESTER_PRESENT
