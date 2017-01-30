// routine_control.h

#ifndef ROUTINE_CONTROL
#define ROUTINE_CONTROL

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

struct _packet_info;
typedef struct _packet_info packet_info;


typedef int gint;

gint add_routine_control_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);
gint add_routine_control_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);

void proto_register_routine_control(gint proto_uds);
void proto_register_routine_control_response(gint proto_uds);

#endif // ROUTINE_CONTROL
