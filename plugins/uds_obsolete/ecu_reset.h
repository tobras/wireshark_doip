// ecu_reset.h

#ifndef ECU_RESET
#define ECU_RESET

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

struct _packet_info;
typedef struct _packet_info packet_info;


typedef int gint;

gint add_ecu_reset_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);
gint add_ecu_reset_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);

void proto_register_ecu_reset(gint proto_uds);
void proto_register_ecu_reset_response(gint proto_uds);

#endif // ECU_RESET
