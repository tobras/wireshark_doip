// vehicle_identification_eid.h

#ifndef VEHICLE_IDENTIFICATION_EID
#define VEHICLE_IDENTIFICATION_EID

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

typedef int gint;

gint add_vehicle_identification_eid_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset);
void proto_register_vehicle_identification_eid(gint proto_doip);

#endif // VEHICLE_IDENTIFICATION_EID
