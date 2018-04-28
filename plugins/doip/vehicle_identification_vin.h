// vehicle_identification_vin.h

#ifndef VEHICLE_IDENTIFICATION_VIN
#define VEHICLE_IDENTIFICATION_VIN

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

typedef int gint;

gint add_vehicle_identification_vin_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset);
void register_vehicle_identification_vin(gint proto_doip);

#endif // VEHICLE_IDENTIFICATION_VIN
