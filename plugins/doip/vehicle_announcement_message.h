// vehicle_announcement_message.h

#ifndef VEHICLE_ANNOUNCEMENT_MESSAGE
#define VEHICLE_ANNOUNCEMENT_MESSAGE

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

typedef int gint;

gint add_vehicle_announcement_message_fields(proto_tree *doip_tree, tvbuff_t *tvb, gint offset);
void register_vehicle_announcement_message(gint proto_doip);

#endif // VEHICLE_ANNOUNCEMENT_MESSAGE
