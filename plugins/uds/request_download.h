// request_download.h

#ifndef REQUEST_DOWNLOAD
#define REQUEST_DOWNLOAD

struct _proto_node;
typedef struct _proto_node proto_tree;

struct tvbuff;
typedef struct tvbuff tvbuff_t;

struct _packet_info;
typedef struct _packet_info packet_info;


typedef int gint;

gint add_request_download_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);
gint add_request_download_response_fields(proto_tree *uds_tree, packet_info *pinfo, tvbuff_t *tvb, gint offset);

void proto_register_request_download(gint proto_uds);
void proto_register_request_download_response(gint proto_uds);

#endif // REQUEST_DOWNLOAD
