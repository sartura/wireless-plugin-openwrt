#include "operational.h"
#include "common.h"

#define MAX_UBUS_PATH 100
#define UBUS_INVOKE_TIMEOUT 200

const char *XPATH_CHANNEL = "/router-wireless:devices-state/device[name='%s']/channel";
const char *XPATH_ENCRYPTION = "/router-wireless:devices-state/device[name='%s']/encryption";
const char *XPATH_SSID = "/router-wireless:devices-state/device[name='%s']/ssid";
const char *XPATH_UP = "/router-wireless:devices-state/device[name='%s']/up";

struct status_container {
    char *interface_name;
    const char *ubus_method;
    ubus_val_to_sr_val transform;
    struct list_head *list;
};

struct ubus_context *ctx;
struct status_container *container_msg;

int
operational_start()
{
    if (ctx) return 0;
    INF("Connect ubus context. %zu", (size_t) ctx);
    container_msg = calloc(1,sizeof(*container_msg));

    ctx = ubus_connect(NULL);
    if (ctx == NULL) {
        INF_MSG("Cant allocate ubus\n");
        return -1;
    }

    return 0;
}

void
operational_stop()
{
    INF_MSG("Free ubus context.");
    INF("%lu %lu", (long unsigned)ctx, (long unsigned) container_msg);
    if (ctx) ubus_free(ctx);
    if (container_msg) free(container_msg);
}

static void
make_status_container(struct status_container **context,
                      const char *ubus_method_to_call,
                      ubus_val_to_sr_val result_function,
                      char *interface_name, struct list_head *list)
{
    *context = container_msg;
    (*context)->interface_name = interface_name;
    (*context)->transform = result_function;
    (*context)->ubus_method = ubus_method_to_call;
    (*context)->list = list;
}

static void
ubus_base_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
    char *json_string;
    struct json_object *base_jobj;
    struct status_container *status_container_msg;

    status_container_msg = (struct status_container *) req->priv;

    if (!msg) {
        return;
    }

    json_string = blobmsg_format_json(msg, true);
    base_jobj = json_tokener_parse(json_string);

    status_container_msg->transform(base_jobj, status_container_msg->interface_name, status_container_msg->list);

    json_object_put(base_jobj);
    free(json_string);
}

static int
ubus_base(const char *ubus_lookup_path,
          struct status_container *msg, struct blob_buf *blob)
{
    uint32_t id = 0;
    int rc = SR_ERR_OK;

    rc = ubus_lookup_id(ctx, ubus_lookup_path, &id);
    if (rc) {
        goto exit;
    }

    rc = ubus_invoke(ctx, id, "status", blob->head, ubus_base_cb, (void *) msg, UBUS_INVOKE_TIMEOUT);
    if (rc) {
        INF("ubus [%s]: no object %s\n", ubus_strerror(rc), msg->ubus_method);
        goto exit;
    }

  exit:
    blob_buf_free(blob);

    return rc;

}

static void
operstatus_channel_f(json_object *base_jobj, char *interface_name, struct list_head *list)
{
    struct json_object *interface_jobj, *config_jobj, *channel_jobj;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = XPATH_CHANNEL;
    char xpath[MAX_XPATH];

    json_object_object_get_ex(base_jobj,
                              interface_name,
                              &interface_jobj);
    // channel is located in the config subsection
    json_object_object_get_ex(interface_jobj,
                              "config",
                              &config_jobj);

    json_object_object_get_ex(config_jobj,
                              "channel",
                              &channel_jobj);
    ubus_result = json_object_to_json_string(channel_jobj);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_ENUM_T, ubus_result);

    list_add(&list_value->head, list);
}

int
operational_channel(char *interface_name, struct list_head *list)
{
    struct status_container *msg = NULL;
    make_status_container(&msg, "status", operstatus_channel_f, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    //blobmsg_add_string(&buf, "name", interface_name);
    ubus_base("network.wireless", msg, &buf);

    return SR_ERR_OK;
}

static void
operstatus_encryption_f(json_object *base_jobj, char *interface_name, struct list_head *list)
{
    struct json_object *interface_jobj, *interfaces_jobj, *config_jobj, *encryption_jobj;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = XPATH_ENCRYPTION;
    char xpath[MAX_XPATH];

    json_object_object_get_ex(base_jobj,
                              interface_name,
                              &interface_jobj);
    // the json we get has an 'interfaces' array
    json_object_object_get_ex(interface_jobj,
                              "interfaces",
                              &interfaces_jobj);

    // we get the encryption for the first interface in the array
    // encryption is in the config subsection
    json_object_object_get_ex(json_object_array_get_idx(interfaces_jobj, 0),
                              "config",
                              &config_jobj);

    json_object_object_get_ex(config_jobj,
                              "encryption",
                              &encryption_jobj);
    ubus_result = json_object_get_string(encryption_jobj);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_STRING_T, ubus_result);

    list_add(&list_value->head, list);
}

int
operational_encryption(char *interface_name, struct list_head *list)
{
    struct status_container *msg = NULL;
    make_status_container(&msg, "status", operstatus_encryption_f, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    blobmsg_add_string(&buf, "name", interface_name);
    ubus_base("network.wireless", msg, &buf);

    return SR_ERR_OK;
}

static void
operstatus_ssid_f(json_object *base_jobj, char *interface_name, struct list_head *list)
{
    struct json_object *interface_jobj, *interfaces_jobj, *config_jobj, *ssid_jobj;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = XPATH_SSID;
    char xpath[MAX_XPATH];

    json_object_object_get_ex(base_jobj,
                              interface_name,
                              &interface_jobj);
    // the json we get has an 'interfaces' array
    json_object_object_get_ex(interface_jobj,
                              "interfaces",
                              &interfaces_jobj);

    // we get the ssid for the first interface in the array
    // ssid is in the config subsection
    json_object_object_get_ex(json_object_array_get_idx(interfaces_jobj, 0),
                              "config",
                              &config_jobj);

    json_object_object_get_ex(config_jobj,
                              "ssid",
                              &ssid_jobj);
    ubus_result = json_object_get_string(ssid_jobj);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    sr_val_set_str_data(list_value->value, SR_STRING_T, ubus_result);

    list_add(&list_value->head, list);
}

int
operational_ssid(char *interface_name, struct list_head *list)
{
    struct status_container *msg = NULL;
    make_status_container(&msg, "status", operstatus_ssid_f, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    blobmsg_add_string(&buf, "name", interface_name);
    ubus_base("network.wireless", msg, &buf);

    return SR_ERR_OK;
}


static void
operstatus_up_f(json_object *base_jobj, char *interface_name, struct list_head *list)
{
    struct json_object *interface_jobj, *up_jobj;
    const char *ubus_result;
    struct value_node *list_value;
    const char *fmt = XPATH_UP;
    char xpath[MAX_XPATH];

    json_object_object_get_ex(base_jobj,
                              interface_name,
                              &interface_jobj);
    json_object_object_get_ex(interface_jobj,
                              "up",
                              &up_jobj);
    ubus_result = json_object_to_json_string(up_jobj);
    if (!ubus_result) return;

    list_value = calloc(1, sizeof *list_value);
    sr_new_values(1, &list_value->value);
    sprintf(xpath, fmt, interface_name);
    sr_val_set_xpath(list_value->value, xpath);
    bool up = strcmp("true", ubus_result) == 0 ? true : false;
    list_value->value->type = SR_BOOL_T;
    list_value->value->data.bool_val = up;

    list_add(&list_value->head, list);
}

int
operational_up(char *interface_name, struct list_head *list)
{
    struct status_container *msg = NULL;
    make_status_container(&msg, "status", operstatus_up_f, interface_name, list);
    struct blob_buf buf = {0,};
    blob_buf_init(&buf, 0);
    blobmsg_add_string(&buf, "name", interface_name);
    ubus_base("network.wireless", msg, &buf);

    return SR_ERR_OK;
}


