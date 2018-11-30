#include <stdio.h>
#include <inttypes.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "wireless.h"
#include "operational.h"
#include "common.h"
#include "version.h"

const char *YANG_MODEL = "router-wireless";

/* Configuration part of the plugin. */
typedef struct sr_uci_mapping {
    char *default_value;
    sr_type_t default_value_type;
    char *ucipath;
    char *xpath;
} sr_uci_link;

struct wireless_device {
    char *name;
    char *option;
};

static sr_uci_link table_wireless[] = {
    /* wireless */
    { 0, SR_STRING_T, "wireless.%s.type", "/router-wireless:devices/device[name='%s']/type"},
    { "EU/13", SR_STRING_T, "wireless.%s.country", "/router-wireless:devices/device[name='%s']/country"},
  //  { "b", SR_STRING_T, "wireless.%s.band", "/terastream-wireless:devices/device[name='%s']/frequencyband"},
  //  { "80", SR_UINT8_T, "wireless.%s.bandwidth", "/terastream-wireless:devices/device[name='%s']/bandwidth"},
    { "auto", SR_STRING_T, "wireless.%s.channel", "/router-wireless:devices/device[name='%s']/channel"},
    //{ "true", SR_BOOL_T, "wireless.%s.obss_coex", "/terastream-wireless:devices/device[name='%s']/obss_coex"},
   // { "0", SR_INT32_T, "wireless.%s.scantimer", "/terastream-wireless:devices/device[name='%s']/scantimer"},
    { "true", SR_BOOL_T, "wireless.%s.wmm", "/router-wireless:devices/device[name='%s']/wmm"},
    //{ "false", SR_BOOL_T, "wireless.%s.wmm_noack",  "/terastream-wireless:devices/device[name='%s']/wmm_noack"},
    //{ "true", SR_BOOL_T, "wireless.%s.wmm_apsd","/terastream-wireless:devices/device[name='%s']/type" },
    { "100", SR_INT32_T, "wireless.%s.txpower", "/router-wireless:devices/device[name='%s']/txpower"},
    //{ "default", SR_STRING_T, "wireless.%s.rateset", "/terastream-wireless:devices/device[name='%s']/rateset"},
    //{ "2346", SR_INT32_T, "wireless.%s.frag", "/terastream-wireless:devices/device[name='%s']/frag"},
    //{ "2347", SR_INT32_T, "wireless.%s.rts", "/terastream-wireless:devices/device[name='%s']/rts"},
    { "1", SR_INT32_T, "wireless.%s.dtim_period", "/router-wireless:devices/device[name='%s']/dtim_period"},
    { "100", SR_INT32_T, "wireless.%s.beacon_int", "/router-wireless:devices/device[name='%s']/beacon_int"},
    //{ "true", SR_BOOL_T, "wireless.%s.rxchainps", "/terastream-wireless:devices/device[name='%s']/rxchainps"},
    //{ "10", SR_INT32_T, "wireless.%s.rxchainps_qt", "/terastream-wireless:devices/device[name='%s']/rxchainps_qt"},
    //{ "10", SR_INT32_T, "wireless.%s.rxchainps_pps", "/terastream-wireless:devices/device[name='%s']/rxchainps_pps"},
    //{ "false", SR_BOOL_T, "wireless.%s.rifs", "/terastream-wireless:devices/device[name='%s']/rifs"},
    //{ "true", SR_BOOL_T, "wireless.%s.rifs_advert", "/terastream-wireless:devices/device[name='%s']/rifs_advert"},
    { "32", SR_INT32_T, "wireless.%s.maxassoc", "/router-wireless:devices/device[name='%s']/maxassoc"},
    //{ "true", SR_BOOL_T, "wireless.%s.dfsc", "/terastream-wireless:devices/device[name='%s']/dfsc"},
    { "auto", SR_STRING_T, "wireless.%s.hwmode", "/router-wireless:devices/device[name='%s']/hwmode"},
    { "false", SR_BOOL_T, "wireless.%s.disabled", "/router-wireless:devices/device[name='%s']/enabled"},
    { "false", SR_BOOL_T, "wireless.%s.frameburst", "/router-wireless:devices/device[name='%s']/frameburst"},
    //{ "false", SR_BOOL_T, "wireless.%s.beamforming", "/terastream-wireless:devices/device[name='%s']/beamforming"},
    //{ "false", SR_BOOL_T, "wireless.%s.atf", "/terastream-wireless:devices/device[name='%s']/atf"},
    { 0, SR_INT32_T, "wireless.%s.doth", "/router-wireless:devices/device[name='%s']/doth"},
};

static sr_uci_link table_interface[] = {
    { 0, SR_STRING_T, "wireless.%s.device", "/router-wireless:devices/device[name='%s']/interface[name='%s']/device"},
    { 0, SR_STRING_T, "wireless.%s.ifname", "/router-wireless:devices/device[name='%s']/interface[name='%s']/ifname"},
    { 0, SR_STRING_T, "wireless.%s.network", "/router-wireless:devices/device[name='%s']/interface[name='%s']/network"},
    { "ap", SR_STRING_T, "wireless.%s.mode", "/router-wireless:devices/device[name='%s']/interface[name='%s']/mode"},
    { 0, SR_STRING_T, "wireless.%s.ssid", "/router-wireless:devices/device[name='%s']/interface[name='%s']/ssid"},
    { "none", SR_STRING_T, "wireless.%s.encryption", "/router-wireless:devices/device[name='%s']/interface[name='%s']/encryption"},
    //{ "none", SR_STRING_T, "wireless.%s.cipher", "/terastream-wireless:devices/device[name='%s']/interface[name='%s']/cipher"},
    { 0, SR_STRING_T, "wireless.%s.key", "/router-wireless:devices/device[name='%s']/interface[name='%s']/key"},
    //{ 0, SR_INT32_T, "wireless.%s.key_index", "/terastream-wireless:devices/device[name='%s']/interface[name='%s']/key_index"},
    { 0, SR_STRING_T, "wireless.%s.key1", "/router-wireless:devices/device[name='%s']/interface[name='%s']/key1"},
    { 0, SR_STRING_T, "wireless.%s.key2", "/router-wireless:devices/device[name='%s']/interface[name='%s']/key2"},
    { 0, SR_STRING_T, "wireless.%s.key3", "/router-wireless:devices/device[name='%s']/interface[name='%s']/key3"},
    { 0, SR_STRING_T, "wireless.%s.key4", "/router-wireless:devices/device[name='%s']/interface[name='%s']/key4"},
    //{ 0, SR_STRING_T, "wireless.%s.radius_server", "/terastream-wireless:devices/device[name='%s']/interface[name='%s']/radius_server"},
    //{ 0, SR_STRING_T, "wireless.%s.radius_port", "/terastream-wireless:devices/device[name='%s']/interface[name='%s']/radius_port"},
    //{ 0, SR_STRING_T, "wireless.%s.radius_secret", "/terastream-wireless:devices/device[name='%s']/interface[name='%s']/radius_secret"},
    //{ "3600", SR_INT32_T, "wireless.%s.gtk_rekey", "/terastream-wireless:devices/device[name='%s']/interface[name='%s']/gtk_rekey"},
    //{ "36000", SR_INT32_T, "wireless.%s.net_reauth", "/terastream-wireless:devices/device[name='%s']/interface[name='%s']/net_reauth"},
    //{ "false", SR_BOOL_T, "wireless.%s.wps_pbc", "/terastream-wireless:devices/device[name='%s']/interface[name='%s']/wps_pbc"},
    //{ "false", SR_BOOL_T, "wireless.%s.wmf_bss_enable", "/terastream-wireless:devices/device[name='%s']/interface[name='%s']/wmf_bss_enable"},
    //{ "32", SR_UINT8_T, "wireless.%s.bss_max" , "/terastream-wireless:devices/device[name='%s']/interface[name='%s']/bss_max"},
    //{ "false", SR_BOOL_T, "wireless.%s.closed", "/terastream-wireless:devices/device[name='%s']/interface[name='%s']/closed"},
    { "false", SR_BOOL_T, "wireless.%s.isolate", "/router-wireless:devices/device[name='%s']/interface[name='%s']/isolate"},
    { "true", SR_BOOL_T,   "wireless.%s.disabled", "/router-wireless:devices/device[name='%s']/interface[name='%s']/enabled"},
    { "0", SR_INT32_T, "wireless.%s.macfilter", "/router-wireless:devices/device[name='%s']/interface[name='%s']/macfilter"},
    { "false", SR_BOOL_T,   "wireless.%s.hidden", "/router-wireless:devices/device[name='%s']/interface[name='%s']/hidden"},
};

/*static sr_uci_link steering[] = {
    { "false", SR_BOOL_T, "wireless.apsteering.enabled", "/terastream-wireless:apsteering/enabled"},
    { "10", SR_INT32_T, "wireless.apsteering.monitor_interval", "/terastream-wireless:apsteering/monitor_interval"},
    { "-80", SR_INT8_T, "wireless.apsteering.rssi_threshold", "/terastream-wireless:apsteering/rssi_threshold"},
    { "5", SR_UINT32_T, "wireless.apsteering.reassoc_timer", "/terastream-wireless:apsteering/reassoc_timer"},
    { "3600", SR_UINT32_T, "wireless.apsteering.retry_interval", "/terastream-wireless:apsteering/retry_interval"},

    { "false", SR_BOOL_T, "wireless.bandsteering.enabled", "/terastream-wireless:bandsteering/enabled"},
    { "false", SR_BOOL_T, "wireless.bansteering.policy", "/terastream-wireless:bandsteering/policy"},
    { "-75", SR_INT8_T, "wireless.bansteering.rssi_threshold", "/terastream-wireless:bandsteering/rssi_threshold"},
    { "60", SR_UINT8_T, "wireless.bansteering.bw_util", "/terastream-wireless:bandsteering/bw_util"},

};*/

static oper_mapping table_operational[] = {
    { "channel", operational_channel },
    { "ssid", operational_ssid },
    { "encryption", operational_encryption },
    { "up", operational_up },
};

char *
transform_orig_sysrepo_value(sr_val_t *value)
{
    char *result = NULL;

    if (SR_BOOL_T == value->type) {
        if (value->data.bool_val) {
            result = strdup("1");
        } else {
            result = strdup("0");
        }
    } else {
        result = sr_val_to_str(value);
    }

    return result;
}

char *
transform_sysrepo_value(char *ucipath, sr_val_t *value)
{
    char *result = NULL;

    if (SR_BOOL_T == value->type) {
        if (value->data.bool_val) {
            result = strdup("0");
        } else {
            result = strdup("1");
        }
    } else {
        /* transform encryption value
         * psk-psk2 to mixed-psk
         * wpa-wpa2 to wpa-mixed
         * */
        if (strlen(ucipath) > 11 && !strcmp(ucipath + strlen(ucipath) - 11, ".encryption")) {
            if (0 == strcmp(value->data.string_val, "psk-psk2")) {
                result = strdup("mixed-psk");
            } else if (0 == strcmp(value->data.string_val, "wpa-wpa2")) {
                result = strdup("wpa-mixed");
            }
        } else if (strlen(ucipath) > 5 && !strcmp(ucipath + strlen(ucipath) - 5, ".band")) {
            if (0 == strcmp(value->data.string_val, "5")) {
                result = strdup("a");
            } else if (0 == strcmp(value->data.string_val, "2.4")) {
                result = strdup("b");
            }
        } else {
            result = sr_val_to_str(value);
        }
    }

    return result;
}

void
transform_default_value(sr_uci_link *map, char **uci_val)
{
    if (0 == strlen(*uci_val) && NULL != map->default_value) {
        strcpy(*uci_val, map->default_value);
    }

    /* transform encryption value
     * mixed-psk to psk-psk2
     * wpa-mixed to wpa-wpa2
     * */
    if (strlen(map->ucipath) > 11 && !strcmp(map->ucipath + strlen(map->ucipath) - 11, ".encryption")) {
        if (0 == strcmp(*uci_val, "mixed-psk")) {
            strcpy(*uci_val, "psk-psk2");
        } else if (0 == strcmp(*uci_val, "wpa-mixed")) {
            strcpy(*uci_val, "wpa-wpa2");
        }
    } else if (strlen(map->ucipath) > 5 && !strcmp(map->ucipath + strlen(map->ucipath) - 5, ".band")) {
        if (0 == strcmp(*uci_val, "a")) {
            strcpy(*uci_val, "5");
        } else if (0 == strcmp(*uci_val, "b")) {
            strcpy(*uci_val, "2.4");
        }
    }
}

void
transform_orig_bool_value(sr_uci_link *map, char **uci_val)
{
    if (SR_BOOL_T != map->default_value_type) {
        return;
    }

    if (0 == strncmp("0", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "false");
    } else if (0 == strncmp("off", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "false");
    } else if (0 == strncmp("no", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "false");
    } else if (0 == strncmp("false", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "false");
    } else if (0 == strncmp("1", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "true");
    } else if (0 == strncmp("on", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "true");
    } else if (0 == strncmp("yes", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "true");
    } else if (0 == strncmp("true", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "true");
    }
}

void
transform_bool_value(sr_uci_link *map, char **uci_val)
{
    if (SR_BOOL_T != map->default_value_type) {
        return;
    }

    if (0 == strncmp("0", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "true");
    } else if (0 == strncmp("off", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "true");
    } else if (0 == strncmp("no", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "true");
    } else if (0 == strncmp("false", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "true");
    } else if (0 == strncmp("1", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "false");
    } else if (0 == strncmp("on", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "false");
    } else if (0 == strncmp("yes", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "false");
    } else if (0 == strncmp("true", *uci_val, strlen(*uci_val))) {
        strcpy(*uci_val, "false");
    }
}

/* Update UCI configuration given ucipath and some string value. */
static int set_uci_item(struct uci_context *uctx, char *ucipath, char *value);

/* Get value from UCI configuration given ucipath and result holder. */
static int get_uci_item(struct uci_context *uctx, char *ucipath, char **value);

static bool
val_has_data(sr_type_t type) {
    /* types containing some data */
    switch(type) {
    case SR_BINARY_T:
    case SR_BITS_T:
    case SR_BOOL_T:
    case SR_DECIMAL64_T:
    case SR_ENUM_T:
    case SR_IDENTITYREF_T:
    case SR_INSTANCEID_T:
    case SR_INT8_T:
    case SR_INT16_T:
    case SR_INT32_T:
    case SR_INT64_T:
    case SR_STRING_T:
    case SR_UINT8_T:
    case SR_UINT16_T:
    case SR_UINT32_T:
    case SR_UINT64_T:
    case SR_ANYXML_T:
    case SR_ANYDATA_T:
        return true;
    default: return false;
    }
}

static char *get_key_value(char *orig_xpath, int n)
{
    char *key = NULL, *node = NULL;
    sr_xpath_ctx_t state = {0, 0, 0, 0};
    int counter = 0;

    node = sr_xpath_next_node(orig_xpath, &state);
    if (NULL == node) {
        goto error;
    }
    while (true) {
        key = sr_xpath_next_key_name(NULL, &state);
        if (NULL != key) {
            if (counter++ != n)
                continue;
            key = strdup(sr_xpath_next_key_value(NULL, &state));
            break;
        }
        node = sr_xpath_next_node(NULL, &state);
        if (NULL == node) {
            break;
        }
    }

error:
    sr_xpath_recover(&state);
    return key;
}

static int
get_uci_item(struct uci_context *uctx, char *ucipath, char **value)
{
    int rc = UCI_OK;
    char path[MAX_UCI_PATH];
    struct uci_ptr ptr;

    sprintf(path, "%s", ucipath);
    rc = uci_lookup_ptr(uctx, &ptr, path, true);
    UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, path);

    if (ptr.o == NULL) {
        ERR("Uci item %s not found", ucipath);
        return UCI_ERR_NOTFOUND;
    }

    strcpy(*value, ptr.o->v.string);

  exit:
    return rc;
}

static int
rename_uci_item(struct uci_context *uctx, char *ucipath, char *value)
{
    int rc = UCI_OK;
    struct uci_ptr ptr;
    char *set_path = calloc(1, MAX_UCI_PATH);

    sprintf(set_path, "%s%s%s", ucipath, "=", value);

    rc = uci_lookup_ptr(uctx, &ptr, set_path, true);
    UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, set_path);

    rc = uci_rename(uctx, &ptr);
    UCI_CHECK_RET(rc, exit, "uci_set %d %s", rc, set_path);

exit:
    free(set_path);
    return rc;
}

static int
set_uci_item(struct uci_context *uctx, char *ucipath, char *value)
{
    int rc = UCI_OK;
    struct uci_ptr ptr;
    char *set_path = calloc(1, MAX_UCI_PATH);

    sprintf(set_path, "%s%s%s", ucipath, "=", value);

    rc = uci_lookup_ptr(uctx, &ptr, set_path, true);
    UCI_CHECK_RET(rc, exit, "lookup_pointer %d %s", rc, set_path);

    rc = uci_set(uctx, &ptr);
    UCI_CHECK_RET(rc, exit, "uci_set %d %s", rc, set_path);

    rc = uci_save(uctx, ptr.p);
    UCI_CHECK_RET(rc, exit, "uci_save %d %s", rc, set_path);

    rc = uci_commit(uctx, &(ptr.p), false);
    UCI_CHECK_RET(rc, exit, "uci_commit %d %s", rc, set_path);

  exit:
    free(set_path);

    return rc;
}

#define WIRELESS_DEVICE_NAME_LENGTH 20

static int
sysrepo_to_uci(sr_session_ctx_t  *session, struct uci_context *uctx, sr_val_t *new_val)
{
    char ucipath[MAX_UCI_PATH];
    char *mem = NULL;
    char *key1 = NULL;
    char *key2 = NULL;
    int rc = SR_ERR_OK;
    char xpath[XPATH_MAX_LEN];

    //TODO handle deletion of interfaces
    if (false == val_has_data(new_val->type)) {
        return SR_ERR_OK;
    }

    key1 = get_key_value(new_val->xpath, 0);
    key2 = get_key_value(new_val->xpath, 1);

    if (strstr(new_val->xpath, "/interface[")) {
        /* handle interface  */
        for (size_t i = 0; i < ARR_SIZE(table_interface); i++) {
            snprintf(xpath, XPATH_MAX_LEN, table_interface[i].xpath, key1, key2);
            if (0 == strcmp(new_val->xpath, xpath)) {
                snprintf(ucipath, MAX_UCI_PATH, table_interface[i].ucipath, key2);
            }
        }
        mem = transform_sysrepo_value(ucipath, new_val);
        rc = set_uci_item(uctx, ucipath, mem);
        UCI_CHECK_RET(rc, uci_error, "set_uci_item %s", sr_strerror(rc));
        if (mem)
            free(mem);
    } else if (strstr(new_val->xpath, "/device[")) {
        /* handle device  */
        for (size_t i = 0; i < ARR_SIZE(table_wireless); i++) {
            snprintf(xpath, XPATH_MAX_LEN, table_wireless[i].xpath, key1);
            if (0 == strcmp(new_val->xpath, xpath)) {
                snprintf(ucipath, MAX_UCI_PATH, table_wireless[i].ucipath, key1);
            }
        }
        mem = transform_sysrepo_value(ucipath, new_val);
        rc = set_uci_item(uctx, ucipath, mem);
        UCI_CHECK_RET(rc, uci_error, "set_uci_item %s", sr_strerror(rc));
        if(mem) free(mem);
    }

   //if (strstr(new_val->xpath, "steering/")) {
   //     /* handle device  */
   //     for (size_t i = 0; i < ARR_SIZE(steering); i++) {
   //         snprintf(xpath, XPATH_MAX_LEN, steering[i].xpath, key1);
   //         if (0 == strcmp(new_val->xpath, xpath)) {
   //             snprintf(ucipath, MAX_UCI_PATH, steering[i].ucipath, key1);
   //         }
   //     }
   //     mem = transform_orig_sysrepo_value(new_val);
   //     rc = set_uci_item(uctx, ucipath, mem);
   //     UCI_CHECK_RET(rc, uci_error, "set_uci_item %s", sr_strerror(rc));
   //     if(mem) free(mem);
   //}

    if (key1) free(key1);
    if (key2) free(key2);

    return rc;
  uci_error:
    return SR_ERR_INTERNAL;
}

/* Text representation of Sysrepo event code. */
static const char *
ev_to_str(sr_notif_event_t ev) {
  switch (ev) {
  case SR_EV_VERIFY:
    return "verify";
  case SR_EV_APPLY:
    return "apply";
  case SR_EV_ABORT:
  default:
    return "abort";
  }
}

static void
restart_network_over_ubus(int wait_time)
{
    struct blob_buf buf = {0};
    struct json_object *p;
    uint32_t id = 0;
    int u_rc = 0;

    struct ubus_context *u_ctx = ubus_connect(NULL);
    if (u_ctx == NULL) {
        ERR_MSG("Could not connect to ubus");
        goto cleanup;
    }

    blob_buf_init(&buf, 0);
    u_rc = ubus_lookup_id(u_ctx, "uci", &id);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object uci\n", u_rc);
        goto cleanup;
    }

    p = json_object_new_object();
    if (NULL == p) {
      ERR_MSG("json_object_new_object() returned a NULL pointer");
      goto cleanup;
    }
    json_object_object_add(p, "config", json_object_new_string("wireless"));
    const char *json_data = json_object_get_string(p);
    if (NULL == json_data) {
      ERR_MSG("json_object_get_string() returned a NULL pointer");
      goto cleanup;
    }
    blobmsg_add_json_from_string(&buf, json_data);

    u_rc = ubus_invoke(u_ctx, id, "commit", buf.head, NULL, NULL, wait_time * 1000);
    if (UBUS_STATUS_OK != u_rc) {
        ERR("ubus [%d]: no object commit\n", u_rc);
        goto cleanup;
    }

cleanup:
    if (NULL != p) {
        json_object_put(p);
    }
    if (NULL != u_ctx) {
        ubus_free(u_ctx);
        blob_buf_free(&buf);
    }
}

static int
wireless_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, uint64_t request_id, void *private_ctx)
{
    struct plugin_ctx *pctx = (struct plugin_ctx*) private_ctx;
    sr_change_iter_t *it = NULL;
    int rc = SR_ERR_OK;
    sr_change_oper_t oper;
    sr_val_t *old_value = NULL;
    sr_val_t *new_value = NULL;
    char change_path[XPATH_MAX_LEN] = {0,};

    INF(">>>>>>>>> EVENT %s <<<<<<<<<", ev_to_str(event));

    snprintf(change_path, XPATH_MAX_LEN, "/%s:*", module_name);

    rc = sr_get_changes_iter(session, change_path , &it);
    if (SR_ERR_OK != rc) {
        printf("Get changes iter failed for xpath %s", change_path);
        goto cleanup;
    }

    while (SR_ERR_OK == (rc = sr_get_change_next(session, it,
                                                 &oper, &old_value, &new_value))) {
        if (SR_OP_CREATED == oper || SR_OP_MODIFIED == oper) {
            rc = sysrepo_to_uci(session, pctx->uctx, new_value);
            sr_print_val(new_value);
        }

        sr_free_val(old_value);
        sr_free_val(new_value);
    }
    INF_MSG("\n\n ========== END OF CHANGES =======================================\n\n");

    if (SR_EV_APPLY == event) { 
      restart_network_over_ubus(2);
      rc = sr_copy_config(pctx->startup_session, module_name, SR_DS_RUNNING, SR_DS_STARTUP);
      return rc;
    }

  cleanup:
    sr_free_change_iter(it);

    return SR_ERR_OK;
}

static int
init_sysrepo_data(struct plugin_ctx *pctx, sr_session_ctx_t *session)
{
    const char uci_package_name[] = "wireless";
    struct uci_element *e;
    struct uci_section *s;
    struct uci_package *package = NULL;
    char xpath[XPATH_MAX_LEN];
    char ucipath[MAX_UCI_PATH];
    int rc = SR_ERR_OK;

    rc = uci_load(pctx->uctx, uci_package_name, &package);
    UCI_CHECK_RET(rc, exit, "[%d] Could not load package %s.", rc, uci_package_name);

    /* remove anonymous sections */
    int interface = 0;
    uci_foreach_element(&package->sections, e) {
        s = uci_to_section(e);
        char *type = s->type;
        char *name = s->e.name;

        if (strcmp("wifi-iface", type) == 0) {
            snprintf(ucipath, MAX_UCI_PATH, "wireless.@wifi-iface[%d]", interface);
            if (s->anonymous) {
                rc = rename_uci_item(pctx->uctx, ucipath, name);
                if (UCI_OK != rc) ERR("rename uci item %s failed", ucipath);
            }
            interface++;
        }
    }
    rc = uci_save(pctx->uctx, package);
    UCI_CHECK_RET(rc, exit, "[%d] Could not save package %s.", rc, uci_package_name);
    rc = uci_commit(pctx->uctx, &package, false);
    UCI_CHECK_RET(rc, exit, "[%d] Could not commit package %s.", rc, uci_package_name);
    if (package) uci_unload(pctx->uctx, package);

    rc = uci_load(pctx->uctx, uci_package_name, &package);
    UCI_CHECK_RET(rc, exit, "[%d] Could not load package %s.", rc, uci_package_name);

    uci_foreach_element(&package->sections, e) {
        s = uci_to_section(e);
        char *type = s->type;
        char *name = s->e.name;

        if (strcmp("wifi-device", type) == 0) {
            INF("uci name type %s %s", name, type);
            char *uci_val = calloc(1, 100);
            for (size_t i = 0; i < ARR_SIZE(table_wireless); i++) {
                snprintf(xpath, XPATH_MAX_LEN, table_wireless[i].xpath, name);
                snprintf(ucipath, MAX_UCI_PATH, table_wireless[i].ucipath, name);
                rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
                if (UCI_ERR_NOTFOUND == rc) {
                    // check if default values exist
                    if (NULL != table_wireless[i].default_value) {
                        strcpy(uci_val,"");
                        rc = UCI_OK;
                    } else {
                        continue;
                    }
                }
                transform_default_value(&table_wireless[i], &uci_val);
                transform_bool_value(&table_wireless[i], &uci_val);
                SR_CHECK_RET(rc, exit, "uci getitem: %s %s", ucipath, sr_strerror(rc));
                rc = sr_set_item_str(session, xpath, uci_val, SR_EDIT_DEFAULT);
                SR_CHECK_RET(rc, exit, "sr setitem: %s %s %s", sr_strerror(rc), xpath, uci_val);
            }
            free(uci_val);
        } else if (strcmp("wifi-iface", type) == 0) {
            char *uci_val = calloc(1, 100);
            char *device = calloc(1, 100);
            snprintf(ucipath, MAX_UCI_PATH, "wireless.%s.device", name);
            rc = get_uci_item(pctx->uctx, ucipath, &device);
            if (UCI_ERR_NOTFOUND == rc) {
                continue;
            }
            for (size_t i = 0; i < ARR_SIZE(table_interface); i++) {
                snprintf(xpath, XPATH_MAX_LEN, table_interface[i].xpath, device, name);
                snprintf(ucipath, MAX_UCI_PATH, table_interface[i].ucipath, name);
                rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
                if (UCI_ERR_NOTFOUND == rc) {
                    // check if default values exist
                    if (NULL != table_interface[i].default_value) {
                        strcpy(uci_val,"");
                        rc = UCI_OK;
                    } else {
                        continue;
                    }
                }
                transform_default_value(&table_interface[i], &uci_val);
                transform_bool_value(&table_interface[i], &uci_val);
                SR_CHECK_RET(rc, exit, "uci getitem: %s %s", ucipath, sr_strerror(rc));
                rc = sr_set_item_str(session, xpath, uci_val, SR_EDIT_DEFAULT);
                SR_CHECK_RET(rc, exit, "sr setitem: %s %s %s", sr_strerror(rc), xpath, uci_val);
            }
            free(uci_val);
            free(device);
        } /*else if (strcmp("bandsteering", type) == 0 || strcmp("apsteering", type) == 0) {
            char *uci_val = calloc(1, 100);
            char *device = calloc(1, 100);
            for (size_t i = 0; i < ARR_SIZE(steering); i++) {
                snprintf(xpath, XPATH_MAX_LEN, steering[i].xpath, device, name);
                snprintf(ucipath, MAX_UCI_PATH, steering[i].ucipath, name);
                rc = get_uci_item(pctx->uctx, ucipath, &uci_val);
                if (UCI_ERR_NOTFOUND == rc) {
                    // check if default values exist
                    if (NULL != steering[i].default_value) {
                        strcpy(uci_val,"");
                        rc = UCI_OK;
                    } else {
                        continue;
                    }
                }
                transform_default_value(&steering[i], &uci_val);
                transform_orig_bool_value(&steering[i], &uci_val);
                SR_CHECK_RET(rc, exit, "uci getitem: %s %s", ucipath, sr_strerror(rc));
                rc = sr_set_item_str(session, xpath, uci_val, SR_EDIT_DEFAULT);
                SR_CHECK_RET(rc, exit, "sr setitem: %s %s %s", sr_strerror(rc), xpath, uci_val);
            }
            free(uci_val);
            free(device);
        }*/
    }

    rc = sr_commit(session);
    SR_CHECK_RET(rc, exit, "Couldn't commit initial interfaces: %s", sr_strerror(rc));

  exit:
    if (package) uci_unload(pctx->uctx, package);
    return rc;
}

int sync_datastores(struct plugin_ctx *ctx)
{
    char startup_file[XPATH_MAX_LEN] = {0};
    int rc = SR_ERR_OK;
    struct stat st;

    /* check if the startup datastore is empty
     * by checking the content of the file */
    snprintf(startup_file, XPATH_MAX_LEN, "/etc/sysrepo/data/%s.startup", YANG_MODEL);

    if (stat(startup_file, &st) != 0) {
        ERR("Could not open sysrepo file %s", startup_file);
        return SR_ERR_INTERNAL;
    }

    if (0 == st.st_size) {
        /* parse uci config */
        rc = init_sysrepo_data(ctx, ctx->startup_session);
        INF_MSG("copy uci data to sysrepo");
        SR_CHECK_RET(rc, error, "failed to apply uci data to sysrepo: %s", sr_strerror(rc));

    }else {
        /* copy the sysrepo startup datastore to uci */
        INF_MSG("copy sysrepo data to uci");
        SR_CHECK_RET(rc, error, "failed to apply sysrepo startup data to snabb: %s", sr_strerror(rc));

    }

error:
    return rc;
}

    static size_t
list_size(struct list_head *list)
{
    size_t current_size = 0;
    struct value_node *vn;

    list_for_each_entry(vn, list, head) {
        current_size += 1;
    }

    return current_size;
}

    int
sr_dup_val_data(sr_val_t *dest, const sr_val_t *source)
{
    int rc = SR_ERR_OK;

    switch (source->type) {
        case SR_BINARY_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.binary_val);
            break;
        case SR_BITS_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.bits_val);
            break;
        case SR_ENUM_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.enum_val);
            break;
        case SR_IDENTITYREF_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.identityref_val);
            break;
        case SR_INSTANCEID_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.instanceid_val);
            break;
        case SR_STRING_T:
            rc = sr_val_set_str_data(dest, source->type, source->data.string_val);
            break;
        case SR_BOOL_T:
        case SR_DECIMAL64_T:
        case SR_INT8_T:
        case SR_INT16_T:
        case SR_INT32_T:
        case SR_INT64_T:
        case SR_UINT8_T:
        case SR_UINT16_T:
        case SR_UINT32_T:
        case SR_UINT64_T:
        case SR_TREE_ITERATOR_T:
            dest->data = source->data;
            dest->type = source->type;
            break;
        default:
            dest->type = source->type;
            break;
    }

    sr_val_set_xpath(dest, source->xpath);
    return rc;
}

static int
#ifdef SYSREPO_LESS_0_7_5
wireless_operational_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
#elifdef SYSREPO_LESS_0_7_7
wireless_operational_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, void *private_ctx)
#else
wireless_operational_cb(const char *cb_xpath, sr_val_t **values, size_t *values_cnt, uint64_t request_id, const char *original_xpath, void *private_ctx)
#endif
{
    char *node;
    struct plugin_ctx *pctx = (struct plugin_ctx *) private_ctx;
    size_t n_mappings;
    int rc = SR_ERR_OK;

    INF("%s", cb_xpath);
    struct list_head list = LIST_HEAD_INIT(list);
    operational_start();
    oper_func func;
    n_mappings = ARR_SIZE(table_operational);

    for (size_t i = 0; i < n_mappings; i++) {
        node = table_operational[i].node;
        func = table_operational[i].op_func;
        INF("\tDiagnostics for: %s", node);
        for (size_t j = 0; j < pctx->interface_count; j++) {
            rc = func(pctx->interface_names[j], &list);
        }
    }

    size_t cnt = 0;
    cnt = list_size(&list);
    INF("Allocating %zu values.", cnt);

    struct value_node *vn, *q;
    size_t j = 0;
    rc = sr_new_values(cnt, values);
    SR_CHECK_RET(rc, exit, "Couldn't create values %s", sr_strerror(rc));

    list_for_each_entry_safe(vn, q, &list, head) {
        rc = sr_dup_val_data(&(*values)[j], vn->value);
        SR_CHECK_RET(rc, exit, "Couldn't copy value: %s", sr_strerror(rc));
        sr_free_val(vn->value);
        list_del(&vn->head);
        free(vn);
        j += 1;
    }

    *values_cnt = cnt;

    list_del(&list);

    if (*values_cnt > 0) {
        INF("[%d - %s]Debug sysrepo values printout: %zu", rc, sr_strerror(rc), *values_cnt);
        for (size_t i = 0; i < *values_cnt; i++){
            sr_print_val(&(*values)[i]);
        }
    }

exit:
    return rc;
}

    static int
get_uci_wireless_devices(struct plugin_ctx *pctx)
{
    const char uci_package_name[] = "wireless";
    struct uci_element *e;
    struct uci_section *s;
    struct uci_package *package = NULL;
    int rc;

    INF("Getting uci devices for %s", uci_package_name);

    rc = uci_load(pctx->uctx, uci_package_name, &package);
    UCI_CHECK_RET(rc, exit, "[%d] Could not load package %s.", rc, uci_package_name);

    uci_foreach_element(&package->sections, e) {
        s = uci_to_section(e);
        char *type = s->type;
        char *name = s->e.name;

        if (strcmp("wifi-device", type) == 0) {
            strcpy(pctx->interface_names[pctx->interface_count++], name);
            INF("%s %s %s", type, name, pctx->interface_names[pctx->interface_count-1]);
        }
    }

exit:
    if (package) uci_unload(pctx->uctx, package);
    return rc;
}


    int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    int rc = SR_ERR_OK;

    INF_MSG("sr_plugin_init_cb for wireless-plugin");

    struct plugin_ctx *ctx = calloc(1, sizeof(*ctx));

    /* Allocate UCI context for uci files. */
    ctx->uctx = uci_alloc_context();
    if (!ctx->uctx) {
        fprintf(stderr, "Can't allocate uci\n");
        goto error;
    }

    *private_ctx = ctx;

    rc = get_uci_wireless_devices(ctx);
    UCI_CHECK_RET(rc, error, "[%d] Could not get list of wireless devices from UCI.", rc);

    for (size_t i = 0; i < ctx->interface_count; i++) {
        INF("%s", ctx->interface_names[i]);
    }

    INF_MSG("Connecting to sysrepo ...");
    rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &ctx->startup_connection);
    SR_CHECK_RET(rc, error, "Error by sr_connect: %s", sr_strerror(rc));


    rc = sr_session_start(ctx->startup_connection, SR_DS_STARTUP, SR_SESS_DEFAULT, &ctx->startup_session);
    SR_CHECK_RET(rc, error, "Error by sr_session_start: %s", sr_strerror(rc));

    rc = sync_datastores(ctx);
    SR_CHECK_RET(rc, error, "Couldn't initialize router-wireless: %s", sr_strerror(rc));
    /* Init wireless. */

    INF_MSG("sr_plugin_init_cb for wireless");
    rc = sr_module_change_subscribe(session, YANG_MODEL, wireless_change_cb, *private_ctx,
                                    0, SR_SUBSCR_DEFAULT, &ctx->subscription);
    SR_CHECK_RET(rc, error, "initialization error: %s", sr_strerror(rc));

    /* Operational data handling. */
    INF_MSG("Subscribing to operational");
    rc = sr_dp_get_items_subscribe(session, "/router-wireless:devices-state", wireless_operational_cb, *private_ctx,
                                   SR_SUBSCR_CTX_REUSE, &ctx->subscription);
    SR_CHECK_RET(rc, error, "Error by sr_dp_get_items_subscribe: %s", sr_strerror(rc));

    SRP_LOG_DBG_MSG("Plugin initialized successfully");
    INF_MSG("sr_plugin_init_cb for sysrepo-plugin-router-wireless finished.");

    return SR_ERR_OK;

  error:
    SRP_LOG_ERR("Plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, ctx->subscription);
    free(ctx);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    INF("Plugin cleanup called, private_ctx is %s available.", private_ctx ? "" : "not");
    if (!private_ctx) return;

    struct plugin_ctx *ctx = private_ctx;
    if (NULL != ctx->subscription) {
        sr_unsubscribe(session, ctx->subscription);
    }
    if (NULL != ctx->startup_session) {
        sr_session_stop(ctx->startup_session);
    }
    if (NULL != ctx->startup_connection) {
        sr_disconnect(ctx->startup_connection);
    }
    if (NULL != ctx->uctx) {
        uci_free_context(ctx->uctx);
    }
    operational_stop();
    free(ctx);

    SRP_LOG_DBG_MSG("Plugin cleaned-up successfully");
}

#ifndef PLUGIN
#include <signal.h>
#include <unistd.h>

volatile int exit_application = 0;

static void
sigint_handler(__attribute__((unused)) int signum) {
    INF_MSG("Sigint called, exiting...");
    exit_application = 1;
}

int
main() {
    INF_MSG("Plugin application mode initialized");
    sr_conn_ctx_t *connection = NULL;
    sr_session_ctx_t *session = NULL;
    void *private_ctx = NULL;
    int rc = SR_ERR_OK;

    /* connect to sysrepo */
    INF_MSG("Connecting to sysrepo ...");
    rc = sr_connect(YANG_MODEL, SR_CONN_DEFAULT, &connection);
    SR_CHECK_RET(rc, cleanup, "Error by sr_connect: %s", sr_strerror(rc));

    /* start session */
    INF_MSG("Starting session ...");
    rc = sr_session_start(connection, SR_DS_RUNNING, SR_SESS_DEFAULT, &session);
    SR_CHECK_RET(rc, cleanup, "Error by sr_session_start: %s", sr_strerror(rc));

    INF_MSG("Initializing plugin ...");
    rc = sr_plugin_init_cb(session, &private_ctx);
    SR_CHECK_RET(rc, cleanup, "Error by sr_plugin_init_cb: %s", sr_strerror(rc));

    /* loop until ctrl-c is pressed / SIGINT is received */
    signal(SIGINT, sigint_handler);
    signal(SIGPIPE, SIG_IGN);
    while (!exit_application) {
        sleep(1);  /* or do some more useful work... */
    }

    sr_plugin_cleanup_cb(session, private_ctx);
  cleanup:
    if (NULL != session) {
        sr_session_stop(session);
    }
    if (NULL != connection) {
        sr_disconnect(connection);
    }
}
#endif
