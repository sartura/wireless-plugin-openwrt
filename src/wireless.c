#include <inttypes.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/xpath.h>

#include <srpo_uci.h>
#include <srpo_ubus.h>

#include "transform_data.h"
#include "utils/memory.h"

#define ARRAY_SIZE(X) (sizeof((X)) / sizeof((X)[0]))

#define WIRELESS_YANG_MODEL "router-wireless"
#define SYSREPOCFG_EMPTY_CHECK_COMMAND "sysrepocfg -X -d running -m " WIRELESS_YANG_MODEL
#define WIRELESS_DEVICE_XPATH_TEMPLATE "/" WIRELESS_YANG_MODEL ":devices/device[name='%s']"
#define WIRELESS_DEVICES_STATE_DATA_PATH "/" WIRELESS_YANG_MODEL ":devices-state"
#define WIRELESS_DEVICES_STATE_DATA_XPATH_TEMPLATE WIRELESS_DEVICES_STATE_DATA_PATH "/device[name='%s']"

int wireless_plugin_init_cb(sr_session_ctx_t *session, void **private_data);
void wireless_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data);

static int wireless_module_change_cb(sr_session_ctx_t *session, const char *module_name,
				     const char *xpath, sr_event_t event,
				     uint32_t request_id, void *private_data);
static int wireless_state_data_cb(sr_session_ctx_t *session, const char *module_name,
				  const char *path, const char *request_xpath,
				  uint32_t request_id, struct lyd_node **parent,
				  void *private_data);

static bool wireless_running_datastore_is_empty_check(void);
static int wireless_uci_data_load(sr_session_ctx_t *session);
static char *wireless_xpath_get(const struct lyd_node *node);

srpo_uci_xpath_uci_template_map_t wireless_xpath_uci_path_template_map[] = {
	// device
	{WIRELESS_DEVICE_XPATH_TEMPLATE,			"wireless.%s", "wifi-device", NULL, NULL, false, false},
	{WIRELESS_DEVICE_XPATH_TEMPLATE "/type",		"wireless.%s.type", NULL, NULL, NULL, false, false},
	{WIRELESS_DEVICE_XPATH_TEMPLATE "/country",		"wireless.%s.country", NULL, NULL, NULL, false, false},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/frequencyband",	"wireless.%s.band", NULL,
	// 	transform_data_freqband_to_band_transform, transform_data_band_to_freqband_transform, true, true},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/bandwidth",		"wireless.%s.bandwidth", NULL, NULL, NULL, false, false},
	{WIRELESS_DEVICE_XPATH_TEMPLATE "/channel",		"wireless.%s.channel", NULL, NULL, NULL, false, false},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/obss_coex",		"wireless.%s.obss_coex", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/scantimer",		"wireless.%s.scantimer", NULL, NULL, NULL, false, false},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/wmm",			"wireless.%s.wmm", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/wmm_noack",		"wireless.%s.wmm_noack", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/wmm_apsd",		"wireless.%s.wmm_apsd", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	{WIRELESS_DEVICE_XPATH_TEMPLATE "/txpower",		"wireless.%s.txpower", NULL, NULL, NULL, false, false},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/rateset",		"wireless.%s.rateset", NULL, NULL, NULL, false, false},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/frag",		"wireless.%s.frag", NULL, NULL, NULL, false, false},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/rts",			"wireless.%s.rts", NULL, NULL, NULL, false, false},
	{WIRELESS_DEVICE_XPATH_TEMPLATE "/dtim_period",		"wireless.%s.dtim_period", NULL, NULL, NULL, false, false},
	{WIRELESS_DEVICE_XPATH_TEMPLATE "/beacon_int",		"wireless.%s.beacon_int", NULL, NULL, NULL, false, false},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/rxchainps",		"wireless.%s.rxchainps", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/rxchainps_qt",	"wireless.%s.rxchainps_qt", NULL, NULL, NULL, false, false},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/rxchainps_pps",	"wireless.%s.rxchainps_pps", NULL, NULL, NULL, false, false},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/rifs",		"wireless.%s.rifs", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/rifs_advert",		"wireless.%s.rifs_advert", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	{WIRELESS_DEVICE_XPATH_TEMPLATE "/maxassoc",		"wireless.%s.maxassoc", NULL, NULL, NULL, false, false},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/dfsc",		"wireless.%s.dfsc", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	{WIRELESS_DEVICE_XPATH_TEMPLATE "/hwmode",		"wireless.%s.hwmode", NULL, NULL, NULL, false, false},
	{WIRELESS_DEVICE_XPATH_TEMPLATE "/enabled",		"wireless.%s.disabled", NULL,
		transform_data_boolean_to_zero_one_negated_transform, transform_data_zero_one_to_boolean_negated_transform, true, true},
	{WIRELESS_DEVICE_XPATH_TEMPLATE "/frameburst",		"wireless.%s.frameburst", NULL,
		transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/beamforming",		"wireless.%s.beamforming", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	// {WIRELESS_DEVICE_XPATH_TEMPLATE "/atf",			"wireless.%s.atf", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	{WIRELESS_DEVICE_XPATH_TEMPLATE "/doth",		"wireless.%s.doth", NULL, NULL, NULL, false, false},

	/*
	// *steering
        {"/" WIRELESS_YANG_MODEL ":apsteering/enabled",		 "wireless.apsteering.enabled", NULL,
		transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	{"/" WIRELESS_YANG_MODEL ":apsteering/monitor_interval", "wireless.apsteering.monitor_interval", NULL, NULL, NULL, false, false},
	{"/" WIRELESS_YANG_MODEL ":apsteering/rssi_threshold",	 "wireless.apsteering.rssi_threshold", NULL, NULL, NULL, false, false},
	{"/" WIRELESS_YANG_MODEL ":apsteering/reassoc_timer",	 "wireless.apsteering.reassoc_timer", NULL, NULL, NULL, false, false},
	{"/" WIRELESS_YANG_MODEL ":apsteering/retry_interval",	 "wireless.apsteering.retry_interval", NULL, NULL, NULL, false, false},

        {"/" WIRELESS_YANG_MODEL ":bandsteering/enabled",	 "wireless.bandsteering.enabled", NULL,
		transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	{"/" WIRELESS_YANG_MODEL ":bandsteering/policy",	 "wireless.bandsteering.policy", NULL,
		transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	{"/" WIRELESS_YANG_MODEL ":bandsteering/rssi_threshold", "wireless.bandsteering.rssi_threshold", NULL, NULL, NULL, false, false},
	{"/" WIRELESS_YANG_MODEL ":bandsteering/bw_util",	 "wireless.bandsteering.bw_util", NULL, NULL, NULL, false, false},
        */
};

srpo_uci_xpath_uci_template_map_t wireless_xpath_uci_path_unnamed_template_map[] = {
	{"/interface[name='%s']/ifname", 	 "wireless.%s.ifname", "wifi-iface", NULL, NULL, false, false},
	{"/interface[name='%s']/network",	 "wireless.%s.network", NULL, NULL, NULL, false, false},
	{"/interface[name='%s']/mode", 		 "wireless.%s.mode", NULL, NULL, NULL, false, false},
	{"/interface[name='%s']/ssid", 		 "wireless.%s.ssid", NULL, NULL, NULL, false, false},
	{"/interface[name='%s']/encryption",	 "wireless.%s.encryption", NULL, NULL, NULL, false, false},
	// {"/interface[name='%s']/cipher", 	 "wireless.%s.cipher", NULL, NULL, NULL, false, false},
	{"/interface[name='%s']/key", 		 "wireless.%s.key", NULL, NULL, NULL, false, false},
	// {"/interface[name='%s']/key_index", 	 "wireless.%s.key_index", NULL, NULL, NULL, false, false},
	{"/interface[name='%s']/key1", 		 "wireless.%s.key1", NULL, NULL, NULL, false, false},
	{"/interface[name='%s']/key2", 		 "wireless.%s.key2", NULL, NULL, NULL, false, false},
	{"/interface[name='%s']/key3", 		 "wireless.%s.key3", NULL, NULL, NULL, false, false},
	{"/interface[name='%s']/key4", 		 "wireless.%s.key4", NULL, NULL, NULL, false, false},
	// {"/interface[name='%s']/radius_server",  "wireless.%s.radius_server", NULL, NULL, NULL, false, false},
	// {"/interface[name='%s']/radius_port", 	 "wireless.%s.radius_port", NULL, NULL, NULL, false, false},
	// {"/interface[name='%s']/radius_secret",  "wireless.%s.radius_secret", NULL, NULL, NULL, false, false},
	// {"/interface[name='%s']/gtk_rekey", 	 "wireless.%s.gtk_rekey", NULL, NULL, NULL, false, false},
	// {"/interface[name='%s']/net_reauth", 	 "wireless.%s.net_reauth", NULL, NULL, NULL, false, false},
	// {"/interface[name='%s']/wps_pbc", 	 "wireless.%s.wps_pbc", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	// {"/interface[name='%s']/wmf_bss_enable", "wireless.%s.wmf_bss_enable", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	// {"/interface[name='%s']/bss_max", 	 "wireless.%s.bss_max", NULL, NULL, NULL, false, false},
	// {"/interface[name='%s']/closed", 	 "wireless.%s.closed", NULL,
	// 	transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	{"/interface[name='%s']/isolate", 	 "wireless.%s.isolate", NULL,
		transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
	{"/interface[name='%s']/enabled", 	 "wireless.%s.disabled", NULL,
		transform_data_boolean_to_zero_one_negated_transform, transform_data_zero_one_to_boolean_negated_transform, true, true},
	{"/interface[name='%s']/macfilter", 	 "wireless.%s.macfilter", NULL, NULL, NULL, false, false},
	{"/interface[name='%s']/hidden", 	 "wireless.%s.hidden", NULL,
		transform_data_boolean_to_zero_one_transform, transform_data_zero_one_to_boolean_transform, true, true},
};

static const char *wireless_uci_sections[] = {"wifi-status", "wifi-device"/*, "bandsteering", "apsteering"*/};
static const char *wireless_uci_unnamed_sections[] = {"wifi-iface"};

static struct {
	const char *uci_file;
	const char **uci_section_list;
	size_t uci_section_list_size;
	bool convert_unnamed_sections;
} wireless_config_files[] = {
	{"wireless", wireless_uci_sections, ARRAY_SIZE(wireless_uci_sections), true},
	{"wireless", wireless_uci_unnamed_sections, ARRAY_SIZE(wireless_uci_unnamed_sections), false},
};

int wireless_plugin_init_cb(sr_session_ctx_t *session, void **private_data)
{
	int error = 0;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *startup_session = NULL;
	sr_subscription_ctx_t *subscription = NULL;

	*private_data = NULL;

	error = srpo_uci_init();
	if (error) {
		SRP_LOG_ERR("srpo_uci_init error (%d): %s", error, srpo_uci_error_description_get(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("start session to startup datastore");

	connection = sr_session_get_connection(session);
	error = sr_session_start(connection, SR_DS_STARTUP, &startup_session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	*private_data = startup_session;

	if (wireless_running_datastore_is_empty_check() == true) {
		SRP_LOG_INFMSG("running DS is empty, loading data from UCI");

		error = wireless_uci_data_load(session);
		if (error) {
			SRP_LOG_ERRMSG("wireless_uci_data_load error");
			goto error_out;
		}

		error = sr_copy_config(startup_session, WIRELESS_YANG_MODEL, SR_DS_RUNNING, 0, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	}

	SRP_LOG_INFMSG("subscribing to module change");

	error = sr_module_change_subscribe(session, WIRELESS_YANG_MODEL,
					   "/" WIRELESS_YANG_MODEL ":*//*",
					   wireless_module_change_cb, *private_data, 0,
					   SR_SUBSCR_DEFAULT, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_module_change_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("subscribing to get oper items");

	error = sr_oper_get_items_subscribe(session, WIRELESS_YANG_MODEL, WIRELESS_DEVICES_STATE_DATA_PATH,
					    wireless_state_data_cb, *private_data,
					    SR_SUBSCR_CTX_REUSE, &subscription);
	if (error) {
		SRP_LOG_ERR("sr_oper_get_items_subscribe error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	SRP_LOG_INFMSG("plugin init done");

	goto out;

error_out:
	sr_unsubscribe(subscription);

out:

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static bool wireless_running_datastore_is_empty_check(void)
{
	FILE *sysrepocfg_DS_empty_check = NULL;
	bool is_empty = false;

	sysrepocfg_DS_empty_check = popen(SYSREPOCFG_EMPTY_CHECK_COMMAND, "r");
	if (sysrepocfg_DS_empty_check == NULL) {
		SRP_LOG_WRN("could not execute %s", SYSREPOCFG_EMPTY_CHECK_COMMAND);
		is_empty = true;
		goto out;
	}

	if (fgetc(sysrepocfg_DS_empty_check) == EOF) {
		is_empty = true;
	}

out:
	if (sysrepocfg_DS_empty_check) {
		pclose(sysrepocfg_DS_empty_check);
	}

	return is_empty;
}

static int wireless_uci_data_load(sr_session_ctx_t *session)
{
	int error = 0;
	char **uci_path_list = NULL;
	size_t uci_path_list_size = 0;
	char *xpath = NULL;
	srpo_uci_transform_data_cb transform_uci_data_cb = NULL;
	bool has_transform_uci_data_private = false;
	char *uci_section_name = NULL;
	char **uci_value_list = NULL;
	size_t uci_value_list_size = 0;
	srpo_uci_xpath_uci_template_map_t *template_map = NULL;
	size_t template_map_size = 0;

	for (size_t i = 0; i < ARRAY_SIZE(wireless_config_files); i++) {

		if (wireless_config_files[i].convert_unnamed_sections) {
			template_map = wireless_xpath_uci_path_template_map;
			template_map_size = ARRAY_SIZE(wireless_xpath_uci_path_template_map);
		} else {
			template_map = wireless_xpath_uci_path_unnamed_template_map;
			template_map_size = ARRAY_SIZE(wireless_xpath_uci_path_unnamed_template_map);
		}

		error = srpo_uci_ucipath_list_get(wireless_config_files[i].uci_file,
						  wireless_config_files[i].uci_section_list,
						  wireless_config_files[i].uci_section_list_size,
						  &uci_path_list, &uci_path_list_size,
						  wireless_config_files[i].convert_unnamed_sections);
		if (error) {
			SRP_LOG_ERR("srpo_uci_path_list_get error (%d): %s", error, srpo_uci_error_description_get(error));
			goto error_out;
		}

		for (size_t j = 0; j < uci_path_list_size; j++) {
			if (wireless_config_files[i].convert_unnamed_sections) {
				error = srpo_uci_ucipath_to_xpath_convert(uci_path_list[j], template_map, template_map_size,
									  &xpath);
			} else {
				error = srpo_uci_sublist_ucipath_to_xpath_convert(uci_path_list[j],
										  WIRELESS_DEVICE_XPATH_TEMPLATE, "wireless.%s.device",
										  template_map, template_map_size,
										  &xpath);
			}

			if (error && error != SRPO_UCI_ERR_NOT_FOUND) {
				SRP_LOG_ERR("srpo_uci_to_xpath_path_convert error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			} else if (error == SRPO_UCI_ERR_NOT_FOUND) {
				FREE_SAFE(uci_path_list[j]);
				continue;
			}

			error = srpo_uci_transform_uci_data_cb_get(uci_path_list[j], template_map, template_map_size,
								   &transform_uci_data_cb);
			if (error) {
				SRP_LOG_ERR("srpo_uci_transfor_uci_data_cb_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			error = srpo_uci_has_transform_uci_data_private_get(uci_path_list[j], template_map, template_map_size,
									    &has_transform_uci_data_private);
			if (error) {
				SRP_LOG_ERR("srpo_uci_has_transform_uci_data_private_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			uci_section_name = srpo_uci_section_name_get(uci_path_list[j]);

			error = srpo_uci_element_value_get(uci_path_list[j],
							   transform_uci_data_cb,
							   has_transform_uci_data_private ? uci_section_name : NULL,
							   &uci_value_list, &uci_value_list_size);
			if (error) {
				SRP_LOG_ERR("srpo_uci_element_value_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			for (size_t k = 0; k < uci_value_list_size; k++) {
				error = sr_set_item_str(session, xpath, uci_value_list[k], NULL, SR_EDIT_DEFAULT);
				if (error) {
					SRP_LOG_ERR("sr_set_item_str error (%d): %s", error, sr_strerror(error));
					goto error_out;
				}

				FREE_SAFE(uci_value_list[k]);
			}

			FREE_SAFE(uci_section_name);
			FREE_SAFE(uci_path_list[j]);
			FREE_SAFE(xpath);
		}

		/*
		 * FIXME: libuci otherwise checks the context for existing file
		 * in `uci_switch_config` and throws `UCI_ERR_DUPLICATE`.
		 */
		srpo_uci_cleanup();
		error = srpo_uci_init();
		if (error) {
			SRP_LOG_ERR("srpo_uci_init error (%d): %s", error, srpo_uci_error_description_get(error));
			goto error_out;
		}
	}

	FREE_SAFE(uci_value_list);
	FREE_SAFE(uci_path_list);

	error = sr_apply_changes(session, 0, 0);
	if (error) {
		SRP_LOG_ERR("sr_apply_changes error (%d): %s", error, sr_strerror(error));
		goto error_out;
	}

	goto out;

error_out:
	FREE_SAFE(xpath);
	FREE_SAFE(uci_section_name);

	for (size_t i = 0; i < uci_path_list_size; i++) {
		FREE_SAFE(uci_path_list[i]);
	}

	FREE_SAFE(uci_path_list);

	for (size_t i = 0; i < uci_value_list_size; i++) {
		FREE_SAFE(uci_value_list[i]);
	}

	FREE_SAFE(uci_value_list);

out:

	return error ? -1 : 0;
}

void wireless_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_data)
{
	srpo_uci_cleanup();

	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;

	if (startup_session) {
		sr_session_stop(startup_session);
	}

	SRP_LOG_INFMSG("plugin cleanup finished");
}

static int wireless_module_change_cb(sr_session_ctx_t *session, const char *module_name,
				     const char *xpath, sr_event_t event,
				     uint32_t request_id, void *private_data)
{
	int error = 0;
	sr_session_ctx_t *startup_session = (sr_session_ctx_t *) private_data;
	sr_change_iter_t *wireless_module_change_iter = NULL;
	sr_change_oper_t operation = SR_OP_CREATED;
	const struct lyd_node *node = NULL;
	const char *prev_value = NULL;
	const char *prev_list = NULL;
	bool prev_default = false;
	char *node_xpath = NULL;
	const char *node_value = NULL;
	char *uci_path = NULL;
	struct lyd_node_leaf_list *node_leaf_list;
	struct lys_node_leaf *schema_node_leaf;
	srpo_uci_transform_data_cb transform_sysrepo_data_cb = NULL;
	bool has_transform_sysrepo_data_private = false;
	const char *uci_section_type = NULL;
	char *uci_section_name = NULL;
	void *transform_cb_data = NULL;
	srpo_uci_xpath_uci_template_map_t *template_map = NULL;
	size_t template_map_size = 0;

	SRP_LOG_INF("module_name: %s, xpath: %s, event: %d, request_id: %" PRIu32, module_name, xpath, event, request_id);

	if (event == SR_EV_ABORT) {
		SRP_LOG_ERR("aborting changes for: %s", xpath);
		error = -1;
		goto error_out;
	}

	if (event == SR_EV_DONE) {
		error = sr_copy_config(startup_session, WIRELESS_YANG_MODEL, SR_DS_RUNNING, 0, 0);
		if (error) {
			SRP_LOG_ERR("sr_copy_config error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}
	}

	if (event == SR_EV_CHANGE) {
		error = sr_get_changes_iter(session, xpath, &wireless_module_change_iter);
		if (error) {
			SRP_LOG_ERR("sr_get_changes_iter error (%d): %s", error, sr_strerror(error));
			goto error_out;
		}

		while (sr_get_change_tree_next(session, wireless_module_change_iter, &operation, &node,
					       &prev_value, &prev_list, &prev_default) == SR_ERR_OK) {
			node_xpath = wireless_xpath_get(node);

			/* sublist case is handled specially */
			if (strcmp(node->parent->schema->name, "interface") == 0) {
				template_map = wireless_xpath_uci_path_unnamed_template_map;
				template_map_size = ARRAY_SIZE(wireless_xpath_uci_path_unnamed_template_map);
			} else {
				template_map = wireless_xpath_uci_path_template_map;
				template_map_size = ARRAY_SIZE(wireless_xpath_uci_path_template_map);
			}

			error = srpo_uci_xpath_to_ucipath_convert(node_xpath, template_map, template_map_size,
								  &uci_path);
			if (error && error != SRPO_UCI_ERR_NOT_FOUND) {
				SRP_LOG_ERR("srpo_uci_xpath_to_ucipath_convert error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			} else if (error == SRPO_UCI_ERR_NOT_FOUND) {
				error = 0;
				SRP_LOG_DBG("xpath %s not found in table", node_xpath);
				FREE_SAFE(node_xpath);
				continue;
			}

			error = srpo_uci_transform_sysrepo_data_cb_get(node_xpath, template_map, template_map_size,
								       &transform_sysrepo_data_cb);
			if (error) {
				SRP_LOG_ERR("srpo_uci_transfor_sysrepo_data_cb_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			error = srpo_uci_has_transform_sysrepo_data_private_get(node_xpath, template_map, template_map_size,
										&has_transform_sysrepo_data_private);
			if (error) {
				SRP_LOG_ERR("srpo_uci_has_transform_sysrepo_data_private_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			error = srpo_uci_section_type_get(uci_path, template_map, template_map_size,
							  &uci_section_type);
			if (error) {
				SRP_LOG_ERR("srpo_uci_section_type_get error (%d): %s", error, srpo_uci_error_description_get(error));
				goto error_out;
			}

			uci_section_name = srpo_uci_section_name_get(uci_path);

			if (node->schema->nodetype == LYS_LEAF || node->schema->nodetype == LYS_LEAFLIST) {
				node_leaf_list = (struct lyd_node_leaf_list *) node;
				node_value = node_leaf_list->value_str;
				if (node_value == NULL) {
					schema_node_leaf = (struct lys_node_leaf *) node_leaf_list->schema;
					node_value = schema_node_leaf->dflt ? schema_node_leaf->dflt : "";
				}
			}

			SRP_LOG_DBG("uci_path: %s; prev_val: %s; node_val: %s; operation: %d", uci_path, prev_value, node_value, operation);

			if (node->schema->nodetype == LYS_LIST) {
				if (operation == SR_OP_CREATED) {
					error = srpo_uci_section_create(uci_path, uci_section_type);
					if (error) {
						SRP_LOG_ERR("srpo_uci_section_create error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpo_uci_section_delete(uci_path);
					if (error) {
						SRP_LOG_ERR("srpo_uci_section_delete error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				}
			} else if (node->schema->nodetype == LYS_LEAF) {
				if (operation == SR_OP_CREATED || operation == SR_OP_MODIFIED) {
					if (has_transform_sysrepo_data_private) {
						transform_cb_data = uci_section_name;
					} else {
						transform_cb_data = NULL;
					}

					error = srpo_uci_option_set(uci_path, node_value, transform_sysrepo_data_cb, transform_cb_data);
					if (error) {
						SRP_LOG_ERR("srpo_uci_option_set error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpo_uci_option_remove(uci_path);
					if (error) {
						SRP_LOG_ERR("srpo_uci_option_remove error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				}
			} else if (node->schema->nodetype == LYS_LEAFLIST) {
				if (has_transform_sysrepo_data_private) {
					transform_cb_data = uci_section_name;
				} else {
					transform_cb_data = NULL;
				}

				if (operation == SR_OP_CREATED) {
					error = srpo_uci_list_set(uci_path, node_value, transform_sysrepo_data_cb, transform_cb_data);
					if (error) {
						SRP_LOG_ERR("srpo_uci_list_set error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				} else if (operation == SR_OP_DELETED) {
					error = srpo_uci_list_remove(uci_path, node_value);
					if (error) {
						SRP_LOG_ERR("srpo_uci_list_remove error (%d): %s", error, srpo_uci_error_description_get(error));
						goto error_out;
					}
				}
			}

			FREE_SAFE(uci_section_name);
			FREE_SAFE(uci_path);
			FREE_SAFE(node_xpath);
			node_value = NULL;
		}

		srpo_uci_commit("wireless");
	}

	goto out;

error_out:
	srpo_uci_revert("wireless");

out:
	FREE_SAFE(uci_section_name);
	FREE_SAFE(node_xpath);
	FREE_SAFE(uci_path);
	sr_free_change_iter(wireless_module_change_iter);

	return error ? SR_ERR_CALLBACK_FAILED : SR_ERR_OK;
}

static char *wireless_xpath_get(const struct lyd_node *node)
{
	char *xpath_node = NULL;
	char *xpath_node_pos = NULL;
	char *xpath_node_pos_second = NULL;
	size_t xpath_trimed_size = 0;
	char *xpath_trimed = NULL;

	if (node->schema->nodetype == LYS_LEAFLIST) {
		xpath_node = lyd_path(node);
		xpath_node_pos = strrchr(xpath_node, '[');
		if (xpath_node_pos == NULL)
			return xpath_node;

		xpath_trimed_size = (size_t)xpath_node_pos - (size_t)xpath_node + 1;
		xpath_trimed = xcalloc(1, xpath_trimed_size);
		strncpy(xpath_trimed, xpath_node, xpath_trimed_size - 1);
		xpath_trimed[xpath_trimed_size - 1] = '\0';

		FREE_SAFE(xpath_node);

		return xpath_trimed;
	} else if (node->parent->schema->nodetype == LYS_LIST &&
		   node->parent->parent->schema->nodetype == LYS_LIST) {
		xpath_node = lyd_path(node);

		xpath_node_pos = strrchr(xpath_node, '/');
		if (xpath_node_pos == NULL)
			return xpath_node;

		/* Temporarily mangle memory to find the second-to-last
		 * occurence of the delimiter in string.
		 */
		*xpath_node_pos = '\0';

		xpath_node_pos_second = strrchr(xpath_node, '/');
		if (xpath_node_pos_second == NULL)
			return xpath_node;

		/* Unmangle string in memory. */
		*xpath_node_pos = '/';

		xpath_trimed = xstrdup(xpath_node_pos_second);

		FREE_SAFE(xpath_node);

		return xpath_trimed;
	} else {
		return lyd_path(node);
	}
}

static int wireless_state_data_cb(sr_session_ctx_t *session, const char *module_name,
				  const char *path, const char *request_xpath,
				  uint32_t request_id, struct lyd_node **parent,
				  void *private_data)
{
	return SR_ERR_CALLBACK_FAILED;
}


#ifndef PLUGIN
#include <signal.h>

volatile int exit_application = 0;

static void sigint_handler(__attribute__((unused)) int signum);

int main()
{
  int error = SR_ERR_OK;
	sr_conn_ctx_t *connection = NULL;
	sr_session_ctx_t *session = NULL;
	void *private_data = NULL;

	sr_log_stderr(SR_LL_DBG);

	/* connect to sysrepo */
	error = sr_connect(SR_CONN_DEFAULT, &connection);
	if (error) {
		SRP_LOG_ERR("sr_connect error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = sr_session_start(connection, SR_DS_RUNNING, &session);
	if (error) {
		SRP_LOG_ERR("sr_session_start error (%d): %s", error, sr_strerror(error));
		goto out;
	}

	error = wireless_plugin_init_cb(session, &private_data);
	if (error) {
		SRP_LOG_ERRMSG("wireless_plugin_init_cb error");
		goto out;
	}

	/* loop until ctrl-c is pressed / SIGINT is received */
	signal(SIGINT, sigint_handler);
	signal(SIGPIPE, SIG_IGN);
	while (!exit_application) {
		sleep(1);
	}

out:
	wireless_plugin_cleanup_cb(session, private_data);
	sr_disconnect(connection);

	return error ? -1 : 0;
}

static void sigint_handler(__attribute__((unused)) int signum)
{
	SRP_LOG_INFMSG("Sigint called, exiting...");
	exit_application = 1;
}

#endif
