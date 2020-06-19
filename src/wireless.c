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
	return -1;
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
	return SR_ERR_CALLBACK_FAILED;
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
