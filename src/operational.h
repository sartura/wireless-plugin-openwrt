#include <libubus.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <json-c/json.h>

#include <sysrepo.h>
#include <sysrepo/values.h>

#define MAX_XPATH 256

struct value_node {
  struct list_head head;
  sr_val_t *value;
};

typedef void (*ubus_val_to_sr_val)(json_object *, char *, struct list_head *list);

typedef int (*oper_func)(char *, struct list_head *);


typedef struct oper_mapping {
  char *node;
  oper_func op_func;
} oper_mapping;


int operational_start();
void operational_stop();

int operational_channel(char *, struct list_head *);
int operational_ssid(char *, struct list_head *);
int operational_encryption(char *, struct list_head *);
int operational_up(char *interface_name, struct list_head *);

