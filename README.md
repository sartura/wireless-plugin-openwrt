# Sysrepo Wireless plugin (generic)

## Introduction

This Sysrepo plugin is responsible for bridging OpenWrt [**UCI**]() (Unified Configuration Interface) and Sysrepo/YANG datastore configuration for wireless interfaces.

## Development Setup

Setup the development environment using the provided [`setup-dev-sysrepo`](https://github.com/sartura/setup-dev-sysrepo) scripts. This will build all the necessary components and initialize a sparse OpenWrt filesystem.

Subsequent rebuilds of the plugin may be done by navigating to the plugin source directory and executing:

```
$ export SYSREPO_DIR=${HOME}/code/sysrepofs
$ cd ${SYSREPO_DIR}/repositories/plugins/wireless-plugin-openwrt

$ rm -rf ./build && mkdir ./build && cd ./build
$ cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DCMAKE_PREFIX_PATH=${SYSREPO_DIR} \
		-DCMAKE_INSTALL_PREFIX=${SYSREPO_DIR} \
		-DCMAKE_BUILD_TYPE=Debug \
		..
-- The C compiler identification is GNU 9.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
[...]
-- Configuring done
-- Generating done
-- Build files have been written to: ${SYSREPO_DIR}/repositories/plugins/wireless-plugin-openwrt/build

$ make && make install
[...]
[ 75%] Building C object CMakeFiles/sysrepo-plugin-router-wireless.dir/src/utils/memory.c.o
[100%] Linking C executable sysrepo-plugin-router-wireless
[100%] Built target sysrepo-plugin-router-wireless
[100%] Built target sysrepo-plugin-router-wireless
Install the project...
-- Install configuration: "Debug"
-- Installing: ${SYSREPO_DIR}/bin/sysrepo-plugin-router-wireless
-- Set runtime path of "${SYSREPO_DIR}/bin/sysrepo-plugin-router-wireless" to ""

$ cd ..
```

Before using the plugin it is necessary to install relevant YANG modules. For this particular plugin, the following commands need to be invoked:

```
$ cd ${SYSREPO_DIR}/repositories/plugins/wireless-plugin-openwrt
$ export LD_LIBRARY_PATH="${SYSREPO_DIR}/lib64;${SYSREPO_DIR}/lib"
$ export PATH="${SYSREPO_DIR}/bin:${PATH}"

$ sysrepoctl -i ./yang/router-wireless@2018-11-27.yang
```

## YANG Overview

The `router-wireless` YANG module with the `ro-ws` prefix consists of the following `container` paths:

* `/router-wireless:devices` — configuration state data for devices

The following items are not configurational i.e. they are `operational` state data:

* `/router-wireless:devices-state` — operational data for devices

## Running and Examples

This plugin is installed as the `sysrepo-plugin-router-wireless` binary to `${SYSREPO_DIR}/bin/` directory path. Simply invoke this binary, making sure that the environment variables are set correctly:

```
$ sysrepo-plugin-router-wireless

[INF]: Applying scheduled changes.
[INF]: Module "router-wireless" was installed.
[INF]: Scheduled changes applied.
[INF]: Session 29 (user "...") created.
[INF]: plugin: start session to startup datastore
[INF]: Session 30 (user "...") created.
[INF]: plugin: running DS is empty, loading data from UCI
[INF]: There are no subscribers for changes of the module "router-wireless" in running DS.
[INF]: plugin: subscribing to module change
[INF]: plugin: subscribing to get oper items
[INF]: plugin: plugin init done
```

Output from the plugin is expected; the plugin has loaded UCI configuration at `${SYSREPO_DIR}/etc/config/wireless` into the `startup` datastore. We can confirm this by invoking the following commands:

```
$ cat ${SYSREPO_DIR}/etc/config/wireless
config wifi-status 'status'
	option wlan '1'
	option wps '1'
	option sched_status '0'
	option schedule '0'

config bandsteering 'bandsteering'
	option enabled '0'
	option policy '0'

config wifi-device 'wl0'
	option type 'broadcom'
	option country 'EU/13'
	option band 'a'
	option bandwidth '80'
	option hwmode 'auto'
	option channel 'auto'
	option scantimer '15'
	option wmm '1'
	option wmm_noack '0'
	option wmm_apsd '1'
	option txpower '100'
	option rateset 'default'
	option frag '2346'
	option rts '2347'
	option dtim_period '1'
	option beacon_int '100'
	option rxchainps '0'
	option rxchainps_qt '10'
	option rxchainps_pps '10'
	option rifs '0'
	option rifs_advert '0'
	option maxassoc '32'
	option beamforming '1'
	option doth '1'
	option dfsc '1'

config wifi-iface
	option device 'wl0'
	option network 'lan'
	option mode 'ap'
	option ssid 'PANTERA-7858'
	option encryption 'psk2'
	option cipher 'auto'
	option key 'keykeykey'
	option gtk_rekey '3600'
	option macfilter '0'
	option wps_pbc '1'
	option wmf_bss_enable '1'
	option bss_max '32'
	option ifname 'wl0'

config wifi-device 'wl1'
	option type 'broadcom'
	option country 'EU/13'
	option band 'b'
	option bandwidth '20'
	option hwmode 'auto'
	option channel 'auto'
	option scantimer '15'
	option wmm '1'
	option wmm_noack '0'
	option wmm_apsd '1'
	option txpower '100'
	option rateset 'default'
	option frag '2346'
	option rts '2347'
	option dtim_period '1'
	option beacon_int '100'
	option rxchainps '0'
	option rxchainps_qt '10'
	option rxchainps_pps '10'
	option rifs '0'
	option rifs_advert '0'
	option maxassoc '32'
	option doth '0'

config wifi-iface
	option device 'wl1'
	option network 'lan'
	option mode 'ap'
	option ssid 'PANTERA-7858'
	option encryption 'psk2'
	option cipher 'auto'
	option key 'rootrootroot'
	option gtk_rekey '3600'
	option macfilter '0'
	option wps_pbc '1'
	option wmf_bss_enable '1'
	option bss_max '32'
	option ifname 'wl1'

config apsteering 'apsteering'
	option enabled '0'

$ sysrepocfg -X -d startup -f json -m 'router-wireless'
{
  "router-wireless:devices": {
    "device": [
      {
        "name": "wl0",
        "type": "broadcom",
        "country": "EU/13",
        "hwmode": "auto",
        "channel": "auto",
        "txpower": 100,
        "dtim_period": 1,
        "beacon_int": 100,
        "maxassoc": 32,
        "doth": 1,
        "interface": [
          {
            "name": "cfg043579",
            "network": "lan",
            "mode": "ap",
            "ssid": "PANTERA-7858",
            "encryption": "psk2",
            "key": "keykeykey",
            "ifname": "wl0",
            "macfilter": 1
          }
        ]
      },
      {
        "name": "wl1",
        "type": "broadcom",
        "country": "EU/13",
        "hwmode": "auto",
        "channel": "auto",
        "txpower": 100,
        "dtim_period": 1,
        "beacon_int": 100,
        "maxassoc": 32,
        "doth": 0,
        "interface": [
          {
            "name": "cfg063579",
            "network": "lan",
            "mode": "ap",
            "ssid": "PANTERA-7858",
            "encryption": "psk2",
            "key": "rootrootroot",
            "ifname": "wl1",
            "macfilter": 1
          }
        ]
      }
    ]
  }
}
```

Provided output suggests that the plugin has correctly initialized Sysrepo `startup` datastore with appropriate data transformations. It can be seen that all containers have been populated.

Changes to the `running` datastore can be done manually by invoking the following command:

```
$ sysrepocfg -E -d running -f json -m 'router-wireless'
[...interactive...]
{
  "router-wireless:devices": {
    "device": [
      {
        "name": "wl0",
		[...]
      },
      {
        "name": "wl1",
		[...]
        "interface": [
          {
            "name": "cfg063579",
            "network": "lan",
            "mode": "ap",
            "ssid": "PANTERA-7858",
            "encryption": "psk2",
            "key": "rootrootroot",
            "ifname": "wl1",
            "macfilter": 1 // => 0
          }
        ]
      }
    ]
  }
}
```

Alternatively, instead of changing the entire module data with `-m 'router-wireless'` we can change data on a certain XPath with e.g. `-x '/router-wireless:devices'`.

After executing previous command, the following should appear at plugin binary standard output:

```
[INF]: Processing "router-wireless" "change" event with ID 1 priority 0 (remaining 1 subscribers).
[INF]: plugin: module_name: router-wireless, xpath: /router-wireless:*//*, event: 1, request_id: 1
[DBG]: plugin: uci_path: wireless.cfg043579.macfilter; prev_val: 0; node_val: 1; operation: 1
[DBG]: plugin: uci_path: wireless.cfg063579.macfilter; prev_val: 0; node_val: 1; operation: 1
[INF]: Successful processing of "change" event with ID 1 priority 0 (remaining 0 subscribers).
[INF]: Processing "router-wireless" "done" event with ID 1 priority 0 (remaining 1 subscribers).
[INF]: plugin: module_name: router-wireless, xpath: /router-wireless:*//*, event: 2, request_id: 1
[...]
[INF]: Successful processing of "done" event with ID 1 priority 0 (remaining 0 subscribers).
```

The datastore change operation should be reflected in the `/etc/config/wireless` UCI file:

```
$ cat ${SYSREPO_DIR}/etc/config/wireless | grep accept_ra
        option macfilter 'enabled'
        option macfilter 'disabled'
```