#include <inttypes.h>
#include <string.h>

#include <uci.h>

#include "transform_data.h"
#include "utils/memory.h"

char *transform_data_boolean_to_zero_one_transform(const char *value, void *private_data)
{
	if (strcmp(value, "true") == 0)
		return xstrdup("1");

	return xstrdup("0");
}

char *transform_data_zero_one_to_boolean_transform(const char *value, void *private_data)
{
	if (strcmp(value, "1") == 0)
		return xstrdup("true");

	return xstrdup("false");
}

char *transform_data_boolean_to_zero_one_negated_transform(const char *value, void *private_data)
{
	if (strcmp(value, "true") == 0)
		return xstrdup("0");

	return xstrdup("1");
}

char *transform_data_zero_one_to_boolean_negated_transform(const char *value, void *private_data)
{
	if (strcmp(value, "1") == 0)
		return xstrdup("false");

	return xstrdup("true");
}

// char *transform_data_freqband_to_band_transform(const char *value, void *private_data)
// {
// 	/*
// 	 * There is no direct linear mapping from frequency band (2.4 or 5 GHz)
// 	 * to UCI bands (a, b, g, n, a/c, ...). Heuristic?
// 	 * https://en.wikipedia.org/wiki/IEEE_802.11
// 	 */
// 	return NULL;
// }

// char *transform_data_band_to_freqband_transform(const char *value, void *private_data)
// {
// 	/* These are direct mappings. */
// 	if (strchr(value, 'a'))
// 		return xstrdup("5");

// 	if (strchr(value, 'b') || strchr(value, 'g'))
// 		return xstrdup("2.4");

// 	return NULL;
// }

// char *transform_data_encryption_ubus(const char *value)
// {
// 	if (strcmp(value, "Disabled") == 0)
// 		return xstrdup("none");

// 	if (strcmp(value, "WEP") == 0)
// 		return xstrdup("wep-open");

// 	if (strcmp(value, "WPA2 PSK") == 0)
// 		return xstrdup("psk2");

// 	if (strcmp(value, "WPA\\/WPA2 PSK") == 0)
// 		return xstrdup("psk-psk2");

// 	if (strcmp(value, "WPA2 802.1x") == 0)
// 		return xstrdup("wpa2");

// 	if (strcmp(value, "WPA\\/WPA2 802.1x") == 0)
// 		return xstrdup("wpa-wpa2");

// 	return NULL;
// }

char *transform_data_zero_one_to_boolean_ubus(const char *value)
{
	if (strcmp(value, "1") == 0)
		return xstrdup("true");

	return xstrdup("false");
}
