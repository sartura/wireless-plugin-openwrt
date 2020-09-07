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

char *transform_data_zero_one_to_boolean_ubus(const char *value)
{
	if (strcmp(value, "1") == 0)
		return xstrdup("true");

	return xstrdup("false");
}

char *transform_data_state_to_integer_transform(const char *value, void *private_data)
{
	if (strcmp(value, "enabled") == 0)
		return xstrdup("1");

	return xstrdup("0");
}

char *transform_data_integer_to_state_transform(const char *value, void *private_data)
{
	if (strcmp(value, "1") == 0)
		return xstrdup("enabled");

	return xstrdup("disabled");
}