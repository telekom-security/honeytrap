#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "download_policy.h"

struct download_network {
	int family;
	unsigned int prefix;
	unsigned char address[16];
};

static struct download_network *allowlist;
static size_t allowlist_size;

static int prefix_matches(const unsigned char *address, const unsigned char *network,
	unsigned int prefix) {
	unsigned int bytes = prefix / 8;
	unsigned int bits = prefix % 8;
	unsigned char mask;

	if (bytes && memcmp(address, network, bytes) != 0) return 0;
	if (!bits) return 1;

	mask = (unsigned char)(0xffU << (8 - bits));
	return (address[bytes] & mask) == (network[bytes] & mask);
}

static char *trim(char *value) {
	char *end;

	while (isspace((unsigned char)*value)) value++;
	if (!*value) return value;

	end = value + strlen(value) - 1;
	while (end > value && isspace((unsigned char)*end)) *end-- = '\0';
	return value;
}

static int parse_network(char *value, struct download_network *network) {
	char *slash = strchr(value, '/');
	char *end;
	long prefix;
	unsigned int max_prefix;

	if (slash) {
		if (strchr(slash + 1, '/')) return -1;
		*slash++ = '\0';
		if (!*slash) return -1;
		for (end = slash; *end; end++) {
			if (!isdigit((unsigned char)*end)) return -1;
		}
		errno = 0;
		prefix = strtol(slash, &end, 10);
		if (errno || *end) return -1;
	} else {
		prefix = -1;
	}

	if (inet_pton(AF_INET, value, network->address) == 1) {
		network->family = AF_INET;
		max_prefix = 32;
	} else if (inet_pton(AF_INET6, value, network->address) == 1) {
		network->family = AF_INET6;
		max_prefix = 128;
	} else {
		return -1;
	}

	if (prefix == -1) prefix = max_prefix;
	if (prefix < 0 || (unsigned long)prefix > max_prefix) return -1;
	network->prefix = (unsigned int)prefix;
	return 0;
}

int download_policy_set_allowlist(const char *value) {
	struct download_network *new_allowlist = NULL;
	struct download_network network, *grown;
	size_t new_size = 0;
	char *copy, *cursor, *comma, *entry;

	if (!value) value = "";
	if (!(copy = strdup(value))) return -1;
	cursor = copy;

	while (cursor) {
		comma = strchr(cursor, ',');
		if (comma) *comma = '\0';
		entry = trim(cursor);
		if (!*entry) {
			if (comma || new_size) {
				free(new_allowlist);
				free(copy);
				return -1;
			}
			break;
		}

		memset(&network, 0, sizeof(network));
		if (parse_network(entry, &network) != 0) {
			free(new_allowlist);
			free(copy);
			return -1;
		}

		grown = realloc(new_allowlist, (new_size + 1) * sizeof(*new_allowlist));
		if (!grown) {
			free(new_allowlist);
			free(copy);
			return -1;
		}
		new_allowlist = grown;
		new_allowlist[new_size++] = network;
		cursor = comma ? comma + 1 : NULL;
		if (comma && !*cursor) {
			free(new_allowlist);
			free(copy);
			return -1;
		}
	}

	free(copy);
	free(allowlist);
	allowlist = new_allowlist;
	allowlist_size = new_size;
	return 0;
}

static int address_matches_allowlist(int family, const unsigned char *address) {
	size_t i;
	unsigned int address_size = family == AF_INET ? 4 : 16;

	for (i = 0; i < allowlist_size; i++) {
		if (allowlist[i].family == family &&
			allowlist[i].prefix <= address_size * 8 &&
			prefix_matches(address, allowlist[i].address, allowlist[i].prefix)) {
			return 1;
		}
	}
	return 0;
}

static int ipv4_is_public(const unsigned char *address) {
	static const struct {
		uint32_t network;
		unsigned int prefix;
	} special_ranges[] = {
		{0x00000000U, 8}, {0x0a000000U, 8}, {0x64400000U, 10},
		{0x7f000000U, 8}, {0xa9fe0000U, 16}, {0xac100000U, 12},
		{0xc0000000U, 24}, {0xc0000200U, 24}, {0xc01fc400U, 24},
		{0xc034c100U, 24}, {0xc0586300U, 24}, {0xc0a80000U, 16},
		{0xc0af3000U, 24}, {0xc6120000U, 15}, {0xc6336400U, 24},
		{0xcb007100U, 24}, {0xe0000000U, 4}, {0xf0000000U, 4}
	};
	uint32_t host_address;
	size_t i;

	memcpy(&host_address, address, sizeof(host_address));
	host_address = ntohl(host_address);
	for (i = 0; i < sizeof(special_ranges) / sizeof(special_ranges[0]); i++) {
		uint32_t mask = UINT32_MAX << (32 - special_ranges[i].prefix);
		if ((host_address & mask) == special_ranges[i].network) return 0;
	}
	return 1;
}

static int ipv6_is_public(const unsigned char *address) {
	static const unsigned char protocol_assignments[16] = {
		0x20, 0x01
	};
	static const unsigned char documentation[16] = {
		0x20, 0x01, 0x0d, 0xb8
	};
	static const unsigned char six_to_four[16] = {
		0x20, 0x02
	};

	if ((address[0] & 0xe0) != 0x20) return 0;
	if (prefix_matches(address, protocol_assignments, 23)) return 0;
	if (prefix_matches(address, documentation, 32)) return 0;
	if (prefix_matches(address, six_to_four, 16)) return 0;
	return 1;
}

int download_policy_address_allowed(const struct sockaddr *address) {
	const struct sockaddr_in *ipv4;
	const struct sockaddr_in6 *ipv6;
	const unsigned char *bytes;
	struct in_addr mapped;

	if (!address) return 0;
	if (address->sa_family == AF_INET) {
		ipv4 = (const struct sockaddr_in *)address;
		bytes = (const unsigned char *)&ipv4->sin_addr;
		return ipv4_is_public(bytes) ||
			address_matches_allowlist(AF_INET, bytes);
	}
	if (address->sa_family == AF_INET6) {
		ipv6 = (const struct sockaddr_in6 *)address;
		bytes = (const unsigned char *)&ipv6->sin6_addr;
		if (IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr)) {
			memcpy(&mapped, &bytes[12], sizeof(mapped));
			bytes = (const unsigned char *)&mapped;
			return ipv4_is_public(bytes) ||
				address_matches_allowlist(AF_INET, bytes);
		}
		return ipv6_is_public(bytes) ||
			address_matches_allowlist(AF_INET6, bytes);
	}
	return 0;
}
