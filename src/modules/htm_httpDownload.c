/* htm_httpDownload.c
 * Copyright (C) 2007-2015 Tillmann Werner <tillmann.werner@gmx.de>
 *
 * This file is free software; as a special exception the author gives
 * unlimited permission to copy and/or distribute it, with or without
 * modifications, as long as this notice is preserved.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY, to the extent permitted by law; without even
 * the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE.
 *
 * Description:
 *   This honeytrap module parses an attack string for HTTP URLs.
 *   Destinations are checked before each request and redirects are
 *   validated before they are followed.
 */

#define _GNU_SOURCE 1

#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>

#include <honeytrap.h>
#include <logging.h>
#include <md5.h>
#include <plughook.h>
#include <readconf.h>
#include <signals.h>
#include <sock.h>
#include <tcpip.h>
#include <util.h>

#include "htm_httpDownload.h"
#include "download_policy.h"

#define MAX_HTTP_REDIRECTS 5

const char module_name[]="httpDownload";
const char module_version[]="1.1.1";

static const char *config_keywords[] = {
	"http_program",
	"http_options",
};

struct http_response {
	u_char *data;
	size_t size;
	char *location;
};

static int curl_initialized;
static int legacy_options_warned;

void plugin_config(void) {
	plugin_register_confopts();
	if (process_conftree(config_tree, config_tree, plugin_process_confopts, NULL) == NULL) {
		fprintf(stderr, "  Error - Unable to process configuration tree for plugin %s.\n", module_name);
		exit(EXIT_FAILURE);
	}
	return;
}

void plugin_init(void) {
	CURLcode result = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (result != CURLE_OK) {
		logmsg(LOG_ERR, 1, "HTTP download error - Cannot initialize libcurl: %s.\n",
			curl_easy_strerror(result));
		return;
	}
	curl_initialized = 1;
	plugin_register_hooks();
	return;
}

void plugin_unload(void) {
	unhook(PPRIO_ANALYZE, module_name, "cmd_parse_for_http_url");
	if (curl_initialized) curl_global_cleanup();
}

void plugin_register_hooks(void) {
	logmsg(LOG_DEBUG, 1, "    Plugin %s: Registering hooks.\n", module_name);
	add_attack_func_to_list(PPRIO_ANALYZE, module_name, "cmd_parse_for_http_url",
		(void *)cmd_parse_for_http_url);
	return;
}

void plugin_register_confopts(void) {
	int i;
	char full_name[264], *confopt;

	memset(full_name, 0, sizeof(full_name));
	strncpy(full_name, "plugin-", 7);
	strncpy(&full_name[7], module_name,
		256 < strlen(module_name) ? 256 : strlen(module_name));
	if (add_keyword(&config_keywords_tree, full_name, NULL, 0) == NULL) {
		fprintf(stderr, "  Error - Unable to add configuration keyword to tree.\n");
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < sizeof(config_keywords) / sizeof(char *); i++) {
		confopt = malloc(strlen(full_name) + strlen(config_keywords[i]) + 2);
		if (!confopt) {
			fprintf(stderr, "  Error - Unable to allocate memory: %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		sprintf(confopt, "%s.%s", full_name, config_keywords[i]);
		if (add_keyword(&config_keywords_tree, confopt, NULL, 0) == NULL) {
			fprintf(stderr, "  Error - Unable to add configuration keyword to tree.\n");
			free(confopt);
			exit(EXIT_FAILURE);
		}
		free(confopt);
	}
	return;
}

conf_node *plugin_process_confopts(conf_node *tree, conf_node *node, void *opt_data) {
	char *value = NULL;
	conf_node *confopt = NULL;

	if ((confopt = check_keyword(tree, node->keyword)) == NULL) return(NULL);
	while (node->val) {
		value = malloc(node->val->size + 1);
		if (!value) {
			perror("  Error - Unable to allocate memory");
			exit(EXIT_FAILURE);
		}
		memset(value, 0, node->val->size + 1);
		memcpy(value, node->val->data, node->val->size);
		node->val = node->val->next;

		if (OPT_IS("http_program") || OPT_IS("http_options")) {
			if (!legacy_options_warned) {
				logmsg(LOG_WARN, 1,
					"HTTP download - http_program and http_options are deprecated; using built-in libcurl.\n");
				legacy_options_warned = 1;
			}
			free(value);
		} else {
			fprintf(stderr, "  Error - Invalid configuration option for plugin %s: %s\n",
				module_name, node->keyword);
			free(value);
			exit(EXIT_FAILURE);
		}
	}
	return(node);
}

static size_t receive_body(void *data, size_t size, size_t count, void *context) {
	struct http_response *response = context;
	size_t bytes, new_size;
	u_char *grown;

	if (size && count > SIZE_MAX / size) return 0;
	bytes = size * count;
	if (bytes > SIZE_MAX - response->size) return 0;
	new_size = response->size + bytes;
	grown = realloc(response->data, new_size ? new_size : 1);
	if (!grown) return 0;
	response->data = grown;
	if (bytes) memcpy(response->data + response->size, data, bytes);
	response->size = new_size;
	return bytes;
}

static size_t receive_header(char *data, size_t size, size_t count, void *context) {
	struct http_response *response = context;
	size_t bytes, value_size;
	char *value, *end, *location;

	if (size && count > SIZE_MAX / size) return 0;
	bytes = size * count;
	if (bytes < sizeof("Location:") - 1 ||
		strncasecmp(data, "Location:", sizeof("Location:") - 1) != 0) {
		return bytes;
	}

	value = data + sizeof("Location:") - 1;
	end = data + bytes;
	while (value < end && (*value == ' ' || *value == '\t')) value++;
	while (end > value && (end[-1] == '\r' || end[-1] == '\n')) end--;
	value_size = (size_t)(end - value);
	if (!value_size) return bytes;

	location = strndup(value, value_size);
	if (!location) return 0;
	free(response->location);
	response->location = location;
	return bytes;
}

static void clear_response(struct http_response *response) {
	free(response->data);
	free(response->location);
	response->data = NULL;
	response->size = 0;
	response->location = NULL;
}

static int resolve_http_target(CURLU *url, struct curl_slist **pinned_address) {
	char *scheme = NULL, *host = NULL, *port = NULL;
	struct addrinfo hints, *addresses = NULL, *address;
	struct in_addr ipv4_literal;
	struct in6_addr ipv6_literal;
	char numeric_host[NI_MAXHOST], *entry = NULL;
	int result = -1, numeric_literal;

	if (curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) != CURLUE_OK ||
		strcasecmp(scheme, "http") != 0 ||
		curl_url_get(url, CURLUPART_HOST, &host, 0) != CURLUE_OK ||
		curl_url_get(url, CURLUPART_PORT, &port, CURLU_DEFAULT_PORT) != CURLUE_OK) {
		goto done;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(host, port, &hints, &addresses) != 0) goto done;
	result = 0;

	numeric_literal = inet_pton(AF_INET, host, &ipv4_literal) == 1 ||
		inet_pton(AF_INET6, host, &ipv6_literal) == 1;
	for (address = addresses; address; address = address->ai_next) {
		if (!download_policy_address_allowed(address->ai_addr)) continue;
		if (numeric_literal) {
			result = 1;
			break;
		}
		if (getnameinfo(address->ai_addr, address->ai_addrlen, numeric_host,
			sizeof(numeric_host), NULL, 0, NI_NUMERICHOST) != 0) {
			continue;
		}
		if (address->ai_family == AF_INET6) {
			if (asprintf(&entry, "%s:%s:[%s]", host, port, numeric_host) < 0) entry = NULL;
		} else {
			if (asprintf(&entry, "%s:%s:%s", host, port, numeric_host) < 0) entry = NULL;
		}
		if (!entry) goto done;
		*pinned_address = curl_slist_append(*pinned_address, entry);
		free(entry);
		entry = NULL;
		if (!*pinned_address) goto done;
		result = 1;
		break;
	}

done:
	free(entry);
	if (addresses) freeaddrinfo(addresses);
	curl_free(scheme);
	curl_free(host);
	curl_free(port);
	return result;
}

static int download_http_url(const char *url, struct http_response *response,
	char **downloaded_url) {
	CURL *curl = NULL;
	CURLU *url_handle = NULL;
	struct curl_slist *pinned_address = NULL;
	char *current_url = NULL, *next_url = NULL;
	long status;
	int redirects, target_allowed;
	CURLcode result = CURLE_OK;
	CURLUcode url_result;

	curl = curl_easy_init();
	url_handle = curl_url();
	current_url = strdup(url);
	if (!curl || !url_handle || !current_url) goto error;
	if (curl_url_set(url_handle, CURLUPART_URL, current_url, 0) != CURLUE_OK) goto error;

	for (redirects = 0; ; redirects++) {
		clear_response(response);
		target_allowed = resolve_http_target(url_handle, &pinned_address);
		if (target_allowed != 1) {
			if (target_allowed == 0) {
				logmsg(LOG_WARN, 1,
					"HTTP download - Refusing a destination that is not public or allowlisted.\n");
			} else {
				logmsg(LOG_WARN, 1,
					"HTTP download - Unable to resolve or validate the destination.\n");
			}
			goto error;
		}
		if (curl_url_get(url_handle, CURLUPART_URL, &next_url,
			CURLU_NO_DEFAULT_PORT) != CURLUE_OK) goto error;

#define SET_CURL_OPTION(option, value) \
		do { \
			result = curl_easy_setopt(curl, option, value); \
			if (result != CURLE_OK) goto error; \
		} while (0)
		SET_CURL_OPTION(CURLOPT_URL, next_url);
		SET_CURL_OPTION(CURLOPT_PROTOCOLS, (long)CURLPROTO_HTTP);
		SET_CURL_OPTION(CURLOPT_REDIR_PROTOCOLS, (long)CURLPROTO_HTTP);
		SET_CURL_OPTION(CURLOPT_FOLLOWLOCATION, 0L);
		SET_CURL_OPTION(CURLOPT_PROXY, "");
		SET_CURL_OPTION(CURLOPT_NOPROXY, "*");
		SET_CURL_OPTION(CURLOPT_NOSIGNAL, 1L);
		SET_CURL_OPTION(CURLOPT_CONNECTTIMEOUT, 5L);
		SET_CURL_OPTION(CURLOPT_TIMEOUT, 30L);
		SET_CURL_OPTION(CURLOPT_HTTP_VERSION, (long)CURL_HTTP_VERSION_1_1);
		SET_CURL_OPTION(CURLOPT_WRITEFUNCTION, receive_body);
		SET_CURL_OPTION(CURLOPT_WRITEDATA, response);
		SET_CURL_OPTION(CURLOPT_HEADERFUNCTION, receive_header);
		SET_CURL_OPTION(CURLOPT_HEADERDATA, response);
		SET_CURL_OPTION(CURLOPT_RESOLVE, pinned_address);
#undef SET_CURL_OPTION

		result = curl_easy_perform(curl);
		if (curl_easy_setopt(curl, CURLOPT_RESOLVE, NULL) != CURLE_OK) goto error;
		curl_slist_free_all(pinned_address);
		pinned_address = NULL;
		curl_free(next_url);
		next_url = NULL;
		if (result != CURLE_OK) goto error;

		if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK) goto error;
		if (status < 300 || status >= 400 || !response->location) break;
		if (redirects >= MAX_HTTP_REDIRECTS) {
			logmsg(LOG_WARN, 1, "HTTP download - Redirect limit exceeded.\n");
			goto error;
		}

		url_result = curl_url_set(url_handle, CURLUPART_URL, response->location, 0);
		if (url_result != CURLUE_OK) {
			logmsg(LOG_WARN, 1, "HTTP download - Invalid redirect URL.\n");
			goto error;
		}
	}

	if (curl_url_get(url_handle, CURLUPART_URL, &next_url, CURLU_NO_DEFAULT_PORT) != CURLUE_OK)
		goto error;
	*downloaded_url = strdup(next_url);
	curl_free(next_url);
	next_url = NULL;
	if (!*downloaded_url) goto error;
	free(current_url);
	curl_url_cleanup(url_handle);
	curl_easy_cleanup(curl);
	return 0;

error:
	curl_free(next_url);
	free(current_url);
	if (url_handle) curl_url_cleanup(url_handle);
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_RESOLVE, NULL);
		curl_easy_cleanup(curl);
	}
	curl_slist_free_all(pinned_address);
	if (result != CURLE_OK) {
		logmsg(LOG_WARN, 1, "HTTP download - libcurl request failed: %s.\n",
			curl_easy_strerror(result));
	} else {
		logmsg(LOG_WARN, 1, "HTTP download - URL validation or redirect processing failed.\n");
	}
	clear_response(response);
	return -1;
}

int cmd_parse_for_http_url(Attack *attack) {
	int i, j;
	char *string_for_processing = NULL, *start = NULL, *end = NULL;
	char *downloaded_url = NULL, *filename;
	struct http_response response;

	memset(&response, 0, sizeof(response));
	if (!curl_initialized) {
		logmsg(LOG_ERR, 1, "HTTP download error - libcurl is not initialized.\n");
		return -1;
	}
	if (attack->a_conn.payload.size == 0 || !attack->a_conn.payload.data) {
		logmsg(LOG_DEBUG, 1, "HTTP download - No data received, nothing to download.\n");
		return 0;
	}

	string_for_processing = malloc(attack->a_conn.payload.size + 1);
	if (!string_for_processing) {
		logmsg(LOG_ERR, 1, "HTTP download error - Unable to allocate memory: %s.\n",
			strerror(errno));
		return -1;
	}
	memcpy(string_for_processing, attack->a_conn.payload.data, attack->a_conn.payload.size);
	string_for_processing[attack->a_conn.payload.size] = '\0';

	for (i = 0; i < attack->a_conn.payload.size; i++) {
		if (attack->a_conn.payload.size - i < 7 ||
			memcmp(string_for_processing + i, "http://", 7) != 0) continue;

		start = string_for_processing + i;
		for (end = start, j = 0; j < strlen(start) && end[0]; end = &start[j++]) {
			if (isspace((unsigned char)end[0]) || !isprint((unsigned char)end[0]))
				end[0] = '\0';
		}
		if (isspace((unsigned char)end[0])) end[0] = '\0';

		logmsg(LOG_DEBUG, 1, "HTTP download - URL found: '%s'.\n", start);
		attack->dl_tries++;
		if (download_http_url(start, &response, &downloaded_url) == 0 && response.size) {
			filename = strrchr(downloaded_url, '/');
			filename = filename ? filename + 1 : downloaded_url;
			add_download("http", TCP, 0, 0, NULL, NULL, filename, start,
				response.data, response.size, attack);
			logmsg(LOG_INFO, 1,
				"HTTP download - %s successfully downloaded and attached to attack record.\n",
				downloaded_url);
		} else {
			logmsg(LOG_INFO, 1, "HTTP download - No data received or request rejected.\n");
		}

		free(downloaded_url);
		downloaded_url = NULL;
		clear_response(&response);
		i += strlen(start);
	}

	if (!start) logmsg(LOG_DEBUG, 1, "HTTP download - No URLs found.\n");
	free(string_for_processing);
	return 0;
}
