#include <assert.h>
#include <arpa/inet.h>
#include <curl/curl.h>
#include <string.h>
#include <sys/socket.h>

#include "../download_policy.h"

static int ipv4_allowed(const char *value) {
	struct sockaddr_in address;

	memset(&address, 0, sizeof(address));
	address.sin_family = AF_INET;
	assert(inet_pton(AF_INET, value, &address.sin_addr) == 1);
	return download_policy_address_allowed((struct sockaddr *)&address);
}

static int ipv6_allowed(const char *value) {
	struct sockaddr_in6 address;

	memset(&address, 0, sizeof(address));
	address.sin6_family = AF_INET6;
	assert(inet_pton(AF_INET6, value, &address.sin6_addr) == 1);
	return download_policy_address_allowed((struct sockaddr *)&address);
}

static void test_relative_redirect(void) {
	CURLU *url;
	char *resolved = NULL;

	url = curl_url();
	assert(url != NULL);
	assert(curl_url_set(url, CURLUPART_URL, "http://example.test/first/path", 0) == CURLUE_OK);
	assert(curl_url_set(url, CURLUPART_URL, "../second", 0) == CURLUE_OK);
	assert(curl_url_get(url, CURLUPART_URL, &resolved, CURLU_NO_DEFAULT_PORT) == CURLUE_OK);
	assert(strcmp(resolved, "http://example.test/second") == 0);
	curl_free(resolved);
	curl_url_cleanup(url);
}

int main(void) {
	test_relative_redirect();
	assert(download_policy_set_allowlist("") == 0);
	assert(ipv4_allowed("8.8.8.8"));
	assert(!ipv4_allowed("10.1.2.3"));
	assert(!ipv4_allowed("100.64.0.1"));
	assert(!ipv4_allowed("127.0.0.1"));
	assert(!ipv4_allowed("169.254.1.1"));
	assert(!ipv4_allowed("192.0.2.1"));
	assert(!ipv4_allowed("224.0.0.1"));
	assert(ipv6_allowed("2606:4700:4700::1111"));
	assert(!ipv6_allowed("::1"));
	assert(!ipv6_allowed("fc00::1"));
	assert(!ipv6_allowed("fe80::1"));
	assert(!ipv6_allowed("2001:db8::1"));
	assert(!ipv6_allowed("ff02::1"));

	assert(download_policy_set_allowlist("10.20.0.0/16, fd00::/8, 127.0.0.1") == 0);
	assert(ipv4_allowed("10.20.1.2"));
	assert(!ipv4_allowed("10.21.1.2"));
	assert(ipv4_allowed("127.0.0.1"));
	assert(ipv6_allowed("fd00::2"));
	assert(!ipv6_allowed("fe80::1"));

	assert(download_policy_set_allowlist("10.0.0.0/33") == -1);
	assert(ipv4_allowed("10.20.1.2"));
	assert(download_policy_set_allowlist("10.0.0.0/8,,192.168.0.0/16") == -1);
	assert(ipv4_allowed("10.20.1.2"));

	assert(download_policy_set_allowlist("") == 0);
	assert(!ipv4_allowed("10.20.1.2"));
	return 0;
}
