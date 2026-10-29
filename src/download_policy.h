#ifndef HONEYTRAP_DOWNLOAD_POLICY_H
#define HONEYTRAP_DOWNLOAD_POLICY_H

#include <sys/socket.h>

int download_policy_set_allowlist(const char *value);
int download_policy_address_allowed(const struct sockaddr *address);

#endif
