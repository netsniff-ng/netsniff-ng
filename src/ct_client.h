/*
 * netsniff-ng - the packet sniffing beast
 * By Daniel Borkmann <daniel@netsniff-ng.org>
 * Copyright 2011 Daniel Borkmann.
 * Subject to the GPL.
 */

#ifndef CT_CLIENT_H
#define CT_CLIENT_H

extern int client_main(int port, int udp);

#define DEVNAME_CLIENT	"curvec"

#endif /* CT_CLIENT_H */
