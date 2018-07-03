/*
 * ipmonitor.c		"ip monitor".
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Alexey Kuznetsov, <kuznet@ms2.inr.ac.ru>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>

#include "utils.h"
#include "ip_common.h"

static void usage(void) __attribute__((noreturn));
static int prefix_banner;
int listen_all_nsid;

static void usage(void)
{
	fprintf(stderr, "Usage: ip monitor [ all | LISTofOBJECTS ] [ FILE ] [ label ] [all-nsid] [dev DEVICE]\n");
	fprintf(stderr, "LISTofOBJECTS := link | address | route | mroute | prefix |\n");
	fprintf(stderr, "                 neigh | netconf | rule | nsid\n");
	fprintf(stderr, "FILE := file FILENAME\n");
	exit(-1);
}

static void print_headers(FILE *fp, char *label, struct rtnl_ctrl_data *ctrl)
{
	if (timestamp)
		print_timestamp(fp);

	if (listen_all_nsid) {
		if (ctrl == NULL || ctrl->nsid < 0)
			fprintf(fp, "[nsid current]");
		else
			fprintf(fp, "[nsid %d]", ctrl->nsid);
	}

	if (prefix_banner)
		fprintf(fp, "%s", label);
}

static int print_routenotify(struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;
	struct rtmsg *r = NLMSG_DATA(n);
	int len = n->nlmsg_len;
	struct rtattr *rta_tb[RTA_MAX+1];
	int family, color;

	SPRINT_BUF(b1);

	if (n->nlmsg_type != RTM_NOTIFYROUTE)
		return 0;

	len -= NLMSG_LENGTH(sizeof(*r));
	if (len < 0) {
		fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
		return -1;
	}

	parse_rtattr(rta_tb, RTA_MAX, RTM_RTA(r), len);

	color = COLOR_NONE;
	if (rta_tb[RTA_DST]) {
		family = get_real_family(r->rtm_type, r->rtm_family);
		color = ifa_family_color(family);

		format_host_rta_r(family, rta_tb[RTA_DST], b1, sizeof(b1));

		print_color_string(PRINT_ANY, color, "dst", "%s ", b1);
	}

	if (rta_tb[RTA_SRC]) {
		family = get_real_family(r->rtm_type, r->rtm_family);
		color = ifa_family_color(family);

		format_host_rta_r(family, rta_tb[RTA_SRC], b1, sizeof(b1));

		print_color_string(PRINT_ANY, color, "src", "%s ", b1);
	}
#if 0

	ifa_flags = get_ifa_flags(ifa, rta_tb[IFA_FLAGS]);

	if (!rta_tb[IFA_LOCAL])
		rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];
	if (!rta_tb[IFA_ADDRESS])
		rta_tb[IFA_ADDRESS] = rta_tb[IFA_LOCAL];

	if (filter.ifindex && filter.ifindex != ifa->ifa_index)
		return 0;
	if ((filter.scope^ifa->ifa_scope)&filter.scopemask)
		return 0;
	if ((filter.flags ^ ifa_flags) & filter.flagmask)
		return 0;

	if (filter.family && filter.family != ifa->ifa_family)
		return 0;

	if (ifa_label_match_rta(ifa->ifa_index, rta_tb[IFA_LABEL]))
		return 0;

	if (inet_addr_match_rta(&filter.pfx, rta_tb[IFA_LOCAL]))
		return 0;

	if (filter.flushb) {
		struct nlmsghdr *fn;

		if (NLMSG_ALIGN(filter.flushp) + n->nlmsg_len > filter.flushe) {
			if (flush_update())
				return -1;
		}
		fn = (struct nlmsghdr *)(filter.flushb + NLMSG_ALIGN(filter.flushp));
		memcpy(fn, n, n->nlmsg_len);
		fn->nlmsg_type = RTM_DELADDR;
		fn->nlmsg_flags = NLM_F_REQUEST;
		fn->nlmsg_seq = ++rth.seq;
		filter.flushp = (((char *)fn) + n->nlmsg_len) - filter.flushb;
		filter.flushed++;
		if (show_stats < 2)
			return 0;
	}

	if (n->nlmsg_type == RTM_DELADDR)
		print_bool(PRINT_ANY, "deleted", "Deleted ", true);

	if (!brief) {
		const char *name;

		if (filter.oneline || filter.flushb) {
			const char *dev = ll_index_to_name(ifa->ifa_index);

			if (is_json_context()) {
				print_int(PRINT_JSON,
					  "index", NULL, ifa->ifa_index);
				print_string(PRINT_JSON, "dev", NULL, dev);
			} else {
				fprintf(fp, "%u: %s", ifa->ifa_index, dev);
			}
		}

		name = family_name(ifa->ifa_family);
		if (*name != '?') {
			print_string(PRINT_ANY, "family", "    %s ", name);
		} else {
			print_int(PRINT_ANY, "family_index", "    family %d ",
				  ifa->ifa_family);
		}
	}

	if (rta_tb[IFA_LOCAL]) {
		print_color_string(PRINT_ANY,
				   ifa_family_color(ifa->ifa_family),
				   "local", "%s",
				   format_host_rta(ifa->ifa_family,
						   rta_tb[IFA_LOCAL]));
		if (rta_tb[IFA_ADDRESS] &&
		    memcmp(RTA_DATA(rta_tb[IFA_ADDRESS]),
			   RTA_DATA(rta_tb[IFA_LOCAL]),
			   ifa->ifa_family == AF_INET ? 4 : 16)) {
			print_string(PRINT_FP, NULL, " %s ", "peer");
			print_color_string(PRINT_ANY,
					   ifa_family_color(ifa->ifa_family),
					   "address",
					   "%s",
					   format_host_rta(ifa->ifa_family,
							   rta_tb[IFA_ADDRESS]));
		}
		print_int(PRINT_ANY, "prefixlen", "/%d ", ifa->ifa_prefixlen);
	}

	if (brief)
		goto brief_exit;

	if (rta_tb[IFA_BROADCAST]) {
		print_string(PRINT_FP, NULL, "%s ", "brd");
		print_color_string(PRINT_ANY,
				   ifa_family_color(ifa->ifa_family),
				   "broadcast",
				   "%s ",
				   format_host_rta(ifa->ifa_family,
						   rta_tb[IFA_BROADCAST]));
	}

	if (rta_tb[IFA_ANYCAST]) {
		print_string(PRINT_FP, NULL, "%s ", "any");
		print_color_string(PRINT_ANY,
				   ifa_family_color(ifa->ifa_family),
				   "anycast",
				   "%s ",
				   format_host_rta(ifa->ifa_family,
						   rta_tb[IFA_ANYCAST]));
	}

	print_string(PRINT_ANY,
		     "scope",
		     "scope %s ",
		     rtnl_rtscope_n2a(ifa->ifa_scope, b1, sizeof(b1)));

	print_ifa_flags(fp, ifa, ifa_flags);

	if (rta_tb[IFA_LABEL])
		print_string(PRINT_ANY,
			     "label",
			     "%s",
			     rta_getattr_str(rta_tb[IFA_LABEL]));

	if (rta_tb[IFA_CACHEINFO]) {
		struct ifa_cacheinfo *ci = RTA_DATA(rta_tb[IFA_CACHEINFO]);

		print_string(PRINT_FP, NULL, "%s", _SL_);
		print_string(PRINT_FP, NULL, "       valid_lft ", NULL);

		if (ci->ifa_valid == INFINITY_LIFE_TIME) {
			print_uint(PRINT_JSON,
				   "valid_life_time",
				   NULL, INFINITY_LIFE_TIME);
			print_string(PRINT_FP, NULL, "%s", "forever");
		} else {
			print_uint(PRINT_ANY,
				   "valid_life_time", "%usec", ci->ifa_valid);
		}

		print_string(PRINT_FP, NULL, " preferred_lft ", NULL);
		if (ci->ifa_prefered == INFINITY_LIFE_TIME) {
			print_uint(PRINT_JSON,
				   "preferred_life_time",
				   NULL, INFINITY_LIFE_TIME);
			print_string(PRINT_FP, NULL, "%s", "forever");
		} else {
			if (ifa_flags & IFA_F_DEPRECATED)
				print_int(PRINT_ANY,
					  "preferred_life_time",
					  "%dsec",
					  ci->ifa_prefered);
			else
				print_uint(PRINT_ANY,
					   "preferred_life_time",
					   "%usec",
					   ci->ifa_prefered);
		}
	}
#endif
	print_string(PRINT_FP, NULL, "%s", "\n");
brief_exit:
	fflush(fp);
	return 0;
}

static int accept_msg(struct rtnl_ctrl_data *ctrl,
		      struct nlmsghdr *n, void *arg)
{
	FILE *fp = (FILE *)arg;

	switch (n->nlmsg_type) {
	case RTM_NEWROUTE:
	case RTM_DELROUTE: {
		struct rtmsg *r = NLMSG_DATA(n);
		int len = n->nlmsg_len - NLMSG_LENGTH(sizeof(*r));

		if (len < 0) {
			fprintf(stderr, "BUG: wrong nlmsg len %d\n", len);
			return -1;
		}

		if (r->rtm_flags & RTM_F_CLONED)
			return 0;

		if (r->rtm_family == RTNL_FAMILY_IPMR ||
		    r->rtm_family == RTNL_FAMILY_IP6MR) {
			print_headers(fp, "[MROUTE]", ctrl);
			print_mroute(n, arg);
			return 0;
		} else {
			print_headers(fp, "[ROUTE]", ctrl);
			print_route(n, arg);
			return 0;
		}
	}

	case RTM_NEWLINK:
	case RTM_DELLINK:
		ll_remember_index(n, NULL);
		print_headers(fp, "[LINK]", ctrl);
		print_linkinfo(n, arg);
		return 0;

	case RTM_NEWADDR:
	case RTM_DELADDR:
		print_headers(fp, "[ADDR]", ctrl);
		print_addrinfo(n, arg);
		return 0;

	case RTM_NEWADDRLABEL:
	case RTM_DELADDRLABEL:
		print_headers(fp, "[ADDRLABEL]", ctrl);
		print_addrlabel(n, arg);
		return 0;

	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
	case RTM_GETNEIGH:
		if (preferred_family) {
			struct ndmsg *r = NLMSG_DATA(n);

			if (r->ndm_family != preferred_family)
				return 0;
		}

		print_headers(fp, "[NEIGH]", ctrl);
		print_neigh(n, arg);
		return 0;

	case RTM_NEWPREFIX:
		print_headers(fp, "[PREFIX]", ctrl);
		print_prefix(n, arg);
		return 0;

	case RTM_NEWRULE:
	case RTM_DELRULE:
		print_headers(fp, "[RULE]", ctrl);
		print_rule(n, arg);
		return 0;

	case NLMSG_TSTAMP:
		print_nlmsg_timestamp(fp, n);
		return 0;

	case RTM_NEWNETCONF:
	case RTM_DELNETCONF:
		print_headers(fp, "[NETCONF]", ctrl);
		print_netconf(ctrl, n, arg);
		return 0;

	case RTM_DELNSID:
	case RTM_NEWNSID:
		print_headers(fp, "[NSID]", ctrl);
		print_nsid(n, arg);
		return 0;

	case RTM_NOTIFYROUTE:
		print_headers(fp, "[NOTIFYROUTE]", ctrl);
		print_routenotify(n, arg);
		return 0;

	case NLMSG_ERROR:
	case NLMSG_NOOP:
	case NLMSG_DONE:
		break;	/* ignore */

	default:
		fprintf(stderr,
			"Unknown message: type=0x%08x(%d) flags=0x%08x(%d) len=0x%08x(%d)\n",
			n->nlmsg_type, n->nlmsg_type,
			n->nlmsg_flags, n->nlmsg_flags, n->nlmsg_len,
			n->nlmsg_len);
	}

	return 0;
}

int do_ipmonitor(int argc, char **argv)
{
	char *file = NULL;
	unsigned int groups = 0;
	int llink = 0;
	int laddr = 0;
	int lroute = 0;
	int lmroute = 0;
	int lprefix = 0;
	int lneigh = 0;
	int lnetconf = 0;
	int lrule = 0;
	int lnsid = 0;
	int ifindex = 0;
	int lrtnotify = 0;

	groups |= nl_mgrp(RTNLGRP_LINK);
	groups |= nl_mgrp(RTNLGRP_IPV4_IFADDR);
	groups |= nl_mgrp(RTNLGRP_IPV6_IFADDR);
	groups |= nl_mgrp(RTNLGRP_IPV4_ROUTE);
	groups |= nl_mgrp(RTNLGRP_IPV6_ROUTE);
	groups |= nl_mgrp(RTNLGRP_MPLS_ROUTE);
	groups |= nl_mgrp(RTNLGRP_IPV4_MROUTE);
	groups |= nl_mgrp(RTNLGRP_IPV6_MROUTE);
	groups |= nl_mgrp(RTNLGRP_IPV6_PREFIX);
	groups |= nl_mgrp(RTNLGRP_NEIGH);
	groups |= nl_mgrp(RTNLGRP_IPV4_NETCONF);
	groups |= nl_mgrp(RTNLGRP_IPV6_NETCONF);
	groups |= nl_mgrp(RTNLGRP_IPV4_RULE);
	groups |= nl_mgrp(RTNLGRP_IPV6_RULE);
	groups |= nl_mgrp(RTNLGRP_NSID);
	groups |= nl_mgrp(RTNLGRP_MPLS_NETCONF);
	groups |= nl_mgrp(RTNLGRP_ROUTE_NOTIFY);

	rtnl_close(&rth);

	while (argc > 0) {
		if (matches(*argv, "file") == 0) {
			NEXT_ARG();
			file = *argv;
		} else if (matches(*argv, "label") == 0) {
			prefix_banner = 1;
		} else if (matches(*argv, "link") == 0) {
			llink = 1;
			groups = 0;
		} else if (matches(*argv, "address") == 0) {
			laddr = 1;
			groups = 0;
		} else if (matches(*argv, "route") == 0) {
			lroute = 1;
			groups = 0;
		} else if (matches(*argv, "mroute") == 0) {
			lmroute = 1;
			groups = 0;
		} else if (matches(*argv, "prefix") == 0) {
			lprefix = 1;
			groups = 0;
		} else if (matches(*argv, "neigh") == 0) {
			lneigh = 1;
			groups = 0;
		} else if (matches(*argv, "netconf") == 0) {
			lnetconf = 1;
			groups = 0;
		} else if (matches(*argv, "rule") == 0) {
			lrule = 1;
			groups = 0;
		} else if (matches(*argv, "nsid") == 0) {
			lnsid = 1;
			groups = 0;
		} else if (matches(*argv, "routenotify") == 0) {
			lrtnotify = 1;
			groups = 0;
		} else if (strcmp(*argv, "all") == 0) {
			prefix_banner = 1;
		} else if (matches(*argv, "all-nsid") == 0) {
			listen_all_nsid = 1;
		} else if (matches(*argv, "help") == 0) {
			usage();
		} else if (strcmp(*argv, "dev") == 0) {
			NEXT_ARG();

			ifindex = ll_name_to_index(*argv);
			if (!ifindex)
				invarg("Device does not exist\n", *argv);
		} else {
			fprintf(stderr, "Argument \"%s\" is unknown, try \"ip monitor help\".\n", *argv);
			exit(-1);
		}
		argc--;	argv++;
	}

	ipaddr_reset_filter(1, ifindex);
	iproute_reset_filter(ifindex);
	ipmroute_reset_filter(ifindex);
	ipneigh_reset_filter(ifindex);
	ipnetconf_reset_filter(ifindex);

	if (llink)
		groups |= nl_mgrp(RTNLGRP_LINK);
	if (laddr) {
		if (!preferred_family || preferred_family == AF_INET)
			groups |= nl_mgrp(RTNLGRP_IPV4_IFADDR);
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_IFADDR);
	}
	if (lroute) {
		if (!preferred_family || preferred_family == AF_INET)
			groups |= nl_mgrp(RTNLGRP_IPV4_ROUTE);
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_ROUTE);
		if (!preferred_family || preferred_family == AF_MPLS)
			groups |= nl_mgrp(RTNLGRP_MPLS_ROUTE);
	}
	if (lmroute) {
		if (!preferred_family || preferred_family == AF_INET)
			groups |= nl_mgrp(RTNLGRP_IPV4_MROUTE);
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_MROUTE);
	}
	if (lprefix) {
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_PREFIX);
	}
	if (lneigh) {
		groups |= nl_mgrp(RTNLGRP_NEIGH);
	}
	if (lnetconf) {
		if (!preferred_family || preferred_family == AF_INET)
			groups |= nl_mgrp(RTNLGRP_IPV4_NETCONF);
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_NETCONF);
		if (!preferred_family || preferred_family == AF_MPLS)
			groups |= nl_mgrp(RTNLGRP_MPLS_NETCONF);
	}
	if (lrule) {
		if (!preferred_family || preferred_family == AF_INET)
			groups |= nl_mgrp(RTNLGRP_IPV4_RULE);
		if (!preferred_family || preferred_family == AF_INET6)
			groups |= nl_mgrp(RTNLGRP_IPV6_RULE);
	}
	if (lnsid) {
		groups |= nl_mgrp(RTNLGRP_NSID);
	}
	if (lrtnotify) {
		groups |= nl_mgrp(RTNLGRP_ROUTE_NOTIFY);
	}
	if (file) {
		FILE *fp;
		int err;

		fp = fopen(file, "r");
		if (fp == NULL) {
			perror("Cannot fopen");
			exit(-1);
		}
		err = rtnl_from_file(fp, accept_msg, stdout);
		fclose(fp);
		return err;
	}

	if (rtnl_open(&rth, groups) < 0)
		exit(1);
	if (listen_all_nsid && rtnl_listen_all_nsid(&rth) < 0)
		exit(1);

	ll_init_map(&rth);
	netns_nsid_socket_init();
	netns_map_init();

	if (rtnl_listen(&rth, accept_msg, stdout) < 0)
		exit(2);

	return 0;
}
