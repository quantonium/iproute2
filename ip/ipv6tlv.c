/*
 * ipv6tlv.c	Control over parameters for IPv6 TLVs
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Authors:	Tom Herbert <tom@herbertland.com>
 */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <linux/genetlink.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#include "libgenl.h"
#include "utils.h"
#include "ip_common.h"
#include "json_print.h"
#include "linux/in6.h"

char *cmd;

static void usage(void)
{
	fprintf(stderr,
"Usage: ip %s set type TLV [ order ORDER ] [ user-perm CHECK ] [ admin-perm CHECK ] [ align-mult MULT ] [ align-off OFF ] [ min-len LEN ] [ max-len LEN ] [ align-mult MULT ] [ len-off OFF ] [ class CLASS ]\n"
"       ip %s get TLV\n"
"       ip %s set-order ORDER ORDER ...\n"
"       ip %s get-order\n"
"       ip %s list\n"
"       ip %s list-all\n"
"PERM := [ none | check | nocheck ]\n"
"CLASS := [ hbh | rtdst | dst | rtdstanddst ]\n", cmd, cmd, cmd, cmd, cmd, cmd);

	exit(-1);
}

/* netlink socket */
static struct rtnl_handle genl_rth = { .fd = -1 };
static int genl_family = -1;

#define TLV_REQUEST(_req, _bufsiz, _cmd, _flags)	\
	GENL_REQUEST(_req, _bufsiz, genl_family, 0,	\
		     IPV6_TLV_GENL_VERSION, _cmd, _flags)

#define TLV_RTA(g) ((struct rtattr *)(((char *)(g)) +	\
	NLMSG_ALIGN(sizeof(struct genlmsghdr))))

struct print_arg {
	FILE *file;
	bool showall;
};

static int print_tlv(struct nlmsghdr *n, void *arg)
{
	struct genlmsghdr *ghdr;
	struct rtattr *tb[IPV6_TLV_ATTR_MAX + 1];
	int len = n->nlmsg_len;
	struct print_arg *pa = arg;

	if (n->nlmsg_type != genl_family)
		return 0;

	len -= NLMSG_LENGTH(GENL_HDRLEN);
	if (len < 0)
		return -1;

	ghdr = NLMSG_DATA(n);

	parse_rtattr(tb, IPV6_TLV_ATTR_MAX, (void *) ghdr + GENL_HDRLEN, len);

	if (!pa->showall && (!tb[IPV6_TLV_ATTR_ORDER] ||
	    !rta_getattr_u8(tb[IPV6_TLV_ATTR_ORDER])))
		return 0;

	if (!tb[IPV6_TLV_ATTR_TYPE]) {
		fprintf(stderr, "No type\n");
		return -1;
	}

        open_json_object(NULL);
	print_uint(PRINT_ANY, "type", "%u ",
		     rta_getattr_u8(tb[IPV6_TLV_ATTR_TYPE]));

	if (tb[IPV6_TLV_ATTR_ORDER])
		print_uint(PRINT_ANY, "order", "order %u ",
		     rta_getattr_u8(tb[IPV6_TLV_ATTR_ORDER]));

	if (tb[IPV6_TLV_ATTR_ADMIN_PERM])
		print_uint(PRINT_ANY, "admin-perm", "admin-perm %u ",
		     rta_getattr_u8(tb[IPV6_TLV_ATTR_ADMIN_PERM]));

	if (tb[IPV6_TLV_ATTR_USER_PERM])
		print_uint(PRINT_ANY, "user-perm", "user-perm %u ",
		     rta_getattr_u8(tb[IPV6_TLV_ATTR_USER_PERM]));

	if (tb[IPV6_TLV_ATTR_CLASS])
		print_uint(PRINT_ANY, "class", "class %u ",
		     rta_getattr_u8(tb[IPV6_TLV_ATTR_CLASS]));

	if (tb[IPV6_TLV_ATTR_ALIGN_MULT])
		print_uint(PRINT_ANY, "align-mult", "align-mult %u ",
			     rta_getattr_u8(tb[IPV6_TLV_ATTR_ALIGN_MULT]));

	if (tb[IPV6_TLV_ATTR_ALIGN_OFF])
		print_uint(PRINT_ANY, "align-off", "align-off %u ",
		     rta_getattr_u8(tb[IPV6_TLV_ATTR_ALIGN_OFF]));

	if (tb[IPV6_TLV_ATTR_MIN_LEN])
		print_uint(PRINT_ANY, "min-len", "min-len %u ",
		     rta_getattr_u8(tb[IPV6_TLV_ATTR_MIN_LEN]));

	if (tb[IPV6_TLV_ATTR_MAX_LEN])
		print_uint(PRINT_ANY, "max-len", "max-len %u ",
		     rta_getattr_u8(tb[IPV6_TLV_ATTR_MAX_LEN]));

	if (tb[IPV6_TLV_ATTR_LEN_MULT])
		print_uint(PRINT_ANY, "len-mult", "len-mult %u ",
			     rta_getattr_u8(tb[IPV6_TLV_ATTR_LEN_MULT]));

	if (tb[IPV6_TLV_ATTR_LEN_OFF])
		print_uint(PRINT_ANY, "len-off", "len-off %u ",
		     rta_getattr_u8(tb[IPV6_TLV_ATTR_LEN_OFF]));

	print_nl();
	close_json_object();

	return 0;
}

#define NLMSG_BUF_SIZE 4096

static int do_list(int argc, char **argv, bool showall)
{
	struct print_arg pa;

	TLV_REQUEST(req, 1024, IPV6_TLV_CMD_GET, NLM_F_REQUEST | NLM_F_DUMP);

	if (argc > 0) {
		fprintf(stderr, "\"ip ip6tlv list\" does not take "
			"any arguments.\n");
		return -1;
	}

	if (rtnl_send(&genl_rth, (void *)&req, req.n.nlmsg_len) < 0) {
		perror("Cannot send dump request");
		exit(1);
	}

	new_json_obj(json);
	pa.file = stdout;
	pa.showall = showall;
	if (rtnl_dump_filter(&genl_rth, print_tlv, &pa) < 0) {
		fprintf(stderr, "Dump terminated\n");
		return 1;
	}
	delete_json_obj();
	fflush(stdout);

	return 0;
}

static int tlv_parse_opt(int argc, char **argv, struct nlmsghdr *n,
			 bool adding)
{
	__u8 tlvtype;
	__u8 order;
	__u8 align_mult;
	__u8 align_off;
	__u8 user_perm;
	__u8 admin_perm;
	__u8 class;
	__u8 min_len;
	__u8 max_len;
	__u8 len_mult;
	__u8 len_off;
	bool tlvtype_set = false;
	bool order_set = false;
	bool align_mult_set = false;
	bool align_off_set = false;
	bool user_perm_set = false;
	bool admin_perm_set = false;
	bool class_set = false;
	bool min_len_set = false;
	bool max_len_set = false;
	bool len_mult_set = false;
	bool len_off_set = false;

	while (argc > 0) {
		if (!matches(*argv, "type")) {
			NEXT_ARG();

			if (get_u8(&tlvtype, *argv, 0) || tlvtype < 2) {
                                invarg("invalid TLV type", *argv);
				return -1;
			}
			tlvtype_set = true;
		} else if (!matches(*argv, "order")) {
			NEXT_ARG();

			if (get_u8(&order, *argv, 0) || !order) {
                                invarg("invalid order", *argv);
				return -1;
			}
			order_set = true;
		} else if (!matches(*argv, "align-mult")) {
			NEXT_ARG();

			if (get_u8(&align_mult, *argv, 0) ||
			    align_mult < 1 || align_mult > 16) {
                                invarg("invalid align-mult", *argv);
				return -1;
			}
			align_mult_set = true;
		} else if (!matches(*argv, "align-off")) {
			NEXT_ARG();

			if (get_u8(&align_off, *argv, 0) || align_off > 15) {
                                invarg("invalid align-off", *argv);
				return -1;
			}
			align_off_set = true;
		} else if (!matches(*argv, "len-mult")) {
			NEXT_ARG();

			if (get_u8(&len_mult, *argv, 0) ||
			    len_mult < 1 || len_mult > 16) {
                                invarg("invalid len-mult", *argv);
				return -1;
			}
			len_mult_set = true;
		} else if (!matches(*argv, "len-off")) {
			NEXT_ARG();

			if (get_u8(&len_off, *argv, 0) || len_off > 15) {
                                invarg("invalid len-off", *argv);
				return -1;
			}
			len_off_set = true;
		} else if (!matches(*argv, "user-perm")) {
			NEXT_ARG();

			if (get_u8(&user_perm, *argv, 0) || user_perm > 3) {
                                invarg("invalid user_perm", *argv);
				return - 1;
			}
			user_perm_set = true;
		} else if (!matches(*argv, "admin-perm")) {
			NEXT_ARG();

			if (get_u8(&admin_perm, *argv, 0) || admin_perm > 3) {
                                invarg("invalid admin_perm", *argv);
				return - 1;
			}
			admin_perm_set = true;
		} else if (!matches(*argv, "class")) {
			NEXT_ARG();

			if (get_u8(&class, *argv, 0) || class > 7) {
                                invarg("invalid class", *argv);
				return - 1;
			}
			class_set = true;
		} else if (!matches(*argv, "min-len")) {
			NEXT_ARG();

			if (get_u8(&min_len, *argv, 0)) {
                                invarg("invalid min-len", *argv);
				return - 1;
			}
			min_len_set = true;
		} else if (!matches(*argv, "max-len")) {
			NEXT_ARG();

			if (get_u8(&max_len, *argv, 0)) {
                                invarg("invalid max-len", *argv);
				return - 1;
			}
			max_len_set = true;
		} else {
			usage();
			return -1;
		}
		argc--, argv++;
	}

	if (tlvtype_set)
		addattr8(n, 1024, IPV6_TLV_ATTR_TYPE, tlvtype);

	if (order_set)
		addattr8(n, 1024, IPV6_TLV_ATTR_ORDER, order);

	if (align_mult_set)
		addattr8(n, 1024, IPV6_TLV_ATTR_ALIGN_MULT, align_mult);

	if (align_off_set)
		addattr8(n, 1024, IPV6_TLV_ATTR_ALIGN_OFF, align_off);

	if (len_mult_set)
		addattr8(n, 1024, IPV6_TLV_ATTR_LEN_MULT, len_mult);

	if (len_off_set)
		addattr8(n, 1024, IPV6_TLV_ATTR_LEN_OFF, len_off);

	if (user_perm_set)
		addattr8(n, 1024, IPV6_TLV_ATTR_USER_PERM, user_perm);

	if (admin_perm_set)
		addattr8(n, 1024, IPV6_TLV_ATTR_ADMIN_PERM, admin_perm);

	if (class_set)
		addattr8(n, 1024, IPV6_TLV_ATTR_CLASS, class);

	if (min_len_set)
		addattr8(n, 1024, IPV6_TLV_ATTR_MIN_LEN, min_len);

	if (max_len_set)
		addattr8(n, 1024, IPV6_TLV_ATTR_MAX_LEN, max_len);

	return 0;
}

static int do_set(int argc, char **argv)
{
	TLV_REQUEST(req, 1024, IPV6_TLV_CMD_SET, NLM_F_REQUEST);

	tlv_parse_opt(argc, argv, &req.n, true);

	if (rtnl_talk(&genl_rth, &req.n, NULL) < 0)
		return -2;

	return 0;
}

static int do_unset(int argc, char **argv)
{
	TLV_REQUEST(req, 1024, IPV6_TLV_CMD_UNSET, NLM_F_REQUEST);

	tlv_parse_opt(argc, argv, &req.n, false);

	if (rtnl_talk(&genl_rth, &req.n, NULL) < 0)
		return -2;

	return 0;
}

static int do_get(int argc, char **argv)
{
	struct nlmsghdr *answer;
	struct print_arg pa;

	TLV_REQUEST(req, 1024, IPV6_TLV_CMD_GET,
		    NLM_F_ROOT | NLM_F_REQUEST);

	tlv_parse_opt(argc, argv, &req.n, false);

	if (rtnl_talk(&genl_rth, &req.n, &answer) < 0)
		return -2;

	pa.file = stdout;
	pa.showall = true;
	print_tlv(answer, &pa);

	return 0;
}

static int do_tlv(int argc, char **argv, char *genl_name)
{
	if (argc < 1)
		usage();

	if (matches(*argv, "help") == 0)
		usage();

	if (genl_init_handle(&genl_rth, genl_name, &genl_family))
		exit(1);

	if (matches(*argv, "get") == 0)
		return do_get(argc-1, argv+1);
	if (matches(*argv, "set") == 0)
		return do_set(argc-1, argv+1);
	if (matches(*argv, "unset") == 0)
		return do_unset(argc-1, argv+1);
	if (matches(*argv, "list") == 0)
		return do_list(argc-1, argv+1, false);
	if (matches(*argv, "list-all") == 0)
		return do_list(argc-1, argv+1, true);

	fprintf(stderr, "Command \"%s\" is unknown, try \"ip ip6tlv help\".\n",
		*argv);
	exit(-1);
}

int do_ip6tlv(int argc, char **argv)
{
	cmd = "ip6tlv";
	return do_tlv(argc, argv, IPV6_TLV_GENL_NAME);
}
