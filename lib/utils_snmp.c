#include <stdio.h>
#include <stdlib.h>
#include <limits.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include "common.h"
#include "utils_snmp.h"

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(x[0]))

/* opaque structure. Modify as needed */
struct mp_snmp_context {
	char *name;
	netsnmp_session session;
};

const char *mp_snmp_oid2str(oid *o, size_t len)
{
	static char str[2 + (MAX_OID_LEN * 4)];
	snprint_objid(str, sizeof(str) - 1, o, len);
	return str;
}

char *mp_snmp_value2str(netsnmp_variable_list *v, char *buf, size_t len)
{
	snprint_value(buf, len, v->name, v->name_length, v);
	return buf;
}

int mp_snmp_walk(netsnmp_session *ss, const char *base_oid, mp_snmp_walker func, void *arg, void *arg2)
{
	netsnmp_session *s;
	oid name[MAX_OID_LEN];
	size_t name_length;
	oid root[MAX_OID_LEN];
	size_t rootlen;
	oid end_oid[MAX_OID_LEN];
	size_t end_len = 0;
	int count, running, status = STAT_ERROR, exitval = 0;
	int result;

	s = snmp_open(ss);

	/*
	 * get the initial object and subtree
	 */
	rootlen = MAX_OID_LEN;
	if (snmp_parse_oid(base_oid, root, &rootlen) == NULL) {
		printf("UNKNOWN - Failed to add %s as root for snmp traversal: %s\n",
			   base_oid, snmp_api_errstring(snmp_errno));
		exit(STATE_UNKNOWN);
	}

	memmove(end_oid, root, rootlen*sizeof(oid));
	end_len = rootlen;
	end_oid[end_len-1]++;

	/*
	 * get first object to start walk
	 */
	memmove(name, root, rootlen * sizeof(oid));
	name_length = rootlen;

	running = 1;
	while (running) {
		netsnmp_variable_list *v;
		netsnmp_pdu	*pdu, *response = NULL;
		/*
		 * create PDU for GETNEXT request and add object name to request
		 */
		pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
		snmp_add_null_var(pdu, name, name_length);

		/* do the request */
		status = snmp_synch_response(s, pdu, &response);
		if (status != STAT_SUCCESS) {
			if (status == STAT_TIMEOUT) {
				printf("Timeout: No Response from %s\n", s->peername);
			}
			else {
				/* status == STAT_ERROR */
				printf("SNMP error when querying %s\n", s->peername);
			}
			running = 0;
			exitval = 1;
			break;
		}

		if (response->errstat != SNMP_ERR_NOERROR) {
			/* error in response, print it */
			fprintf(stderr, "Error in packet.\nReason: %s\n",
					snmp_errstring(response->errstat));
			if (response->errindex != 0) {
				fprintf(stderr, "Failed object: ");
				for (count = 1, v = response->variables;
					 v && count != response->errindex;
					 v = v->next_variable, count++)
					/*EMPTY*/;
				if (v)
					fprint_objid(stderr, v->name, v->name_length);
				fprintf(stderr, "\n");
			}
			exitval = 2;
			break;
		}

		/* check resulting variables */
		for (v = response->variables; v; v = v->next_variable) {
			if (snmp_oid_compare(end_oid, end_len, v->name, v->name_length) <= 0) {
				/* not part of this subtree */
				running = 0;
				break;
			}

			if ((v->type == SNMP_ENDOFMIBVIEW) ||
				(v->type == SNMP_NOSUCHOBJECT) ||
				(v->type == SNMP_NOSUCHINSTANCE))
			{
				running = 0;
				break;
			}

			/* found a proper variable, so handle it */
			result = func(v, arg, arg2);
			if (result == MP_SNMPWALK_STOP) {
				running = 0;
				break;
			}

			memmove((char *) name, (char *) v->name,
					v->name_length * sizeof(oid));
			name_length = v->name_length;
		}
		if (response) {
			snmp_free_pdu(response);
			response = NULL;
		}
	}
	snmp_close(s);

	return exitval;
}

/*
 * This function takes an snmp-subtree and grabs snmp variables
 * of that subtree that are marked in the 'mask' argument, using
 * 'key' as the final entry in the oid to reach the leaf node.
 *
 * if base_oid == .1.3.6.1, mask == 5 (101, binary) and key == 9,
 * we would add .1.3.6.1.0.9 and .1.3.6.1.2.9 to be fetched by the
 * next request using *pdu, because (mask & (1 << 0)) == 1, and
 * (mask & (1 << 2)) == 1
 * This is pretty useful, since almost all snmp info requires
 * multiple variables to be fetched from a single table in order
 * to make sense of the information. This is, for example, the
 * hrStorage table for the /home partition on my laptop. In
 * this case, I would have base_oid = .1.3.6.1.2.1.25.2.3.1,
 * key = 55 and mask = 28 (binary 111000) in order to fetch
 * the blocksize, total size and used size for the home
 * partition.
 * .1.3.6.1.2.1.25.2.3.1.1.55 = INTEGER: 55
 * .1.3.6.1.2.1.25.2.3.1.2.55 = OID: .1.3.6.1.2.1.25.2.1.4
 * .1.3.6.1.2.1.25.2.3.1.3.55 = STRING: /home
 * .1.3.6.1.2.1.25.2.3.1.4.55 = INTEGER: 4096 Bytes
 * .1.3.6.1.2.1.25.2.3.1.5.55 = INTEGER: 49678626
 * .1.3.6.1.2.1.25.2.3.1.6.55 = INTEGER: 45483461
 */
int mp_snmp_add_keyed_subtree(netsnmp_pdu *pdu, const char *base_oid, int mask, int key)
{
	oid o[MAX_OID_LEN];
	size_t len = MAX_OID_LEN;
	int i = 0;

	if (key < 0)
		return key;

	memset(o, 0, sizeof(o));
	snmp_parse_oid(base_oid, o, &len);
	len++;
	o[len++] = key;
	/* snmp trees are 1-indexed, so i starts at one */
	for (i = 1; mask; i++, mask >>= 1) {
		if (!(mask & 1))
			continue;

		o[len - 2] = i;
		snmp_add_null_var(pdu, o, len);
	}
	return 0;
}

void mp_snmp_parse_key(netsnmp_session *ss, char *arg, char *pass, u_char *key, size_t *len)
{
	if (*pass == '0' && pass[1] == 'x') {
		if (!snmp_hex_to_binary((u_char **)&pass, len, (size_t *)key, 0, pass)) {
			die(STATE_UNKNOWN, _("Bad key value for %s\n"), arg);
		}
	} else {
		if (generate_Ku(ss->securityAuthProto,
						ss->securityAuthProtoLen,
						(u_char *)pass, strlen(pass),
						key, len) != SNMPERR_SUCCESS)
		{
			die(STATE_UNKNOWN, _("Error generating Ku from authentication password '%s'\n"), pass);
		}
	}
}

void mp_snmp_init(const char *name, int flags)
{
	/* optionally disable logging from the net-snmp library */
	if (!(flags & MP_SNMP_ENABLE_LOGS)) {
		int i;
		for (i = 0; i < LOG_DEBUG; i++) {
			(void)netsnmp_register_loghandler(NETSNMP_LOGHANDLER_NONE, i);
		}
	}

	if (!(flags & MP_SNMP_LOAD_MIBS)) {
		/* disable mib parsing. It takes a lot of resources */
		netsnmp_set_mib_directory(":");
	}

	if (!(flags & MP_SNMP_LOAD_CONFIG)) {
		netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_DISABLE_CONFIG_LOAD, 1);
	}
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_PRINT_BARE_VALUE, 1);
	netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICKE_PRINT, 1);
	netsnmp_ds_set_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_OID_OUTPUT_FORMAT, NETSNMP_OID_OUTPUT_NUMERIC);

	init_snmp(name ? name : "mp_snmp");
}

void mp_snmp_deinit(const char *name)
{
	snmp_shutdown(name ? name : "mp_snmp");
}
