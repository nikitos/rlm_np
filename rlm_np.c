/*
 * This file is part of NetProfile RADIUS Module
 * Copyright © 2007-2015 Alex 'Unik' Unigovsky <unik@compot.ru>
 * Copyright © 2007-2009 Nikita 'Nikitos' Andrianov <nikitos@compot.ru>
 * Module source
 *
 * Originally based on rlm_ldap module.
 * Rewritten with a heavy influence of rlm_sqlhpwippool module.
 *
 * NetProfile RADIUS Module is free software: you can redistribute it
 * and/or modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * NetProfile RADIUS Module is distributed in the hope that it will
 * be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with NetProfile RADIUS Module. If not, see
 * <http://www.gnu.org/licenses/>.
 */

#include <freeradius-devel/autoconf.h>

#include <gmp.h>
#include <mpfr.h>

#include <freeradius-devel/radiusd.h>
#include <freeradius-devel/modules.h>
#include <freeradius-devel/modpriv.h>

#include "rlm_sql.h"

#define MAX_NAS_NAME_SIZE 64
#define MAX_TIMESTAMP_SIZE 20
#define TIMESTAMP_FORMAT "%Y-%m-%d %H:%M:%S"

#define NP_FLAG_INUSE 0x1

#define VENDOR_MPD 12341
#define VENDOR_NP 24910

#ifndef  PW_ACCT_INPUT_GIGAWORDS
# define PW_ACCT_INPUT_GIGAWORDS 52
#endif /* PW_ACCT_INPUT_GIGAWORDS */
#ifndef  PW_ACCT_OUTPUT_GIGAWORDS
# define PW_ACCT_OUTPUT_GIGAWORDS 53
#endif /* PW_ACCT_OUTPUT_GIGAWORDS */
#ifndef PW_ACCT_INTERIM_INTERVAL
# define PW_ACCT_INTERIM_INTERVAL 85
#endif /* PW_ACCT_INTERIM_INTERVAL */
#ifndef PW_DROP_USER 
# define PW_DROP_USER 154
#endif /* PW_DROP_USER */
#ifndef PW_TUNNEL_TYPE
# define PW_TUNNEL_TYPE 64
#endif /* PW_TUNNEL_TYPE */
#ifndef PW_TUNNEL_MEDIUM_TYPE
# define PW_TUNNEL_MEDIUM_TYPE 65
#endif /* PW_TUNNEL_MEDIUM_TYPE */
#ifndef PW_TUNNEL_CLIENT_ENDPOINT
# define PW_TUNNEL_CLIENT_ENDPOINT 66
#endif /* PW_TUNNEL_CLIENT_ENDPOINT */
#ifndef PW_TUNNEL_SERVER_ENDPOINT
# define PW_TUNNEL_SERVER_ENDPOINT 67
#endif /* PW_TUNNEL_SERVER_ENDPOINT */
#ifndef PW_FRAMED_INTERFACE_ID
# define PW_FRAMED_INTERFACE_ID 96
#endif /* PW_FRAMED_INTERFACE_ID */
#ifndef PW_FRAMED_IPV6_PREFIX
# define PW_FRAMED_IPV6_PREFIX 97
#endif /* PW_FRAMED_IPV6_PREFIX */

#define PW_NP_POLICY_INGRESS 1
#define PW_NP_POLICY_EGRESS 2
#define PW_NP_NAS_ID 3

#include <mysql/mysql_version.h>
#include <mysql/errmsg.h>
#include <mysql/mysql.h>
#include <mysql/mysqld_error.h>

typedef struct rlm_np_s
{
	char const *name;
	char const *sql_instance_name;
	char const *db_name;
	uint32_t
		station_id,
		alive_interval;
	bool
		do_alloc_v4,
		do_alloc_v6,
		do_drop_user;
#ifdef WITH_COA
	bool
		do_dm,
		do_coa;
#endif

	rlm_sql_t *sql_inst;
	rlm_sql_module_t *db;
}
rlm_np_t;

typedef struct rlm_sql_mysql_conn {
	MYSQL		db;
	MYSQL		*sock;
	MYSQL_RES	*result;
} rlm_sql_mysql_conn_t;

#define SQL_CFG(inst)            ((inst)->sql_inst->config)
#define SQL_SOCK_GET(inst)       (fr_connection_get((inst)->sql_inst->pool))
#define SQL_SOCK_PUT(inst, sock) (fr_connection_release((inst)->sql_inst->pool, (sock)))

#define np_log(level, fmt, ...)  radlog((level), "rlm_np (%s): " fmt, inst->name, ##__VA_ARGS__)
#define np_err(fmt, ...)         np_log(L_ERR, fmt, ##__VA_ARGS__)
#define np_warn(fmt, ...)        np_log(L_WARN, fmt, ##__VA_ARGS__)
#define np_info(fmt, ...)        np_log(L_INFO, fmt, ##__VA_ARGS__)
#define np_auth(fmt, ...)        np_log(L_AUTH, fmt, ##__VA_ARGS__)
#define np_dbg(fmt, ...)         np_log(L_DBG, fmt, ##__VA_ARGS__)

static const CONF_PARSER module_config[] = {
	{ "station_id",			FR_CONF_OFFSET( PW_TYPE_INTEGER, rlm_np_t, station_id),        .dflt = "0"   },
	{ "alive_interval",		FR_CONF_OFFSET(	PW_TYPE_INTEGER, rlm_np_t, alive_interval),    .dflt = "60"  },
	{ "allocate_ipv4",		FR_CONF_OFFSET( PW_TYPE_BOOLEAN, rlm_np_t, do_alloc_v4),       .dflt = "yes" },
	{ "allocate_ipv6",		FR_CONF_OFFSET( PW_TYPE_BOOLEAN, rlm_np_t, do_alloc_v6),       .dflt = "no"  },
	{ "send_drop_user",		FR_CONF_OFFSET( PW_TYPE_BOOLEAN, rlm_np_t, do_drop_user),      .dflt = "no"  },
#ifdef WITH_COA
	{ "send_disconnects",	FR_CONF_OFFSET( PW_TYPE_BOOLEAN, rlm_np_t, do_dm),             .dflt = "yes" },
	{ "send_coa",			FR_CONF_OFFSET( PW_TYPE_BOOLEAN, rlm_np_t, do_coa),            .dflt = "yes" },
#endif
	{ "sql_instance_name",	FR_CONF_OFFSET( PW_TYPE_STRING,  rlm_np_t, sql_instance_name), .dflt = "sql" },
	{ "db_name",			FR_CONF_OFFSET( PW_TYPE_STRING,  rlm_np_t, db_name),           .dflt = "np"  },
	CONF_PARSER_TERMINATOR
};

DIAG_OFF(format-nonliteral)
static sql_rcode_t np_vquery(rlm_np_t *inst, rlm_sql_handle_t *sqlsock, char const *fmt, va_list ap)
{
	char *query;
	sql_rcode_t rc = RLM_SQL_OK;

	if(sqlsock == NULL)
		return RLM_SQL_ERROR;
	query = talloc_vasprintf(inst, fmt, ap);
	if(query == NULL)
		return RLM_SQL_ERROR;
	rc = rlm_sql_query(inst->sql_inst, NULL, &sqlsock, query);
	if(rc != RLM_SQL_OK)
		np_err("np_vquery(): Error in query: %s", query);
	talloc_free(query);
	return rc;
}

static sql_rcode_t np_vselect(rlm_np_t *inst, rlm_sql_handle_t *sqlsock, char const *fmt, va_list ap)
{
	char *query;
	sql_rcode_t rc = RLM_SQL_OK;

	if(sqlsock == NULL)
		return RLM_SQL_ERROR;
	query = talloc_vasprintf(inst, fmt, ap);
	if(query == NULL)
		return RLM_SQL_ERROR;
	rc = rlm_sql_select_query(inst->sql_inst, NULL, &sqlsock, query);
	if(rc != RLM_SQL_OK)
		np_err("np_vselect(): Error in query: %s", query);
	talloc_free(query);
	return rc;
}
DIAG_ON(format-nonliteral)

static sql_rcode_t np_query(rlm_np_t *inst, rlm_sql_handle_t *sqlsock, char const *fmt, ...)
{
	va_list ap;
	sql_rcode_t rc;

	va_start(ap, fmt);
	rc = np_vquery(inst, sqlsock, fmt, ap);
	va_end(ap);

	return rc;
}

static sql_rcode_t np_finish(rlm_np_t *inst, rlm_sql_handle_t *sqlsock)
{
	return (inst->db->sql_finish_query)(sqlsock, SQL_CFG(inst));
}

static sql_rcode_t np_select_finish(rlm_np_t *inst, rlm_sql_handle_t *sqlsock, rlm_sql_row_t *row)
{
	if(row != NULL)
		*row = NULL;
	return (inst->db->sql_finish_select_query)(sqlsock, SQL_CFG(inst));
}

static sql_rcode_t np_select(rlm_np_t *inst, rlm_sql_handle_t *sqlsock, rlm_sql_row_t *row, char const *fmt, ...)
{
	va_list ap;
	sql_rcode_t rc;

	va_start(ap, fmt);
	rc = np_vselect(inst, sqlsock, fmt, ap);
	va_end(ap);
	if(rc != RLM_SQL_OK)
		return rc;

	if(row != NULL)
	{
		rc = rlm_sql_fetch_row(inst->sql_inst, NULL, &sqlsock);
		*row = sqlsock->row;
		if(rc != RLM_SQL_OK)
		{
			np_select_finish(inst, sqlsock, row);
			np_err("np_select(): Couldn't fetch row from results of query.");
			return rc;
		}
	}
	return RLM_SQL_OK;
}

static size_t sql_escape_func(UNUSED REQUEST *request, char *out, size_t outlen, char const *in, void *arg)
{
	size_t			inlen;
	rlm_sql_handle_t	*handle = talloc_get_type_abort(arg, rlm_sql_handle_t);
	rlm_sql_mysql_conn_t	*conn = handle->conn;

	/* Check for potential buffer overflow */
	inlen = strlen(in);
	if ((inlen * 2 + 1) > outlen) return 0;
	/* Prevent integer overflow */
	if ((inlen * 2 + 1) <= inlen) return 0;

	return mysql_real_escape_string(conn->sock, out, in, inlen);
}

static char *np_escape(rlm_np_t *inst, rlm_sql_handle_t *sqlsock, char const *str)
{
	size_t inlen, outlen;
	char *escaped;

	if(str == NULL)
	{
		np_err("np_escape(): Can't escape NULL value.");
		return NULL;
	}
	inlen = strlen(str);
	outlen = inlen * 2 + 1;
	if(outlen <= inlen)
	{
		np_err("np_escape(): Integer overflow detected when escaping value.");
		return NULL;
	}
	escaped = talloc_zero_array(inst, char, outlen);
	if(escaped == NULL)
	{
		np_err("np_escape(): Could not allocate memory for escaped value.");
		return NULL;
	}

	sql_escape_func(NULL, escaped, outlen, str, sqlsock);
	return escaped;
}

static char *np_escape_mpz(rlm_np_t *inst, rlm_sql_handle_t *sqlsock, mpz_t num)
{
	char *tmp, *escaped;

	tmp = mpz_get_str(NULL, 10, num);
	if(tmp == NULL)
	{
		np_err("np_escape_mpz(): Could not allocate memory for number's string representation.");
		return NULL;
	}
	escaped = np_escape(inst, sqlsock, tmp);
	free(tmp);
	return escaped;
}

static char *np_timestamp(rlm_np_t *inst, rlm_sql_handle_t *sqlsock, struct tm *ts)
{
	char *timestr, *escaped;

	timestr = talloc_zero_array(inst, char, MAX_TIMESTAMP_SIZE);
	if(timestr == NULL)
	{
		np_err("np_timestamp(): Could not allocate memory for timestamp string.");
		return NULL;
	}
	if(strftime(timestr, MAX_TIMESTAMP_SIZE, TIMESTAMP_FORMAT, ts) == 0)
	{
		talloc_free(timestr);
		np_err("np_timestamp(): Error while formatting timestamp string.");
		return NULL;
	}
	escaped = np_escape(inst, sqlsock, timestr);
	talloc_free(timestr);
	return escaped;
}

static int np_get_nas_id(rlm_np_t *inst, rlm_sql_handle_t *sqlsock, REQUEST *request, char **nas)
{
	struct in_addr nasip;
	char *tmpnas = NULL;
	VALUE_PAIR *vp;

	vp = fr_pair_find_by_num(request->packet->vps, PW_NAS_IP_ADDRESS, 0, TAG_ANY);
	if(vp != NULL)
	{
		nasip.s_addr = vp->vp_ipaddr;
		tmpnas = talloc_zero_array(inst, char, 16);
		if(tmpnas == NULL)
		{
			np_err("np_get_nas_id(): Could not allocate memory for NAS IP address.");
			return RLM_MODULE_FAIL;
		}
		if(inet_ntop(AF_INET, &nasip, tmpnas, 16) == NULL)
		{
			talloc_free(tmpnas);
			np_err("np_get_nas_id(): Could not construct NAS IP address string.");
			return RLM_MODULE_FAIL;
		}
	}
	else
	{
		vp = fr_pair_find_by_num(request->packet->vps, PW_NAS_IDENTIFIER, 0, TAG_ANY);
		if(vp == NULL)
		{
			np_warn("np_get_nas_id(): Could not find NAS information.");
			return RLM_MODULE_INVALID;
		}
		tmpnas = talloc_strndup(inst, vp->vp_strvalue, MAX_NAS_NAME_SIZE);
		if(tmpnas == NULL)
		{
			np_err("np_get_nas_id(): Could not allocate memory for NAS identifier.");
			return RLM_MODULE_FAIL;
		}
	}
	if(tmpnas != NULL)
	{
		*nas = np_escape(inst, sqlsock, tmpnas);
		talloc_free(tmpnas);
	}
	if(*nas == NULL)
		return RLM_MODULE_FAIL;
	return 0;
}

static int np_instantiate(CONF_SECTION *conf, void *instance)
{
	rlm_np_t *inst = instance;
	module_instance_t *sql_inst;

	inst->name = cf_section_name2(conf);
	if(!inst->name)
		inst->name = "(no name)";

	if(inst->station_id == 0)
	{
		cf_log_err_cs(conf, "NetProfile station ID is unset.");
		return -1;
	}

	sql_inst = module_instantiate(cf_section_find("modules"), (inst->sql_instance_name));
	if(sql_inst == NULL)
	{
		cf_log_err_cs(conf, "Cannot find SQL module instance named '%s'.", inst->sql_instance_name);
		return -1;
	}
	if(strcmp(sql_inst->entry->name, "rlm_sql") != 0)
	{
		cf_log_err_cs(conf, "Given instance ('%s') is not an instance of the rlm_sql module.", inst->sql_instance_name);
		return -1;
	}
	inst->sql_inst = (rlm_sql_t *) sql_inst->insthandle;
	inst->db = (rlm_sql_module_t *) inst->sql_inst->module;

	return 0;
}

static rlm_rcode_t np_authorize(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t np_authorize(void *instance, REQUEST *request)
{
	VALUE_PAIR *vp;
	rlm_sql_handle_t *sqlsock;
	int r_porttype = 0,
		r_servicetype = 0,
		r_frproto = 0,
		r_tuntype = 0,
		r_tunmedium = 0;
	uint32_t
		authz_aeid = 0,
		authz_state = 90;
	char
		*authz_username = NULL,
		*authz_ts = NULL,
		*authz_password_ntlm = NULL,
		*authz_password_crypt = NULL,
		*authz_password_plain = NULL,
		*authz_policy_in = NULL,
		*authz_policy_eg = NULL;
	struct tm ts;
	rlm_sql_row_t row = NULL;
	rlm_rcode_t rc = RLM_MODULE_OK;
	rlm_np_t *inst = (rlm_np_t *) instance;

	np_dbg("np_authorize(): Started.");

	if(!request->username || !request->username->vp_strvalue)
	{
		np_auth("np_authorize(): Attribute 'User-Name' is required for authorization.");
		return RLM_MODULE_INVALID;
	}
	if(!strlen(request->username->vp_strvalue))
	{
		np_err("np_authorize(): Zero length username is not permitted.");
		return RLM_MODULE_INVALID;
	}
	np_dbg("np_authorize(): Performing authorization for user '%s'.", request->username->vp_strvalue);

	/* Convert request timestamp to local time, and split into components. */
	if(localtime_r(&request->timestamp, &ts) == NULL)
	{
		np_err("np_authorize(): Could not convert request timestamp to local time.");
		return RLM_MODULE_FAIL;
	}

	/* Get NAS port type */
	vp = fr_pair_find_by_num(request->packet->vps, PW_NAS_PORT_TYPE, 0, TAG_ANY);
	if(vp != NULL)
		r_porttype = vp->vp_integer;

	/* Get service type */
	vp = fr_pair_find_by_num(request->packet->vps, PW_SERVICE_TYPE, 0, TAG_ANY);
	if(vp != NULL)
		r_servicetype = vp->vp_integer;

	/* Get framed protocol */
	vp = fr_pair_find_by_num(request->packet->vps, PW_FRAMED_PROTOCOL, 0, TAG_ANY);
	if(vp != NULL)
		r_frproto = vp->vp_integer;

	/* Get tunnel type */
	vp = fr_pair_find_by_num(request->packet->vps, PW_TUNNEL_TYPE, 0, TAG_ANY);
	if(vp != NULL)
		r_tuntype = vp->vp_integer;

	/* Get tunnel medium type */
	vp = fr_pair_find_by_num(request->packet->vps, PW_TUNNEL_MEDIUM_TYPE, 0, TAG_ANY);
	if(vp != NULL)
		r_tunmedium = vp->vp_integer;

	/* Get DB connection. */
	sqlsock = SQL_SOCK_GET(inst);
	if(sqlsock == NULL)
	{
		np_err("np_authorize(): Error while requesting an SQL socket.");
		return RLM_MODULE_FAIL;
	}

	/* Escape username for use in DB queries. */
	authz_username = np_escape(inst, sqlsock, request->username->vp_strvalue);
	if(authz_username == NULL)
	{
		SQL_SOCK_PUT(inst, sqlsock);
		return RLM_MODULE_FAIL;
	}

	/* Retreive username, password, policies and accounting state from DB. */
	if(np_select(inst, sqlsock, &row,
			"CALL acct_authz_session('%s', %d, %d, %d, %d, %d)",
			authz_username, r_porttype, r_servicetype, r_frproto, r_tuntype, r_tunmedium) != RLM_SQL_OK)
	{
		SQL_SOCK_PUT(inst, sqlsock);
		talloc_free(authz_username);
		np_err("np_authorize(): Error executing 'acct_authz_session' procedure.");
		return RLM_MODULE_FAIL;
	}
	if(!row || !row[1])
	{
		np_select_finish(inst, sqlsock, &row);
		SQL_SOCK_PUT(inst, sqlsock);
		talloc_free(authz_username);
		if(!row)
			np_err("np_authorize(): 'acct_authz_session' procedure did not provide any data.");
		else if(!row[1])
			np_auth("np_authorize(): 'acct_authz_session' procedure couldn't find username '%s'.", request->username->vp_strvalue);
		return RLM_MODULE_NOTFOUND;
	}
	if(row[0])
		authz_aeid = strtoul(row[0], (char **) NULL, 10);
	if(row[2])
	{
		authz_password_ntlm = talloc_strndup(inst, row[2], 256);
		if(authz_password_ntlm == NULL)
			rc = RLM_MODULE_FAIL;
	}
	if(row[3])
	{
		authz_password_crypt = talloc_strndup(inst, row[3], 256);
		if(authz_password_crypt == NULL)
			rc = RLM_MODULE_FAIL;
	}
	if(row[4])
	{
		authz_password_plain = talloc_strndup(inst, row[4], 256);
		if(authz_password_plain == NULL)
			rc = RLM_MODULE_FAIL;
	}
	if(row[5])
	{
		authz_policy_in = talloc_strndup(inst, row[5], 256);
		if(authz_policy_in == NULL)
			rc = RLM_MODULE_FAIL;
	}
	if(row[6])
	{
		authz_policy_eg = talloc_strndup(inst, row[6], 256);
		if(authz_policy_eg == NULL)
			rc = RLM_MODULE_FAIL;
	}
	if(row[7])
		authz_state = strtoul(row[7], (char **) NULL, 10);
	np_select_finish(inst, sqlsock, &row);
	if(rc != RLM_MODULE_OK)
	{
		SQL_SOCK_PUT(inst, sqlsock);
		talloc_free(authz_username);
		if(authz_password)
			talloc_free(authz_password);
		if(authz_policy_in)
			talloc_free(authz_policy_in);
		if(authz_policy_eg)
			talloc_free(authz_policy_eg);
		np_err("np_authorize(): Could not allocate memory for authorize query results.");
		return rc;
	}

	/* User is active or auto-blocked. Accounting needed. */
	if(authz_aeid && (authz_state < 2))
	{
		authz_ts = np_timestamp(inst, sqlsock, &ts);
		if(authz_ts == NULL)
		{
			SQL_SOCK_PUT(inst, sqlsock);
			talloc_free(authz_username);
			if(authz_password)
				talloc_free(authz_password);
			if(authz_policy_in)
				talloc_free(authz_policy_in);
			if(authz_policy_eg)
				talloc_free(authz_policy_eg);
			np_dbg("np_authorize(): Unable to authorize, timestamp formatting.");
			return RLM_MODULE_FAIL;
		}
		if(np_select(inst, sqlsock, &row,
				"CALL acct_add(%u, '%s', 0, 0, '%s')",
				authz_aeid, authz_username, authz_ts) != RLM_SQL_OK)
		{
			SQL_SOCK_PUT(inst, sqlsock);
			talloc_free(authz_ts);
			talloc_free(authz_username);
			if(authz_password_ntlm)
				talloc_free(authz_password_ntlm);
			if(authz_password_crypt)
				talloc_free(authz_password_crypt);
			if(authz_password_plain)
				talloc_free(authz_password_plain);
			if(authz_policy_in)
				talloc_free(authz_policy_in);
			if(authz_policy_eg)
				talloc_free(authz_policy_eg);
			np_err("np_authorize(): Error executing 'acct_add' procedure.");
			return RLM_MODULE_FAIL;
		}
		talloc_free(authz_ts);
		if(row != NULL)
		{
			/* User state */
			if(row[1] != NULL)
				authz_state = strtoul(row[1], (char **) NULL, 10);
			/* Ingress policy */
			if(row[2] != NULL)
			{
				if(authz_policy_in)
					talloc_free(authz_policy_in);
				authz_policy_in = talloc_strndup(inst, row[2], 256);
				if(authz_policy_eg == NULL)
					rc = RLM_MODULE_FAIL;
			}
			/* Egress policy */
			if(row[3] != NULL)
			{
				if(authz_policy_eg)
					talloc_free(authz_policy_eg);
				authz_policy_eg = talloc_strndup(inst, row[3], 256);
				if(authz_policy_eg == NULL)
					rc = RLM_MODULE_FAIL;
			}
			if(rc != RLM_MODULE_OK)
			{
				np_select_finish(inst, sqlsock, &row);
				SQL_SOCK_PUT(inst, sqlsock);
				talloc_free(authz_username);
			    if(authz_password_ntlm)
			    	talloc_free(authz_password_ntlm);
    			if(authz_password_crypt)
			    	talloc_free(authz_password_crypt);
    			if(authz_password_plain)
			    	talloc_free(authz_password_plain);
				if(authz_policy_in)
					talloc_free(authz_policy_in);
				if(authz_policy_eg)
					talloc_free(authz_policy_eg);
				np_err("np_authorize(): Could not allocate memory for pre-accounting query results.");
				return rc;
			}
		}
		else
			np_warn("np_authorize(): 'acct_add' procedure did not provide any data.");
		np_select_finish(inst, sqlsock, &row);
	}
	SQL_SOCK_PUT(inst, sqlsock);
	talloc_free(authz_username);

	/* User is auto- or manually-blocked, or there was an error in DB. */
	if(authz_state > 0)
	{
	    if(authz_password_ntlm)
	    	talloc_free(authz_password_ntlm);
  		if(authz_password_crypt)
	    	talloc_free(authz_password_crypt);
  		if(authz_password_plain)
	    	talloc_free(authz_password_plain);
		if(authz_policy_in)
			talloc_free(authz_policy_in);
		if(authz_policy_eg)
			talloc_free(authz_policy_eg);
		np_err("np_authorize(): Authorization rejected for user '%s' with state %u.",
				request->username->vp_strvalue, authz_state);
		return RLM_MODULE_USERLOCK;
	}

	/* Add user ntlm password for authorization by PAP/CHAP/EAP/etc. */
	if(authz_password_ntlm)
	{
		vp = radius_pair_create(request, &request->config, PW_NT_PASSWORD, 0);
		if(vp == NULL)
		{
			talloc_free(authz_password_ntlm);
			if(authz_policy_in)
				talloc_free(authz_policy_in);
			if(authz_policy_eg)
				talloc_free(authz_policy_eg);
			np_err("np_authorize(): Error allocating memory for ntlm password A/V pair.");
			return RLM_MODULE_FAIL;
		}
		fr_pair_value_strsteal(vp, authz_password_ntlm);
		np_dbg("np_authorize(): Added user ntlm password to config items.");
    }

	/* Add user crypt password for authorization by PAP/CHAP/EAP/etc. */
	if(authz_password_crypt)
	{
		vp = radius_pair_create(request, &request->config, PW_CRYPT_PASSWORD, 0);
		if(vp == NULL)
		{
			talloc_free(authz_password_crypt);
			if(authz_policy_in)
				talloc_free(authz_policy_in);
			if(authz_policy_eg)
				talloc_free(authz_policy_eg);
			np_err("np_authorize(): Error allocating memory for crypt password A/V pair.");
			return RLM_MODULE_FAIL;
		}
		fr_pair_value_strsteal(vp, authz_password_crypt);
		np_dbg("np_authorize(): Added user crypt password to config items.");
    }

	/* Add user plain password for authorization by PAP/CHAP/EAP/etc. */
	if(authz_password_plain)
	{
		vp = radius_pair_create(request, &request->config, PW_CLEARTEXT_PASSWORD, 0);
		if(vp == NULL)
		{
			talloc_free(authz_password_plain);
			if(authz_policy_in)
				talloc_free(authz_policy_in);
			if(authz_policy_eg)
				talloc_free(authz_policy_eg);
			np_err("np_authorize(): Error allocating memory for plain password A/V pair.");
			return RLM_MODULE_FAIL;
		}
		fr_pair_value_strsteal(vp, authz_password_plain);
		np_dbg("np_authorize(): Added user plain password to config items.");
	}

	/* Add user ingress policy for rate-limiting and firewalling. */
	if(authz_policy_in)
	{
		vp = radius_pair_create(request->reply, &request->reply->vps, PW_NP_POLICY_INGRESS, VENDOR_NP);
		if(vp == NULL)
		{
			talloc_free(authz_policy_in);
			if(authz_policy_eg)
				talloc_free(authz_policy_eg);
			np_err("np_authorize(): Error allocating memory for ingress policy A/V pair.");
			return RLM_MODULE_FAIL;
		}
		fr_pair_value_strsteal(vp, authz_policy_in);
		np_dbg("np_authorize(): Added user ingress policy to reply items.");
	}

	/* Add user egress policy for rate-limiting and firewalling. */
	if(authz_policy_eg)
	{
		vp = radius_pair_create(request->reply, &request->reply->vps, PW_NP_POLICY_EGRESS, VENDOR_NP);
		if(vp == NULL)
		{
			talloc_free(authz_policy_eg);
			np_err("np_authorize(): Error allocating memory for egress policy A/V pair.");
			return RLM_MODULE_FAIL;
		}
		fr_pair_value_strsteal(vp, authz_policy_eg);
		np_dbg("np_authorize(): Added user egress policy to reply items.");
	}

	/* Add IPv6 interface ID based on access entity ID. */
	if(inst->do_alloc_v6 && authz_aeid)
	{
		uint64_t sessid;

		vp = radius_pair_create(request->reply, &request->reply->vps, PW_FRAMED_INTERFACE_ID, 0);
		if(vp == NULL)
		{
			np_err("np_authorize(): Error allocating memory for Framed-Interface-Id A/V pair.");
			return RLM_MODULE_FAIL;
		}
		sessid = (uint64_t) authz_aeid;
		sessid = htobe64(sessid);
		memcpy(vp->vp_ifid, (void *) &sessid, sizeof(uint64_t));
		vp->vp_length = 8;
		np_dbg("np_authorize(): Added IPv6 interface ID to reply items.");
	}
	if(inst->alive_interval > 0)
	{
		vp = radius_pair_create(request->reply, &request->reply->vps, PW_ACCT_INTERIM_INTERVAL, 0);
		if(vp == NULL)
		{
			np_err("np_authorize(): Error allocating memory for accounting interval A/V pair.");
			return RLM_MODULE_FAIL;
		}
		vp->vp_integer = inst->alive_interval;
		np_dbg("np_authorize(): Added accounting interval to reply items.");
	}
	return rc;
}

static rlm_rcode_t np_accounting(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t np_accounting(void *instance, REQUEST *request)
{
	VALUE_PAIR *vp, *sid, *stype;
	rlm_sql_handle_t *sqlsock;
	mpz_t t_in, t_eg;
	int i;
	uint32_t
		ipaddrid = 0,
		nasid = 0;
	uint64_t
		ip6addrid = 0,
		sessid = 0;
	struct tm ts;
	char
		*user_esc,
		*sid_esc,
		*ts_esc,
		*nas,
		*csid,
		*called,
		*t_in_esc,
		*t_eg_esc,
		*pol_in = NULL,
		*pol_eg = NULL;
	rlm_sql_row_t row = NULL;
	rlm_rcode_t rc = RLM_MODULE_OK;
	rlm_np_t *inst = (rlm_np_t *) instance;

	np_dbg("np_accounting(): Started.");

	if(!request->username || !request->username->vp_strvalue)
	{
		np_auth("np_accounting(): Attribute 'User-Name' is required for accounting.");
		return RLM_MODULE_INVALID;
	}
	if(!strlen(request->username->vp_strvalue))
	{
		np_err("np_accounting(): Zero length username is not permitted.");
		return RLM_MODULE_INVALID;
	}
	np_dbg("np_accounting(): Performing accounting for user '%s'.", request->username->vp_strvalue);

	stype = fr_pair_find_by_num(request->packet->vps, PW_ACCT_STATUS_TYPE, 0, TAG_ANY);
	if(stype == NULL)
	{
		np_dbg("np_accounting(): Could not find account status type in packet.");
		return RLM_MODULE_NOOP;
	}
	sid = fr_pair_find_by_num(request->packet->vps, PW_ACCT_UNIQUE_SESSION_ID, 0, TAG_ANY);
	if(sid == NULL || sid->vp_strvalue == NULL)
	{
		np_dbg("np_accounting(): Could not find unique session ID in packet.");
		return RLM_MODULE_NOOP;
	}

	/* Convert request timestamp to local time, and split into components. */
	if(localtime_r(&request->timestamp, &ts) == NULL)
	{
		np_err("np_accounting(): Could not convert request timestamp to local time.");
		return RLM_MODULE_FAIL;
	}

	/* Get DB connection. */
	sqlsock = SQL_SOCK_GET(inst);
	if(sqlsock == NULL)
	{
		np_err("np_accounting(): Error while requesting an SQL socket.");
		return RLM_MODULE_FAIL;
	}

	/* Escape username for use in DB queries. */
	user_esc = np_escape(inst, sqlsock, request->username->vp_strvalue);
	if(user_esc == NULL)
	{
		SQL_SOCK_PUT(inst, sqlsock);
		return RLM_MODULE_FAIL;
	}

	/* Escape RADIUS session ID for use in DB queries. */
	sid_esc = np_escape(inst, sqlsock, sid->vp_strvalue);
	if(sid_esc == NULL)
	{
		SQL_SOCK_PUT(inst, sqlsock);
		talloc_free(user_esc);
		return RLM_MODULE_FAIL;
	}

	/* Format escaped timestamp for use in DB queries. */
	ts_esc = np_timestamp(inst, sqlsock, &ts);
	if(ts_esc == NULL)
	{
		SQL_SOCK_PUT(inst, sqlsock);
		talloc_free(sid_esc);
		talloc_free(user_esc);
		return RLM_MODULE_FAIL;
	}

	switch(stype->vp_integer)
	{
		case PW_STATUS_START:
			/* Fetch NAS ID string */
			i = np_get_nas_id(inst, sqlsock, request, &nas);
			if((i != 0) && (nas != NULL))
			{
				talloc_free(nas);
				nas = NULL;
			}
			if(nas != NULL)
			{
				if(np_select(inst, sqlsock, &row,
						"SELECT n.nasid nasid"
						" FROM nas_def n"
						" WHERE n.idstr LIKE '%s'",
						nas) == RLM_SQL_OK)
				{
					if(row && row[0])
						nasid = strtoul(row[0], (char **) NULL, 10);
					np_select_finish(inst, sqlsock, &row);
				}
				talloc_free(nas);
			}
			if(nasid == 0)
				np_warn("np_accounting(): Unable to identify calling NAS. Setting nasid to 0.");

			/* Fetch calling station ID */
			vp = fr_pair_find_by_num(request->packet->vps, PW_CALLING_STATION_ID, 0, TAG_ANY);
			if(vp == NULL)
				vp = fr_pair_find_by_num(request->packet->vps, PW_TUNNEL_CLIENT_ENDPOINT, 0, TAG_ANY);
			if(vp && vp->vp_strvalue)
				csid = np_escape(inst, sqlsock, vp->vp_strvalue);
			else
				csid = NULL;

			/* Fetch called station ID */
			vp = fr_pair_find_by_num(request->packet->vps, PW_CALLED_STATION_ID, 0, TAG_ANY);
			if(vp == NULL)
				vp = fr_pair_find_by_num(request->packet->vps, PW_TUNNEL_SERVER_ENDPOINT, 0, TAG_ANY);
			if(vp && vp->vp_strvalue)
				called = np_escape(inst, sqlsock, vp->vp_strvalue);
			else
				called = NULL;

			/* Fetch framed IPv4 address */
			vp = fr_pair_find_by_num(request->packet->vps, PW_FRAMED_IP_ADDRESS, 0, TAG_ANY);
			if(vp != NULL)
			{
				if(np_select(inst, sqlsock, &row,
						"SELECT i.ipaddrid ipaddrid"
						" FROM ipaddr_def i LEFT JOIN nets_def n USING(netid)"
						" WHERE (n.ipaddr + i.offset) = %u",
						ntohl(vp->vp_integer)) == RLM_SQL_OK)
				{
					if(row && row[0])
						ipaddrid = strtoul(row[0], (char **) NULL, 10);
					np_select_finish(inst, sqlsock, &row);
				}
				else
					np_warn("np_accounting(): Unable to get IPv4 address from DB. Setting ipaddrid to 0.");
			}
			else
				np_warn("np_accounting(): No IPv4 address provided. Setting ipaddrid to 0.");

			/* Fetch framed IPv6 prefix */
			vp = fr_pair_find_by_num(request->packet->vps, PW_FRAMED_IPV6_PREFIX, 0, TAG_ANY);
			if((vp != NULL) && (vp->vp_length >= 18))
			{
				if(np_select(inst, sqlsock, &row,
						"SELECT i.ip6addrid ip6addrid"
						" FROM ip6addr_def i LEFT JOIN nets_def n USING(netid)"
						" WHERE CONCAT(SUBSTRING(HEX(n.ip6addr) FROM 1 FOR 16), LPAD(HEX(CAST(CONV(SUBSTRING(n.ip6addr FROM 17 FOR 16), 16, 10) AS UNSIGNED) + i.offset), 16, '0')) = '%08X%08X%08X%08X'",
						*((uint32_t const *) (vp->vp_octets + 2)),
						*((uint32_t const *) (vp->vp_octets + 6)),
						*((uint32_t const *) (vp->vp_octets + 10)),
						*((uint32_t const *) (vp->vp_octets + 14))) == RLM_SQL_OK)
				{
					if(row && row[0])
						ip6addrid = strtoull(row[0], (char **) NULL, 10);
					np_select_finish(inst, sqlsock, &row);
				}
				else
					np_warn("np_accounting(): Unable to get IPv6 address from DB. Setting ip6addrid to 0.");
			}
			else
				np_warn("np_accounting(): No IPv6 address provided. Setting ip6addrid to 0.");

			/* Query DB to allocate session and link IP addresses to it. */
			if(np_select(inst, sqlsock, &row,
					"CALL acct_open_session('%s', %u, '%s', %u, %" PRIu64 ", %u, '%s', '%s', '%s', NULL, NULL)",
					sid_esc, inst->station_id, user_esc,
					ipaddrid, ip6addrid, nasid,
					ts_esc, csid, called) == RLM_SQL_OK)
			{
				if(row && row[0])
				{
					sessid = strtoull(row[0], (char **) NULL, 10);
					if(sessid == 0)
					{
						rc = RLM_MODULE_INVALID;
						np_dbg("np_accounting(): Unable to open session, SQL error.");
					}
					else
						np_dbg("np_accounting(): Opened session ID %" PRIu64 ".", sessid);
				}
				else
					np_warn("np_accounting(): Unable to determine ID of newly opened session.");
				np_select_finish(inst, sqlsock, &row);
			}
			else
			{
				rc = RLM_MODULE_INVALID;
				np_dbg("np_accounting(): Unable to open session, SQL error.");
			}
			if(called != NULL)
				talloc_free(called);
			if(csid != NULL)
				talloc_free(csid);
			break;
		case PW_STATUS_STOP:
		case PW_STATUS_ALIVE:
			mpz_init_set_ui(t_in, 0);
			mpz_init_set_ui(t_eg, 0);
			/* Note: we swap ingress/egress counters because we label them from client's PoV. */
			vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_INPUT_GIGAWORDS, 0, TAG_ANY);
			if(vp != NULL)
			{
				mpz_set_ui(t_eg, 1);
				mpz_mul_2exp(t_eg, t_eg, 32);
				mpz_mul_ui(t_eg, t_eg, vp->vp_integer);
			}
			vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_OUTPUT_GIGAWORDS, 0, TAG_ANY);
			if(vp != NULL)
			{
				mpz_set_ui(t_in, 1);
				mpz_mul_2exp(t_in, t_in, 32);
				mpz_mul_ui(t_in, t_in, vp->vp_integer);
			}
			vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_INPUT_OCTETS, 0, TAG_ANY);
			if(vp != NULL)
				mpz_add_ui(t_eg, t_eg, vp->vp_integer);
			vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_OUTPUT_OCTETS, 0, TAG_ANY);
			if(vp != NULL)
				mpz_add_ui(t_in, t_in, vp->vp_integer);

			/* Format ingress traffic count for use in DB queries. */
			t_in_esc = np_escape_mpz(inst, sqlsock, t_in);
			if(t_in_esc == NULL)
			{
				mpz_clear(t_eg);
				mpz_clear(t_in);
				rc = RLM_MODULE_FAIL;
				break;
			}

			/* Format egress traffic count for use in DB queries. */
			t_eg_esc = np_escape_mpz(inst, sqlsock, t_eg);
			if(t_eg_esc == NULL)
			{
				talloc_free(t_in_esc);
				mpz_clear(t_eg);
				mpz_clear(t_in);
				rc = RLM_MODULE_FAIL;
				break;
			}

			/* Run accounting in DB, return new user state and policies. */
			if(np_select(inst, sqlsock, &row,
					"CALL acct_add_session('%s', %u, '%s', '%s', '%s', '%s')",
					sid_esc, inst->station_id, user_esc, t_in_esc, t_eg_esc, ts_esc) == RLM_SQL_OK)
			{
				if(row && row[1])
				{
					/* New user state */
					i = strtoul(row[1], (char **) NULL, 10);
					/* New ingress policy */
					if(row[2])
					{
						pol_in = talloc_strndup(inst, row[2], 256);
						if(pol_in == NULL)
							rc = RLM_MODULE_FAIL;
					}
					/* New egress policy */
					if(row[3])
					{
						pol_eg = talloc_strndup(inst, row[3], 256);
						if(pol_eg == NULL)
							rc = RLM_MODULE_FAIL;
					}
					if(rc != RLM_MODULE_OK)
						np_err("np_accounting(): Could not allocate memory for accounting query results.");
				}
				else
				{
					rc = RLM_MODULE_INVALID;
					np_dbg("np_accounting(): Unable to process session accounting, SQL error.");
				}
				np_select_finish(inst, sqlsock, &row);
			}
			else
			{
				rc = RLM_MODULE_INVALID;
				np_dbg("np_accounting(): Unable to process session accounting, SQL error.");
			}

			talloc_free(t_eg_esc);
			talloc_free(t_in_esc);
			mpz_clear(t_eg);
			mpz_clear(t_in);
			if(rc != RLM_MODULE_OK)
				break;

			/* User state > 0, access is denied. */
			if(i > 0)
			{
				/* Add Drop-User vendor-specific attribute (for MPD etc.). Violates the RADIUS spec. */
				if(inst->do_drop_user)
				{
					vp = radius_pair_create(request->reply, &request->reply->vps, PW_DROP_USER, VENDOR_MPD);
					if(vp == NULL)
					{
						rc = RLM_MODULE_FAIL;
						np_err("np_accounting(): Error allocating memory for MPD:Drop-User A/V pair.");
						break;
					}
					vp->vp_integer = 1;
					np_dbg("np_accounting(): Added MPD:Drop-User to reply A/V pairs.");
				}

#ifdef WITH_COA
				/* Add Disconnect-Request. */
				if(request->coa || request_alloc_coa(request))
				{
					np_dbg("np_accounting(): Priming Disconnect-Request.");
					request->coa->proxy->code = PW_CODE_DISCONNECT_REQUEST;

					vp = fr_pair_copy(request->coa->proxy, request->username);
					if(vp)
					{
						fr_pair_add(&request->coa->proxy->vps, vp);
						np_dbg("np_accounting(): Added User-Name to Disconnect-Request.");
					}
					else
						np_err("np_accounting(): Error adding username A/V pair to Disconnect-Request.");

					vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_SESSION_ID, 0, TAG_ANY);
					if(vp)
					{
						vp = fr_pair_copy(request->coa->proxy, vp);
						if(vp)
						{
							fr_pair_add(&request->coa->proxy->vps, vp);
							np_dbg("np_accounting(): Added Acct-Session-Id to Disconnect-Request.");
						}
						else
							np_err("np_accounting(): Error adding accounting session ID A/V pair to Disconnect-Request.");
					}
					else
						np_err("np_accounting(): Unable to find accounting session ID in a request.");
				}
				else
					np_err("np_accounting(): Unable to add Disconnect-Request packet.");
#endif
			}
#ifdef WITH_COA
			else if((pol_in != NULL) || (pol_eg != NULL))
			{
				/* Add CoA-Request. */
				if(request->coa || request_alloc_coa(request))
				{
					np_dbg("np_accounting(): Priming CoA-Request.");
					request->coa->proxy->code = PW_CODE_COA_REQUEST;

					vp = fr_pair_copy(request->coa->proxy, request->username);
					if(vp)
					{
						fr_pair_add(&request->coa->proxy->vps, vp);
						np_dbg("np_accounting(): Added User-Name to CoA-Request.");
					}
					else
						np_err("np_accounting(): Error adding username A/V pair to CoA-Request.");

					vp = fr_pair_find_by_num(request->packet->vps, PW_ACCT_SESSION_ID, 0, TAG_ANY);
					if(vp)
					{
						vp = fr_pair_copy(request->coa->proxy, vp);
						if(vp)
						{
							fr_pair_add(&request->coa->proxy->vps, vp);
							np_dbg("np_accounting(): Added Acct-Session-Id to CoA-Request.");
						}
						else
							np_err("np_accounting(): Error adding accounting session ID A/V pair to CoA-Request.");
					}
					else
						np_err("np_accounting(): Unable to find accounting session ID in a request.");

					if(pol_in && strlen(pol_in))
					{
						vp = radius_pair_create(request->coa->proxy, &request->coa->proxy->vps, PW_NP_POLICY_INGRESS, VENDOR_NP);
						if(vp)
						{
							fr_pair_value_strsteal(vp, pol_in);
							pol_in = NULL;
							np_dbg("np_accounting(): Added user ingress policy to CoA-Request.");
						}
						else
							np_err("np_accounting(): Error allocating memory for ingress policy A/V pair.");
					}
					if(pol_eg && strlen(pol_eg))
					{
						vp = radius_pair_create(request->coa->proxy, &request->coa->proxy->vps, PW_NP_POLICY_EGRESS, VENDOR_NP);
						if(vp)
						{
							fr_pair_value_strsteal(vp, pol_eg);
							pol_eg = NULL;
							np_dbg("np_accounting(): Added user egress policy to CoA-Request.");
						}
						else
							np_err("np_accounting(): Error allocating memory for egress policy A/V pair.");
					}
				}
				else
					np_err("rlm_np: Unable to add CoA-Request packet.");
			}
#endif
			/* Handle session closing in DB. Archives session record and releases IP addresses. */
			if(stype->vp_integer == PW_STATUS_STOP)
			{
				if(np_query(inst, sqlsock,
						"CALL acct_close_session('%s', %u, '%s')",
						sid_esc, inst->station_id, ts_esc) == RLM_SQL_OK)
				{
					np_finish(inst, sqlsock);
					np_dbg("np_accounting(): Closed session '%s'.", sid->vp_strvalue);
				}
				else
				{
					rc = RLM_MODULE_INVALID;
					np_err("np_accounting(): Unable to close session '%s'.", sid->vp_strvalue);
					break;
				}
			}
			break;
	}
	SQL_SOCK_PUT(inst, sqlsock);
	if(pol_eg != NULL)
		talloc_free(pol_eg);
	if(pol_in != NULL)
		talloc_free(pol_in);
	talloc_free(ts_esc);
	talloc_free(sid_esc);
	talloc_free(user_esc);
	return rc;
}

static rlm_rcode_t np_post_auth(void *instance, REQUEST *request) CC_HINT(nonnull);
static rlm_rcode_t np_post_auth(void *instance, REQUEST *request)
{
	VALUE_PAIR *vp;
	rlm_sql_handle_t *sqlsock;
	int
		do_alloc,
		subrc;
	uint32_t
		ipaddr = 0,
		ipaddrid = 0,
		nasid = 0;
	uint64_t
		ip6addrid = 0,
		ip6offset = 0;
	char
		*user_esc,
		*nas = NULL;
	uint8_t
		*ip6addr = NULL,
		*prefix = NULL,
		plen = 0;

	rlm_sql_row_t row = NULL;
	rlm_rcode_t rc = RLM_MODULE_OK;
	rlm_np_t *inst = (rlm_np_t *) instance;

	np_dbg("np_post_auth(): Started.");

	if(!inst->do_alloc_v4 && !inst->do_alloc_v6)
	{
		np_dbg("np_post_auth(): Neither IPv4 nor IPv6 address allocation is enabled.");
		return RLM_MODULE_NOOP;
	}

	if(!request->username || !request->username->vp_strvalue)
	{
		np_auth("np_post_auth(): Attribute 'User-Name' is required for post-auth processing.");
		return RLM_MODULE_INVALID;
	}
	if(!strlen(request->username->vp_strvalue))
	{
		np_err("np_post_auth(): Zero length username is not permitted.");
		return RLM_MODULE_INVALID;
	}
	np_dbg("np_post_auth(): Performing post-auth processing for user '%s'.", request->username->vp_strvalue);

	/* Get DB connection. */
	sqlsock = SQL_SOCK_GET(inst);
	if(sqlsock == NULL)
	{
		np_err("np_post_auth(): Error while requesting an SQL socket.");
		return RLM_MODULE_FAIL;
	}

	do_alloc = inst->do_alloc_v4;

	if(do_alloc)
	{
		np_dbg("np_post_auth(): Determining Framed-IP-Address for user '%s'.", request->username->vp_strvalue);

		if(fr_pair_find_by_num(request->reply->vps, PW_FRAMED_IP_ADDRESS, 0, TAG_ANY) != NULL)
		{
			np_dbg("np_post_auth(): Framed-IP-Address already exists, IPv4 address allocation disabled.");
			do_alloc = 0;
		}
	}

	subrc = np_get_nas_id(inst, sqlsock, request, &nas);
	if(subrc != 0)
	{
		if(nas != NULL)
			talloc_free(nas);
		return subrc;
	}
	if(nas == NULL)
	{
		SQL_SOCK_PUT(inst, sqlsock);
		return RLM_MODULE_FAIL;
	}

	/* Escape username for use in DB queries. */
	user_esc = np_escape(inst, sqlsock, request->username->vp_strvalue);
	if(user_esc == NULL)
	{
		SQL_SOCK_PUT(inst, sqlsock);
		talloc_free(nas);
		return RLM_MODULE_FAIL;
	}

	/* Allocate IPv4 address. */
	if(do_alloc)
	{
		if(np_select(inst, sqlsock, &row,
				"CALL acct_alloc_ip('%s', '%s')",
				nas, user_esc) == RLM_SQL_OK)
		{
			if(row != NULL)
			{
				if(row[0])
					ipaddrid = strtoul(row[0], (char **) NULL, 10);
				if(row[1])
					nasid = strtoul(row[1], (char **) NULL, 10);
			}
			else
				rc = RLM_MODULE_FAIL;
			np_select_finish(inst, sqlsock, &row);
		}
		else
			rc = RLM_MODULE_FAIL;
		if(rc != RLM_MODULE_OK)
		{
			SQL_SOCK_PUT(inst, sqlsock);
			talloc_free(user_esc);
			talloc_free(nas);
			np_err("np_post_auth(): Unable to allocate IPv4 address due to SQL error.");
			return rc;
		}

		if(nasid && ipaddrid)
		{
			np_dbg("np_post_auth(): Allocated IPv4 address ID %u on NAS ID %u for user '%s'.", ipaddrid, nasid, request->username->vp_strvalue);

			if(np_select(inst, sqlsock, &row,
					"SELECT (n.ipaddr + i.offset) ipaddr"
					" FROM ipaddr_def i LEFT JOIN nets_def n USING(netid)"
					" WHERE i.ipaddrid = %u",
					ipaddrid) == RLM_SQL_OK)
			{
				if(row && row[0])
				{
					ipaddr = strtoul(row[0], (char **) NULL, 10);
					if(ipaddr == 0)
						rc = RLM_MODULE_INVALID;
				}
				else
					rc = RLM_MODULE_FAIL;
				np_select_finish(inst, sqlsock, &row);
			}
			else
				rc = RLM_MODULE_FAIL;
			if(rc != RLM_MODULE_OK)
			{
				SQL_SOCK_PUT(inst, sqlsock);
				talloc_free(user_esc);
				talloc_free(nas);
				np_err("np_post_auth(): Unable to allocate IPv4 address due to invalid IPv4 address ID.");
				return rc;
			}

			vp = radius_pair_create(request->reply, &request->reply->vps, PW_FRAMED_IP_ADDRESS, 0);
			if(vp == NULL)
			{
				SQL_SOCK_PUT(inst, sqlsock);
				talloc_free(user_esc);
				talloc_free(nas);
				np_err("np_post_auth(): Error allocating memory for framed IP address A/V pair.");
				return RLM_MODULE_FAIL;
			}
			vp->vp_integer = htonl(ipaddr);
		}
		else
			np_info("np_post_auth(): No IPv4 address allocated for user '%s'.", request->username->vp_strvalue);
	}

	do_alloc = inst->do_alloc_v6;

	/* Allocate IPv6 address. */
	if(do_alloc)
	{
		if(np_select(inst, sqlsock, &row,
				"CALL acct_alloc_ipv6('%s', '%s')",
				nas, user_esc) == RLM_SQL_OK)
		{
			if(row != NULL)
			{
				if(row[0])
					ip6addrid = strtoull(row[0], (char **) NULL, 10);
				if(row[1])
					nasid = strtoul(row[1], (char **) NULL, 10);
				if(row[2])
				{
					prefix = talloc_array(inst, uint8_t, 16);
					if(prefix != NULL)
						memcpy(prefix, row[2], 16);
					else
						rc = RLM_MODULE_FAIL;
				}
				if(row[3])
					plen = strtoul(row[3], (char **) NULL, 10);
			}
			else
				rc = RLM_MODULE_FAIL;
			np_select_finish(inst, sqlsock, &row);
		}
		else
			rc = RLM_MODULE_FAIL;
		if(rc != RLM_MODULE_OK)
		{
			SQL_SOCK_PUT(inst, sqlsock);
			if(prefix != NULL)
				talloc_free(prefix);
			talloc_free(user_esc);
			talloc_free(nas);
			np_err("np_post_auth(): Unable to allocate IPv6 address due to SQL error.");
			return rc;
		}

		if(nasid && ip6addrid)
		{
			np_dbg("np_post_auth(): Offering IPv6 address ID %" PRIu64 " on NAS ID %u for user '%s'.", ip6addrid, nasid, request->username->vp_strvalue);

			if(np_select(inst, sqlsock, &row,
					"SELECT n.ip6addr ip6addr, i.offset offset"
					" FROM ip6addr_def i LEFT JOIN nets_def n USING(netid)"
					" WHERE i.ip6addrid = %" PRIu64,
					ip6addrid) == RLM_SQL_OK)
			{
				if(row)
				{
					if(row[0])
					{
						ip6addr = talloc_array(inst, uint8_t, 16);
						if(ip6addr != NULL)
							memcpy(ip6addr, row[0], 16);
						else
							rc = RLM_MODULE_FAIL;
					}
					else
						rc = RLM_MODULE_FAIL;
					if(row[1])
						ip6offset = strtoull(row[1], (char **) NULL, 10);

					if((ip6addr != NULL) && ip6offset)
					{
						uint8_t i = 15, carry = 0, oct, off_oct;

						do
						{
							oct = ip6addr[i];
							off_oct = (uint8_t) ((ip6offset >> ((15 - i) * 8)) % 256) + carry;
							oct += off_oct;
							if(oct < ip6addr[i])
								carry = 1;
							else if(carry && (off_oct == 0))
								carry = 1;
							else
								carry = 0;

							ip6addr[i] = oct;
							i--;
						}
						while(i > 0);
						if(carry)
							rc = RLM_MODULE_FAIL;
					}
				}
				else
					rc = RLM_MODULE_FAIL;
				np_select_finish(inst, sqlsock, &row);
			}
			else
				rc = RLM_MODULE_FAIL;
			if(rc != RLM_MODULE_OK)
			{
				SQL_SOCK_PUT(inst, sqlsock);
				if(ip6addr != NULL)
					talloc_free(ip6addr);
				if(prefix != NULL)
					talloc_free(prefix);
				talloc_free(user_esc);
				talloc_free(nas);
				np_err("np_post_auth(): Unable to allocate IPv4 address due to invalid IPv4 address ID.");
				return rc;
			}

			vp = radius_pair_create(request->reply, &request->reply->vps, PW_FRAMED_IPV6_PREFIX, 0);
			if(vp == NULL)
			{
				SQL_SOCK_PUT(inst, sqlsock);
				if(ip6addr != NULL)
					talloc_free(ip6addr);
				if(prefix != NULL)
					talloc_free(prefix);
				talloc_free(user_esc);
				talloc_free(nas);
				np_err("np_post_auth(): Error allocating memory for Framed-IPv6-Prefix A/V pair.");
				return RLM_MODULE_FAIL;
			}
			memcpy(vp->vp_ipv6prefix + 2, ip6addr, 16);
			vp->vp_ipv6prefix[1] = 128;
			vp->vp_ipv6prefix[0] = 0;
			vp->vp_length = 16 + 2;
		}
		else if((prefix != NULL) && (plen > 0))
		{
			np_dbg("np_post_auth(): Offering IPv6 pool prefix on NAS ID %u for user '%s'.", nasid, request->username->vp_strvalue);

			vp = radius_pair_create(request->reply, &request->reply->vps, PW_FRAMED_IPV6_PREFIX, 0);
			if(vp == NULL)
			{
				SQL_SOCK_PUT(inst, sqlsock);
				if(ip6addr != NULL)
					talloc_free(ip6addr);
				if(prefix != NULL)
					talloc_free(prefix);
				talloc_free(user_esc);
				talloc_free(nas);
				np_err("np_post_auth(): Error allocating memory for Framed-IPv6-Prefix A/V pair.");
				return RLM_MODULE_FAIL;
			}
			memcpy(vp->vp_ipv6prefix + 2, prefix, 16);
			vp->vp_ipv6prefix[1] = plen;
			vp->vp_ipv6prefix[0] = 0;
			vp->vp_length = 16 + 2;
		}
		else
			np_info("np_post_auth(): No IPv6 address allocated for user '%s'.", request->username->vp_strvalue);

		if(ip6addr != NULL)
			talloc_free(ip6addr);
		if(prefix != NULL)
			talloc_free(prefix);
	}

	SQL_SOCK_PUT(inst, sqlsock);
	talloc_free(user_esc);
	talloc_free(nas);

	if(nasid > 0)
	{
		vp = radius_pair_create(request->reply, &request->reply->vps, PW_NP_NAS_ID, VENDOR_NP);
		if(vp == NULL)
		{
			np_err("np_post_auth(): Error allocating memory for NP NAS ID A/V pair.");
			return RLM_MODULE_FAIL;
		}
		vp->vp_integer = nasid;
		np_dbg("np_post_auth(): Added NP NAS ID %u to reply items.", nasid);
	}

	return rc;
}

extern module_t rlm_np;
module_t rlm_np = {
	.magic       = RLM_MODULE_INIT,
	.name        = "np",
	.type        = RLM_TYPE_THREAD_SAFE,
	.inst_size   = sizeof(rlm_np_t),
	.config      = module_config,
	.instantiate = np_instantiate,
	.methods     = {
		[MOD_AUTHORIZE]  = np_authorize,
		[MOD_ACCOUNTING] = np_accounting,
		[MOD_POST_AUTH]  = np_post_auth
	}
};

