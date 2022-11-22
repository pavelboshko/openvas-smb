/*
   WMI Sample client

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
*/

#include "includes.h"
#include "lib/cmdline/popt_common.h"
#include "librpc/rpc/dcerpc.h"
#include "librpc/gen_ndr/ndr_oxidresolver.h"
#include "librpc/gen_ndr/ndr_oxidresolver_c.h"
#include "librpc/gen_ndr/ndr_dcom.h"
#include "librpc/gen_ndr/ndr_dcom_c.h"
#include "librpc/gen_ndr/ndr_remact_c.h"
#include "librpc/gen_ndr/ndr_epmapper_c.h"
#include "librpc/gen_ndr/com_dcom.h"
#include "librpc/rpc/dcerpc_table.h"

#include "lib/com/dcom/dcom.h"
#include "lib/com/proto.h"
#include "lib/com/dcom/proto.h"

#include "wmi/wmi.h"
#include <poll.h>
#include <pthread.h>
#include <cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define INFINITE_TIMEOUT (-1)

struct WBEMCLASS;
struct WBEMOBJECT;

#include "wmi/proto.h"

typedef struct program_args {
    char *hostname;
    char *ns;
} program_args;

#define MAX_DATA_SIZE 4096
typedef struct buffer_struct {
	char data[MAX_DATA_SIZE];
	int  offWritten;
} buffer_struct;

buffer_struct stdin_buffer = { 0 };
volatile sig_atomic_t terminate_flag = 0;

typedef struct query_struct {
	char text[MAX_DATA_SIZE];
	int timeout;
} query_struct;

query_struct query = { {}, .timeout = 1 };

static void parse_args(int argc, char *argv[], struct program_args *pmyargs)
{
    poptContext pc;
    int opt, i;

    int argc_new;
    char **argv_new;

    struct poptOption long_options[] = {
	POPT_AUTOHELP
	POPT_COMMON_SAMBA
	POPT_COMMON_CONNECTION
	POPT_COMMON_CREDENTIALS
	POPT_COMMON_VERSION
	{"namespace", 0, POPT_ARG_STRING, &pmyargs->ns, 0,
		 "WMI namespace, default to root\\cimv2", 0},
	POPT_TABLEEND
    };

    pc = poptGetContext("wmi", argc, (const char **) argv,
	        long_options, POPT_CONTEXT_KEEP_FIRST);

    poptSetOtherOptionHelp(pc, "//host query\n\nExample: wmic -U [domain/]adminuser%password //host");

    while ((opt = poptGetNextOpt(pc)) != -1) {
		poptPrintUsage(pc, stdout, 0);
		poptFreeContext(pc);
		exit(1);
    }

    argv_new = discard_const_p(char *, poptGetArgs(pc));

    argc_new = argc;
    for (i = 0; i < argc; i++) {
		if (argv_new[i] == NULL) {
			argc_new = i;
			break;
		}
    }

    if (argc_new != 2
	|| strncmp(argv_new[1], "//", 2) != 0) {
		poptPrintUsage(pc, stdout, 0);
		poptFreeContext(pc);
		exit(1);
    }

    /* skip over leading "//" in host name */
    pmyargs->hostname = argv_new[1] + 2;
    poptFreeContext(pc);
}

bool check_not_error(WERROR err)
{
	bool is_not_error = W_ERROR_IS_OK(err);
	if (!is_not_error)
	{
		NTSTATUS status = werror_to_ntstatus(err);
		fprintf(stderr, "NTSTATUS: %s - %s\n", nt_errstr(status), get_friendly_nt_error_msg(status));
	}
	return is_not_error;
}

#define CHK_ERROR   (-1)
#define CHK_NOTHING (0)
#define CHK_CANCEL  (1)
#define CHK_REQUEST (2)

int check_input(int timeout)
{
	struct pollfd poll_struct = {STDIN_FILENO, POLLIN|POLLPRI};
	int rc = CHK_NOTHING;
	if (poll(&poll_struct, 1, timeout) > 0)
	{
		int num_bytes = read(STDIN_FILENO, &stdin_buffer.data[stdin_buffer.offWritten],
							MAX_DATA_SIZE - stdin_buffer.offWritten);
		if (num_bytes < 0)
			return errno == EINTR ? CHK_NOTHING : CHK_ERROR;
		stdin_buffer.offWritten += num_bytes;
		char *eol = memchr(stdin_buffer.data, '\n', stdin_buffer.offWritten);
		if (!eol && stdin_buffer.offWritten < MAX_DATA_SIZE)
			return CHK_NOTHING;
		cJSON* request_json = cJSON_ParseWithLength(stdin_buffer.data, stdin_buffer.offWritten);
		if (eol)
		{
			size_t tail_size = stdin_buffer.offWritten + stdin_buffer.data - eol - 1;
			memmove(stdin_buffer.data, eol + 1, tail_size);
			stdin_buffer.offWritten = tail_size;
		}
		else
			stdin_buffer.offWritten = 0;
		if (request_json)
		{
			char *command = NULL;
			cJSON* command_json = cJSON_GetObjectItem(request_json, "command");
			if (command_json)
			{
				command = cJSON_GetStringValue(command_json);
				if (!strcmp(command, "cancel"))
					rc = CHK_CANCEL;
				else if (!strcmp(command, "request"))
				{
					cJSON* query_json = cJSON_GetObjectItem(request_json, "query");
					if (query_json)
					{
						char *query_str = cJSON_GetStringValue(query_json);
						size_t query_str_size = strlen(query_str);
						if (query_str_size > MAX_DATA_SIZE - 1)
							query_str_size = MAX_DATA_SIZE - 1;
						memcpy(query.text, query_str, query_str_size);
						query.text[query_str_size] = 0;

						cJSON* timeout_json = cJSON_GetObjectItem(request_json, "timeout");
						query.timeout = timeout_json ? cJSON_GetNumberValue(timeout_json) : 0;

						rc = CHK_REQUEST;
					}
					else
						query.text[0] = 0;
				}
			}
			cJSON_Delete(request_json);
		}
	}
	return rc;
}

#define WERR_CHECK(msg) if (!W_ERROR_IS_OK(result)) { \
			    DEBUG(0, ("ERROR: %s\n", msg)); \
			    goto error; \
			} else { \
			    DEBUG(1, ("OK   : %s\n", msg)); \
			}

#define RETURN_CVAR_ARRAY_STR(fmt, arr, type) {\
        uint32_t i;\
		char *r;\
\
        if (!arr) {\
                return talloc_strdup(mem_ctx, "NULL");\
        }\
		r = talloc_strdup(mem_ctx, "(");\
        for (i = 0; i < arr->count; ++i) {\
		r = talloc_asprintf_append(r, fmt "%s", (type)arr->item[i], (i+1 == arr->count)?"":",");\
        }\
        return talloc_asprintf_append(r, ")");\
}

#define CHECK_POINTER(ptr, msg) if (!ptr) { \
		DEBUG(0, ("%s: Out of memory\n", msg)); \
		rc = CHK_ERROR; \
		goto error; \
	}

#define ADD_FIELD_WITHOUT_VALUE_TO_JSON(str, stype) \
do { \
	cJSON *data = cJSON_AddObjectToObject(container_obj, name); \
	if (data) { \
		cJSON_AddStringToObject(data, "type", stype); \
		cJSON_AddStringToObject(data, "data", str); \
	} \
} while (0)

#define ADD_FIELD_TO_JSON(fmt, value, stype) \
do { \
	cJSON *data = cJSON_AddObjectToObject(container_obj, name); \
	if (data) { \
		cJSON_AddStringToObject(data, "type", stype); \
		char *s = talloc_asprintf(mem_ctx, fmt, value); \
		cJSON_AddStringToObject(data, "data", s); \
	} \
} while (0)

#define ADD_ARRAY_FIELD_TO_JSON(fmt, arr, type, stype) \
do { \
	uint32_t i; \
	cJSON *data = cJSON_AddObjectToObject(container_obj, name); \
	if (data) { \
		cJSON_AddStringToObject(data, "type", stype); \
		cJSON *value_array = cJSON_AddArrayToObject(data, "data"); \
		if (value_array && arr) { \
			for (i = 0; i < arr->count; ++i) { \
				char *s = talloc_asprintf(mem_ctx, fmt, (type)arr->item[i]); \
				cJSON *item = cJSON_CreateString(s); \
				cJSON_AddItemToArray(value_array, item); \
			} \
		} \
	} \
} while (0)

void CIMVAR_to_cJSON(TALLOC_CTX *mem_ctx, cJSON *container_obj, const char *name, union CIMVAR *v,
					 enum CIMTYPE_ENUMERATION cimtype)
{
	switch (cimtype) {
        case CIM_SINT8: ADD_FIELD_TO_JSON("%d", v->v_sint8, "int8"); break;
        case CIM_UINT8: ADD_FIELD_TO_JSON("%u", v->v_uint8, "uint8"); break;
        case CIM_SINT16: ADD_FIELD_TO_JSON("%d", v->v_sint16, "int16"); break;
        case CIM_UINT16: ADD_FIELD_TO_JSON("%u", v->v_uint16, "uint16"); break;
        case CIM_SINT32: ADD_FIELD_TO_JSON("%d", v->v_sint32, "int32"); break;
        case CIM_UINT32: ADD_FIELD_TO_JSON("%u", v->v_uint32, "uint32"); break;
        case CIM_SINT64: ADD_FIELD_TO_JSON("%ld", v->v_sint64, "int64"); break;
        case CIM_UINT64: ADD_FIELD_TO_JSON("%lu", v->v_uint64, "uint64"); break;
        case CIM_REAL32: ADD_FIELD_TO_JSON("%f", (double)v->v_uint32, "double"); break;
        case CIM_REAL64: ADD_FIELD_TO_JSON("%f", (double)v->v_uint64, "double"); break;
        case CIM_BOOLEAN: ADD_FIELD_TO_JSON("%d", v->v_boolean, "bool"); break;
        case CIM_STRING: ADD_FIELD_TO_JSON("%s", v->v_string, "string"); break;
        case CIM_DATETIME: ADD_FIELD_TO_JSON("%s", v->v_string, "datetime"); break;
        case CIM_REFERENCE: ADD_FIELD_TO_JSON("%s", v->v_string, "reference"); break;
        case CIM_CHAR16: ADD_FIELD_WITHOUT_VALUE_TO_JSON("Unsupported", "char16"); break;
        case CIM_OBJECT: ADD_FIELD_WITHOUT_VALUE_TO_JSON("Unsupported", "object"); break;
        case CIM_ARR_SINT8: ADD_ARRAY_FIELD_TO_JSON("%d", v->a_sint8, int8_t, "int8"); break;
        case CIM_ARR_UINT8: ADD_ARRAY_FIELD_TO_JSON("%u", v->a_uint8, uint8_t, "uint8"); break;
        case CIM_ARR_SINT16: ADD_ARRAY_FIELD_TO_JSON("%d", v->a_sint16, int16_t, "int16"); break;
        case CIM_ARR_UINT16: ADD_ARRAY_FIELD_TO_JSON("%u", v->a_uint16, uint16_t, "uint16"); break;
        case CIM_ARR_SINT32: ADD_ARRAY_FIELD_TO_JSON("%d", v->a_sint32, int32_t, "int32"); break;
        case CIM_ARR_UINT32: ADD_ARRAY_FIELD_TO_JSON("%u", v->a_uint32, uint32_t, "uint32"); break;
        case CIM_ARR_SINT64: ADD_ARRAY_FIELD_TO_JSON("%ld", v->a_sint64, int64_t, "int64"); break;
        case CIM_ARR_UINT64: ADD_ARRAY_FIELD_TO_JSON("%lu", v->a_uint64, uint64_t, "uint64"); break;
        case CIM_ARR_REAL32: ADD_ARRAY_FIELD_TO_JSON("%f", v->a_real32, double, "double"); break;
        case CIM_ARR_REAL64: ADD_ARRAY_FIELD_TO_JSON("%f", v->a_real64, double, "double"); break;
        case CIM_ARR_BOOLEAN: ADD_ARRAY_FIELD_TO_JSON("%d", v->a_boolean, uint16_t, "bool"); break;
        case CIM_ARR_STRING: ADD_ARRAY_FIELD_TO_JSON("%s", v->a_string, const char *, "string"); break;
        case CIM_ARR_DATETIME: ADD_ARRAY_FIELD_TO_JSON("%s", v->a_datetime, const char *, "datetime"); break;
        case CIM_ARR_REFERENCE: ADD_ARRAY_FIELD_TO_JSON("%s", v->a_reference, const char *, "reference"); break;
	default: ADD_FIELD_WITHOUT_VALUE_TO_JSON("Unsupported", "unknown");
	}
}

#undef RETURN_CVAR_ARRAY_STR

int print_json(struct IWbemServices *pWS, struct IEnumWbemClassObject *pEnum, TALLOC_CTX *mem_ctx, struct timeval* timestamp)
{
	uint32_t cnt = 5, ret;
	int rc = CHK_NOTHING;
	cJSON *class_obj = NULL;
	do {
		uint32_t i, j;
		struct WbemClassObject *co[cnt];

		WERROR result = IEnumWbemClassObject_SmartNext(pEnum, mem_ctx, 0xFFFFFFFF, cnt, co, &ret);
		/* WERR_BADFUNC is OK, it means only that there is less returned objects than requested */
		if (!W_ERROR_EQUAL(result, WERR_BADFUNC)) {
			if (!check_not_error(result))
				return CHK_ERROR;
		} else {
			DEBUG(1, ("OK   : Retrieved less objects than requested (it is normal).\n"));
		}
		if (!ret) break;

		for (i = 0; i < ret; ++i) {
			class_obj = cJSON_CreateObject();
			CHECK_POINTER(class_obj, "Class object");
			CHECK_POINTER(cJSON_AddStringToObject(class_obj, "__CLASS", co[i]->obj_class->__CLASS),
							"Class name");
			cJSON *derivation_array = cJSON_AddArrayToObject(class_obj, "__DERIVATION");
			CHECK_POINTER(derivation_array, "Class derivation");
			for (j = 0; j < co[i]->obj_class->__DERIVATION.count; ++j) {
				cJSON *item = cJSON_CreateString(co[i]->obj_class->__DERIVATION.item[j]);
				cJSON_AddItemToArray(derivation_array, item);
			}
			CHECK_POINTER(cJSON_AddStringToObject(class_obj, "__SERVER", co[i]->__SERVER),
							"Server name");
			CHECK_POINTER(cJSON_AddStringToObject(class_obj, "__NAMESPACE", co[i]->__NAMESPACE),
							"Namespace");
			CHECK_POINTER(cJSON_AddNumberToObject(class_obj, "__PROPERTY_COUNT", co[i]->obj_class->__PROPERTY_COUNT),
							"Property count");
			cJSON *properties = cJSON_AddObjectToObject(class_obj, "Properties");
			CHECK_POINTER(properties, "Properties");
			for (j = 0; j < co[i]->obj_class->__PROPERTY_COUNT; ++j)
				CIMVAR_to_cJSON(mem_ctx, properties, co[i]->obj_class->properties[j].name, &co[i]->instance->data[j],
								co[i]->obj_class->properties[j].desc->cimtype & CIM_TYPEMASK);

			/*char *s = cJSON_Print(class_obj); */
			char *s = cJSON_PrintUnformatted(class_obj);
			fprintf(stdout, "%s\n", s);
			fflush(stdout);
			free(s);
			cJSON_Delete(class_obj);
			class_obj = NULL;
		}
		rc = check_input(0);
		if (rc != CHK_NOTHING || timeval_expired(timestamp))
			break;

	} while (ret == cnt);

error:
	if (class_obj)
		cJSON_Delete(class_obj);
	return rc;
}

void interrupt_handler(int signal_num) {

	if(signal_num == SIGINT || signal_num == SIGQUIT) { // handle Ctrl-C
		// if not reset since last call, exit
		if (terminate_flag > 0)
			exit(EXIT_FAILURE);
		++terminate_flag;
	}
}

int main(int argc, char **argv)
{
	program_args args = {};
	NTSTATUS status;
	struct IWbemServices *pWS = NULL;

	struct sigaction sigIntHandler;

	sigIntHandler.sa_handler = interrupt_handler;
	sigemptyset(&sigIntHandler.sa_mask);
	sigIntHandler.sa_flags = 0;

	sigaction(SIGINT, &sigIntHandler, NULL);
	sigaction(SIGQUIT, &sigIntHandler, NULL);

    parse_args(argc, argv, &args);

	/* apply default values if not given by user*/
	if (!args.ns) args.ns = "root\\cimv2";

	dcerpc_init();
	dcerpc_table_init();

	dcom_proxy_IUnknown_init();
	dcom_proxy_IWbemLevel1Login_init();
	dcom_proxy_IWbemServices_init();
	dcom_proxy_IWbemClassObject_init();
	dcom_proxy_IEnumWbemClassObject_init();
	dcom_proxy_IRemUnknown_init();
	dcom_proxy_IWbemFetchSmartEnum_init();
	dcom_proxy_IWbemWCOSmartEnum_init();


	struct com_context *ctx = NULL;
	com_init_ctx(&ctx, NULL);
	dcom_client_init(ctx, cmdline_credentials);

	if (!check_not_error(WBEM_ConnectServer(ctx, args.hostname, args.ns, 0, 0, 0, 0, 0, 0, &pWS)))
	{
		talloc_free(ctx);
		return 1;
	}
	fprintf(stdout, "Connected\n");
	fflush(stdout);

	int rc = CHK_NOTHING;
	while (!terminate_flag)
	{
		if (rc != CHK_REQUEST || query.text[0] == 0)
			rc = check_input(INFINITE_TIMEOUT);
		if (rc < 0)
			break;
		if (rc == CHK_REQUEST)
		{
			if (query.timeout < 1)
				query.timeout = 1;

			struct timeval timestamp_orig = timeval_current();
			struct timeval timestamp = timeval_add(&timestamp_orig, query.timeout, 0);  /* timeval_current_ofs(query.timeout, 0); */
			struct IEnumWbemClassObject *pEnum = NULL;
			WERROR result = IWbemServices_ExecQuery(pWS, ctx, "WQL", query.text,
					WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_ENSURE_LOCATABLE,
					NULL, &pEnum);
			if (check_not_error(result) && !timeval_expired(&timestamp))
			{
				result = IEnumWbemClassObject_Reset(pEnum, ctx);
				if (check_not_error(result) && !timeval_expired(&timestamp))
				{
					rc = print_json(pWS, pEnum, ctx, &timestamp);
					if (rc == CHK_ERROR)
						break;
				}
			}
			if (!W_ERROR_IS_OK(result))
				break;

			fprintf(stdout, "\n");
			fflush(stdout);
		}
	}
	talloc_free(ctx);
	return rc == CHK_ERROR ? 1 : 0;
}
