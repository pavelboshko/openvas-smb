/*
   WMI Sample client
   Copyright (C) 2006 Andrzej Hajda <andrzej.hajda@wp.pl>

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
#include <cJSON.h>

struct WBEMCLASS;
struct WBEMOBJECT;

#include "wmi/proto.h"

struct program_args {
    char *hostname;
    char *query;
    char *ns;
    char *delim;
	int   print_json;
};

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
	{"delimiter", 0, POPT_ARG_STRING, &pmyargs->delim, 0,
		 "delimiter to use when querying multiple values, default to '|'", 0},
	{"json", 'J', POPT_ARG_NONE, &pmyargs->print_json, 0, "print result in JSON format", 0},
	POPT_TABLEEND
    };

    pc = poptGetContext("wmi", argc, (const char **) argv,
	        long_options, POPT_CONTEXT_KEEP_FIRST);

    poptSetOtherOptionHelp(pc, "//host query\n\nExample: wmic -U [domain/]adminuser%password //host \"select * from Win32_ComputerSystem\"");

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

    if (argc_new != 3
	|| strncmp(argv_new[1], "//", 2) != 0) {
	poptPrintUsage(pc, stdout, 0);
	poptFreeContext(pc);
	exit(1);
    }

    /* skip over leading "//" in host name */
    pmyargs->hostname = argv_new[1] + 2;
    pmyargs->query = argv_new[2];
    poptFreeContext(pc);
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

char *string_CIMVAR(TALLOC_CTX *mem_ctx, union CIMVAR *v, enum CIMTYPE_ENUMERATION cimtype)
{
	switch (cimtype) {
        case CIM_SINT8: return talloc_asprintf(mem_ctx, "%d", v->v_sint8);
        case CIM_UINT8: return talloc_asprintf(mem_ctx, "%u", v->v_uint8);
        case CIM_SINT16: return talloc_asprintf(mem_ctx, "%d", v->v_sint16);
        case CIM_UINT16: return talloc_asprintf(mem_ctx, "%u", v->v_uint16);
        case CIM_SINT32: return talloc_asprintf(mem_ctx, "%d", v->v_sint32);
        case CIM_UINT32: return talloc_asprintf(mem_ctx, "%u", v->v_uint32);
        case CIM_SINT64: return talloc_asprintf(mem_ctx, "%ld", v->v_sint64);
        case CIM_UINT64: return talloc_asprintf(mem_ctx, "%lu", v->v_uint64);
        case CIM_REAL32: return talloc_asprintf(mem_ctx, "%f", (double)v->v_uint32);
        case CIM_REAL64: return talloc_asprintf(mem_ctx, "%f", (double)v->v_uint64);
        case CIM_BOOLEAN: return talloc_asprintf(mem_ctx, "%d", v->v_boolean);
        case CIM_STRING:
        case CIM_DATETIME:
        case CIM_REFERENCE: return talloc_asprintf(mem_ctx, "%s", v->v_string);
        case CIM_CHAR16: return talloc_asprintf(mem_ctx, "Unsupported");
        case CIM_OBJECT: return talloc_asprintf(mem_ctx, "Unsupported");
        case CIM_ARR_SINT8: RETURN_CVAR_ARRAY_STR("%d", v->a_sint8, int8_t);
        case CIM_ARR_UINT8: RETURN_CVAR_ARRAY_STR("%u", v->a_uint8, uint8_t);
        case CIM_ARR_SINT16: RETURN_CVAR_ARRAY_STR("%d", v->a_sint16, int16_t);
        case CIM_ARR_UINT16: RETURN_CVAR_ARRAY_STR("%u", v->a_uint16, uint16_t);
        case CIM_ARR_SINT32: RETURN_CVAR_ARRAY_STR("%d", v->a_sint32, int32_t);
        case CIM_ARR_UINT32: RETURN_CVAR_ARRAY_STR("%u", v->a_uint32, uint32_t);
        case CIM_ARR_SINT64: RETURN_CVAR_ARRAY_STR("%ld", v->a_sint64, int64_t);
        case CIM_ARR_UINT64: RETURN_CVAR_ARRAY_STR("%lu", v->a_uint64, uint64_t);
        case CIM_ARR_REAL32: RETURN_CVAR_ARRAY_STR("%f", v->a_real32, double);
        case CIM_ARR_REAL64: RETURN_CVAR_ARRAY_STR("%f", v->a_real64, double);
        case CIM_ARR_BOOLEAN: RETURN_CVAR_ARRAY_STR("%d", v->a_boolean, uint16_t);
        case CIM_ARR_STRING: RETURN_CVAR_ARRAY_STR("%s", v->a_string, const char * );
        case CIM_ARR_DATETIME: RETURN_CVAR_ARRAY_STR("%s", v->a_datetime, const char *);
        case CIM_ARR_REFERENCE: RETURN_CVAR_ARRAY_STR("%s", v->a_reference, const char *);
	default: return talloc_asprintf(mem_ctx, "Unsupported");
	}
}

#define CHECK_POINTER(ptr, msg) if (!ptr) { \
		DEBUG(0, ("%s: Out of memory\n", msg)); \
		goto memory_error; \
	}

#define ADD_FIELD_WITHOUT_VALUE_TO_JSON(str) \
do { \
	cJSON *data = cJSON_AddObjectToObject(container_obj, name); \
	if (data) { \
		cJSON_AddNumberToObject(data, "type", (uint32_t)cimtype); \
		cJSON_AddStringToObject(data, "value", str); \
	} \
} while (0)

#define ADD_FIELD_TO_JSON(fmt, value) \
do { \
	cJSON *data = cJSON_AddObjectToObject(container_obj, name); \
	if (data) { \
		cJSON_AddNumberToObject(data, "type", (uint32_t)cimtype); \
		char *s = talloc_asprintf(mem_ctx, fmt, value); \
		cJSON_AddStringToObject(data, "value", s); \
	} \
} while (0)

#define ADD_ARRAY_FIELD_TO_JSON(fmt, arr, type) \
do { \
	uint32_t i; \
	cJSON *data = cJSON_AddObjectToObject(container_obj, name); \
	if (data) { \
		cJSON_AddNumberToObject(data, "type", (uint32_t)cimtype); \
		cJSON *value_array = cJSON_AddArrayToObject(data, "values"); \
		if (value_array && arr) { \
			for (i = 0; i < arr->count; ++i) { \
				char *s = talloc_asprintf(mem_ctx, fmt, (type)arr->item[i]); \
				cJSON *item = cJSON_CreateString(s); \
				cJSON_AddItemToArray(data, item); \
			} \
		} \
	} \
} while (0)

void CIMVAR_to_cJSON(TALLOC_CTX *mem_ctx, cJSON *container_obj, const char *name, union CIMVAR *v,
					 enum CIMTYPE_ENUMERATION cimtype)
{
	switch (cimtype) {
        case CIM_SINT8: ADD_FIELD_TO_JSON("%d", v->v_sint8); break;
        case CIM_UINT8: ADD_FIELD_TO_JSON("%u", v->v_uint8); break;
        case CIM_SINT16: ADD_FIELD_TO_JSON("%d", v->v_sint16); break;
        case CIM_UINT16: ADD_FIELD_TO_JSON("%u", v->v_uint16); break;
        case CIM_SINT32: ADD_FIELD_TO_JSON("%d", v->v_sint32); break;
        case CIM_UINT32: ADD_FIELD_TO_JSON("%u", v->v_uint32); break;
        case CIM_SINT64: ADD_FIELD_TO_JSON("%ld", v->v_sint64); break;
        case CIM_UINT64: ADD_FIELD_TO_JSON("%lu", v->v_uint64); break;
        case CIM_REAL32: ADD_FIELD_TO_JSON("%f", (double)v->v_uint32); break;
        case CIM_REAL64: ADD_FIELD_TO_JSON("%f", (double)v->v_uint64); break;
        case CIM_BOOLEAN: ADD_FIELD_TO_JSON("%d", v->v_boolean); break;
        case CIM_STRING:
        case CIM_DATETIME:
        case CIM_REFERENCE: ADD_FIELD_TO_JSON("%s", v->v_string); break;
        case CIM_CHAR16: ADD_FIELD_WITHOUT_VALUE_TO_JSON("Unsupported"); break;
        case CIM_OBJECT: ADD_FIELD_WITHOUT_VALUE_TO_JSON("Unsupported"); break;
        case CIM_ARR_SINT8: ADD_ARRAY_FIELD_TO_JSON("%d", v->a_sint8, int8_t); break;
        case CIM_ARR_UINT8: ADD_ARRAY_FIELD_TO_JSON("%u", v->a_uint8, uint8_t); break;
        case CIM_ARR_SINT16: ADD_ARRAY_FIELD_TO_JSON("%d", v->a_sint16, int16_t); break;
        case CIM_ARR_UINT16: ADD_ARRAY_FIELD_TO_JSON("%u", v->a_uint16, uint16_t); break;
        case CIM_ARR_SINT32: ADD_ARRAY_FIELD_TO_JSON("%d", v->a_sint32, int32_t); break;
        case CIM_ARR_UINT32: ADD_ARRAY_FIELD_TO_JSON("%u", v->a_uint32, uint32_t); break;
        case CIM_ARR_SINT64: ADD_ARRAY_FIELD_TO_JSON("%ld", v->a_sint64, int64_t); break;
        case CIM_ARR_UINT64: ADD_ARRAY_FIELD_TO_JSON("%lu", v->a_uint64, uint64_t); break;
        case CIM_ARR_REAL32: ADD_ARRAY_FIELD_TO_JSON("%f", v->a_real32, double); break;
        case CIM_ARR_REAL64: ADD_ARRAY_FIELD_TO_JSON("%f", v->a_real64, double); break;
        case CIM_ARR_BOOLEAN: ADD_ARRAY_FIELD_TO_JSON("%d", v->a_boolean, uint16_t); break;
        case CIM_ARR_STRING: ADD_ARRAY_FIELD_TO_JSON("%s", v->a_string, const char *); break;
        case CIM_ARR_DATETIME: ADD_ARRAY_FIELD_TO_JSON("%s", v->a_datetime, const char *); break;
        case CIM_ARR_REFERENCE: ADD_ARRAY_FIELD_TO_JSON("%s", v->a_reference, const char *); break;
	default: ADD_FIELD_WITHOUT_VALUE_TO_JSON("Unsupported");
	}
}

#undef RETURN_CVAR_ARRAY_STR

int main(int argc, char **argv)
{
	struct program_args args = {};
	uint32_t cnt = 5, ret;
	char *class_name = NULL;
	WERROR result;
	NTSTATUS status;
	struct IWbemServices *pWS = NULL;
	cJSON *root_obj = NULL;
	cJSON *array_of_classes = NULL;
	cJSON *class_obj = NULL;
	cJSON *class_data = NULL;

    parse_args(argc, argv, &args);

	/* apply default values if not given by user*/
	if (!args.ns) args.ns = "root\\cimv2";
	if (!args.delim) args.delim = "|";

	dcerpc_init();
	dcerpc_table_init();

	dcom_proxy_IUnknown_init();
	dcom_proxy_IWbemLevel1Login_init();
	dcom_proxy_IWbemServices_init();
	dcom_proxy_IEnumWbemClassObject_init();
	dcom_proxy_IRemUnknown_init();
	dcom_proxy_IWbemFetchSmartEnum_init();
	dcom_proxy_IWbemWCOSmartEnum_init();

	struct com_context *ctx = NULL;
	com_init_ctx(&ctx, NULL);
	dcom_client_init(ctx, cmdline_credentials);

	result = WBEM_ConnectServer(ctx, args.hostname, args.ns, 0, 0, 0, 0, 0, 0, &pWS);
	WERR_CHECK("Login to remote object.");

	struct IEnumWbemClassObject *pEnum = NULL;
	result = IWbemServices_ExecQuery(pWS, ctx, "WQL", args.query, WBEM_FLAG_RETURN_IMMEDIATELY | WBEM_FLAG_ENSURE_LOCATABLE, NULL, &pEnum);
	WERR_CHECK("WMI query execute.");

	IEnumWbemClassObject_Reset(pEnum, ctx);
	WERR_CHECK("Reset result of WMI query.");

	if (args.print_json)
	{
		root_obj = cJSON_CreateObject();
		CHECK_POINTER(root_obj, "Root json object");

		array_of_classes = cJSON_AddArrayToObject(root_obj, "classes");
		CHECK_POINTER(root_obj, "Json array of classes");
	}

	do {
		uint32_t i, j;
		struct WbemClassObject *co[cnt];

		result = IEnumWbemClassObject_SmartNext(pEnum, ctx, 0xFFFFFFFF, cnt, co, &ret);
		/* WERR_BADFUNC is OK, it means only that there is less returned objects than requested */
		if (!W_ERROR_EQUAL(result, WERR_BADFUNC)) {
			WERR_CHECK("Retrieve result data.");
		} else {
			DEBUG(1, ("OK   : Retrieved less objects than requested (it is normal).\n"));
		}
		if (!ret) break;

		if (args.print_json) {
			for (i = 0; i < ret; ++i) {
				if (   !class_obj
				    ||  strcmp(co[i]->obj_class->__CLASS,
						   	   cJSON_GetStringValue(cJSON_GetObjectItem(class_obj, "class")))) {
					class_obj = cJSON_CreateObject();
					CHECK_POINTER(class_obj, "Class json object");
					cJSON_AddItemToArray(array_of_classes, class_obj);
					CHECK_POINTER(cJSON_AddStringToObject(class_obj, "class", co[i]->obj_class->__CLASS),
								  "Json class name");
					class_data = cJSON_AddArrayToObject(class_obj, "data");
					CHECK_POINTER(class_data, "Json class data");
				}
				cJSON *data_obj = cJSON_CreateObject();
				CHECK_POINTER(data_obj, "Json data object");
				cJSON_AddItemToArray(class_data, data_obj);
				for (j = 0; j < co[i]->obj_class->__PROPERTY_COUNT; ++j) {
					CIMVAR_to_cJSON(ctx, data_obj, co[i]->obj_class->properties[j].name, &co[i]->instance->data[j],
									co[i]->obj_class->properties[j].desc->cimtype & CIM_TYPEMASK);
				}
			}
		} else {
			for (i = 0; i < ret; ++i) {
				if (!class_name || strcmp(co[i]->obj_class->__CLASS, class_name)) {
					if (class_name) talloc_free(class_name);
					class_name = talloc_strdup(ctx, co[i]->obj_class->__CLASS);
					printf("CLASS: %s\n", class_name);
					for (j = 0; j < co[i]->obj_class->__PROPERTY_COUNT; ++j)
						printf("%s%s", j?args.delim:"", co[i]->obj_class->properties[j].name);
					printf("\n");
				}
				for (j = 0; j < co[i]->obj_class->__PROPERTY_COUNT; ++j) {
					char *s;
					s = string_CIMVAR(ctx, &co[i]->instance->data[j], co[i]->obj_class->properties[j].desc->cimtype & CIM_TYPEMASK);
					printf("%s%s", j?args.delim:"", s);
				}
				printf("\n");
			}
		}
	} while (ret == cnt);

	if (args.print_json) {
		/* char *s = cJSON_Print(root_obj); */
		char *s = cJSON_PrintUnformatted(root_obj);
		printf("%s\n", s);
		free(s);
	}
	if (root_obj)
		cJSON_Delete(root_obj);
	talloc_free(ctx);
	return 0;
error:
	status = werror_to_ntstatus(result);
	fprintf(stderr, "NTSTATUS: %s - %s\n", nt_errstr(status), get_friendly_nt_error_msg(status));
	talloc_free(ctx);
	return 1;
memory_error:
	if (root_obj)
		cJSON_Delete(root_obj);
	talloc_free(ctx);
	return 2;
}
