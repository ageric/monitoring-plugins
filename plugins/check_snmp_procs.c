/**
 * Check system load over snmp
 */
#include "common.h"
#include "utils.h"
#include "utils_snmp.h"
//#include "bitmap.h"

#define PROCESS_TABLE "1.3.6.1.2.1.25.4.2.1"
#define PROCESS_SUBIDX_RunIndex 1
#define PROCESS_SUBIDX_RunName 2
#define PROCESS_SUBIDX_RunID 3 /* we don't use this */
#define PROCESS_SUBIDX_RunPath 4
#define PROCESS_SUBIDX_RunParameters 5
#define PROCESS_SUBIDX_RunType 6
#define PROCESS_SUBIDX_RunStatus 7

#define PROCPERF_TABLE "1.3.6.1.2.1.25.5.1.1"
#define PROCPERF_SUBIDX_RunPerfCPU 1
#define PROCPERF_SUBIDX_RunPerfMem 2

enum process_state {
	PROC_STATE_RUNNING = 1,
	PROC_STATE_RUNNABLE = 2,
	PROC_STATE_NOTRUNNABLE = 3,
	PROC_STATE_INVALID = 4,
};

struct process_state_count {
	int running, runnable, notrunnable, invalid;
};

static thresholds *thresh;

struct proc_info {
	int Index;
	char *Name;
	int ID;
	char *Path;
	char *Parameters;
	int Type;
	enum process_state Status;
	struct {
		int CPU;
		int Mem;
	} Perf;
};

static const char *pstate2str(enum process_state pstate)
{
	switch (pstate) {
		case PROC_STATE_RUNNING: return "running";
		case PROC_STATE_RUNNABLE: return "runnable";
		case PROC_STATE_NOTRUNNABLE: return "not runnable";
		case PROC_STATE_INVALID: return "zombie";
	}
	return "(unknown)";
}

static int procs;

static int pstate_callback(netsnmp_variable_list *v, void *psc_ptr, void *discard)
{
	procs++;
	struct process_state_count *psc = (struct process_state_count *)psc_ptr;

	switch (*v->val.integer) {
		case PROC_STATE_RUNNING:
			psc->running++;
			break;
		case PROC_STATE_RUNNABLE:
			psc->runnable++;
			break;
		case PROC_STATE_NOTRUNNABLE:
			psc->notrunnable++;
			break;
		case PROC_STATE_INVALID:
			psc->invalid++;
			break;
	}
}

static int check_proc_states(mp_snmp_context *ss, int statemask)
{
	int i;
	struct process_state_count pstate_count;

	memset(&pstate_count, 0, sizeof(pstate_count));
	mp_snmp_walk(ss, PROCESS_TABLE ".7", pstate_callback, &pstate_count, NULL);
	printf("Processes: running=%d, runnable=%d, not runnable=%d, invalid=%d\n",
	      pstate_count.running, pstate_count.runnable, pstate_count.notrunnable, pstate_count.invalid);
}

static int walker_print_name(netsnmp_variable_list *v, void *discard_, void *discard)
{
	int c;
	if (!v->val.string || v->val_len <= 0 || !*v->val.string)
		return 0;
	c = v->val.string[v->val_len];
	v->val.string[v->val_len] = 0;
	printf("%s\n", v->val.string);
	v->val.string[v->val_len] = c;
	procs++;
	return 0;
}

static int check_proc_names(mp_snmp_context *c)
{
	mp_snmp_walk(c, PROCESS_TABLE ".4", walker_print_name, NULL, NULL);
}

static struct proc_info *query_process(mp_snmp_context *ctx, int k)
{
	netsnmp_pdu *pdu, *response = NULL;
	netsnmp_variable_list *v;
	int mask;
	struct proc_info *p;
	int error = 0, count = 0;

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	if (!pdu) {
		return NULL;
	}

	MP_SNMP_PDU_MASK_ADD(mask, PROCESS_SUBIDX_RunStatus);
	MP_SNMP_PDU_MASK_ADD(mask, PROCESS_SUBIDX_RunName);
	MP_SNMP_PDU_MASK_ADD(mask, PROCESS_SUBIDX_RunParameters);
	MP_SNMP_PDU_MASK_ADD(mask, PROCESS_SUBIDX_RunPath);
	mp_snmp_add_keyed_subtree(pdu, PROCESS_TABLE, mask, k);
	mask = 0;
	MP_SNMP_PDU_MASK_ADD(mask, PROCPERF_SUBIDX_RunPerfCPU);
	MP_SNMP_PDU_MASK_ADD(mask, PROCPERF_SUBIDX_RunPerfMem);
	mp_snmp_add_keyed_subtree(pdu, PROCPERF_TABLE, mask, k);
	if (mp_snmp_query(ctx, pdu, &response)) {
		die(STATE_UNKNOWN, _("Failed to fetch variables for process %d\n"), k);
	}
	if (!(p = calloc(1, sizeof(*p)))) {
		snmp_free_pdu(response);
		snmp_free_pdu(pdu);
		die(STATE_UNKNOWN, _("Failed to allocate memory"));
	}

	for (v = response->variables; v; v = v->next_variable, count++) {
		int is_perf;
		if (!mp_snmp_is_valid_var(v)) {
			error++;
			continue;
		}
		if (v->name[7] == 5) {
			/* procperf table */
			if (v->name[10] == PROCPERF_SUBIDX_RunPerfCPU) {
				p->Perf.CPU = 1 + *v->val.integer;
			} else if (v->name[10] == PROCPERF_SUBIDX_RunPerfMem) {
				p->Perf.Mem = 1 + *v->val.integer;
			}
			continue;
		}
		switch (v->name[10]) {
			case PROCESS_SUBIDX_RunID:
				p->ID = *v->val.integer;
				break;
			case PROCESS_SUBIDX_RunIndex:
				p->Index = *v->val.integer;
				break;
			case PROCESS_SUBIDX_RunName:
				p->Name = strndup(v->val.string, v->val_len);
				break;
			case PROCESS_SUBIDX_RunParameters:
				p->Parameters = strndup(v->val.string, v->val_len);
				break;
			case PROCESS_SUBIDX_RunPath:
				p->Path = strndup(v->val.string, v->val_len);
				break;
			case PROCESS_SUBIDX_RunStatus:
				p->Status = *v->val.integer;
				break;
		}
	}
	printf("count: %d\n", count);
	snmp_free_pdu(response);
	return p;
}

static void print_proc_info(struct proc_info *p)
{
	printf("CPU: %d\n", p->Perf.CPU);
	printf("Mem: %d\n", p->Perf.Mem);
	printf("Name: %s\n", p->Name);
	printf("Path: %s\n", p->Path);
	printf("Status: %d\n", p->Status);
	printf("Parameters: %s\n", p->Parameters);
}

static void destroy_proc_info(struct proc_info *p)
{
	free(p->Name);
	free(p->Parameters);
	free(p->Path);
	free(p);
}

int main(int argc, char **argv)
{
	int i, x;
	int c, err, option;
	netsnmp_session session, *ss;
	mp_snmp_context *ctx;
	struct proc_info *p;
	char *optary;
	char *warn_str = NULL, *crit_str = NULL;
	char *state_str;

	static struct option longopts[] = {
		{"timeout", required_argument, 0, 't'},
		{"warning", required_argument, 0, 'w'},
		{"critical", required_argument, 0, 'c'},
		{"state", required_argument, 0, 's'},
		{"host", required_argument, 0, 'H'},
		MP_SNMP_LONGOPTS,
		{NULL, 0, 0, 0},
	};

	optary = calloc(3, ARRAY_SIZE(longopts));
	i = 0;
	optary[i++] = '+';
	optary[i++] = '?';
	for (x = 0; longopts[x].name; x++) {
		struct option *o = &longopts[x];
		if (o->val >= CHAR_MAX || o->val <= 0) {
			continue;
		}
#if 0
		if (bitmap_isset(bm, o->val)) {
			printf("###############################\n##### DOUBLE OPTION YOU DOOFUS!\n#########################\n");
			exit(1);
		}
		bitmap_set(bm, o->val);
#endif
		if (o->val < CHAR_MAX)
			optary[i++] = o->val;
		if (o->has_arg)
			optary[i++] = ':';
		if (o->has_arg == optional_argument)
			optary[i++] = ':';
	}

	printf("optary: %s\n", optary);
	mp_snmp_init("check_snmp_procs", 0);
	ctx = mp_snmp_create_context();

	while (1) {
		c = getopt_long(argc, argv, optary, longopts, &option);
		if (c < 0 || c == EOF)
			break;

		if (!mp_snmp_handle_argument(ctx, c, optarg)) {
			continue;
		}

		switch (c) {
		case 'c':
			crit_str = optarg;
			break;
		case 'w':
			warn_str = optarg;
			break;
		case 's':
			state_str = optarg;
		}
	}
	free(optary);

	set_thresholds(&thresh, warn_str, crit_str);

	mp_snmp_finalize_auth(ctx);
	if (1) {
		p = query_process(ctx, 1);
		print_proc_info(p);
		destroy_proc_info(p);
	}
	if (1) {
		check_proc_names(ctx);
		printf("procs: %d\n", procs);
	}
	procs = 0;
	if (1) {
		check_proc_states(ctx, ~0);
		printf("procs: %d\n", procs);
	}
	mp_snmp_deinit("check_snmp_procs");

	return 0;
}
