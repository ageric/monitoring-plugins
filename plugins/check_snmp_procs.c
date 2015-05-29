/**
 * Check system load over snmp
 */
#include "common.h"
#include "utils.h"
#include "utils_snmp.h"

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

	printf("Handling oid %s\n", mp_snmp_oid2str(v->name, v->name_length));
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

static int check_proc_states(netsnmp_session *ss, int statemask)
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

static int check_proc_names(netsnmp_session *ss)
{
	mp_snmp_walk(ss, PROCESS_TABLE ".4", walker_print_name, NULL, NULL);
}

static struct proc_info *query_process(netsnmp_session *ss, int k)
{
	netsnmp_pdu *pdu, *response = NULL;
	netsnmp_variable_list *v;
	int mask;
	struct proc_info *p;

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
	if (snmp_synch_response(ss, pdu, &response) < 0) {
		die(STATE_UNKNOWN, _("Failed to fetch variables for process %d\n"), k);
	}
	if (!response) {
		die(STATE_UNKNOWN, _("Failed to query server"));
	}
	if (!(p = calloc(1, sizeof(p)))) {
		snmp_free_pdu(response);
		snmp_free_pdu(pdu);
		die(STATE_UNKNOWN, _("Failed to allocate memory"));
	}

	for (v = response->variables; v; v = v->next_variable) {
		int is_perf;
		if (!v->name || !v->name_length)
			continue;
		if (v->name[7] == 5) {
			/* procperf table */
			if (v->name[8] == PROCPERF_SUBIDX_RunPerfCPU) {
				p->Perf.CPU = *v->val.integer;
			} else if (v->name[8] == PROCPERF_SUBIDX_RunPerfMem) {
				p->Perf.Mem = *v->val.integer;
			}
			continue;
		}
		switch (v->name[8]) {
			case PROCESS_SUBIDX_RunID:
				p->ID = *v->val.integer;
				break;
			case PROCESS_SUBIDX_RunIndex:
				p->Index = *v->val.integer;
				break;
			case PROCESS_SUBIDX_RunName:
				mp_snmp_value2str(v, p->Name, 0);
				break;
			case PROCESS_SUBIDX_RunParameters:
				mp_snmp_value2str(v, p->Parameters, 0);
				break;
			case PROCESS_SUBIDX_RunPath:
				mp_snmp_value2str(v, p->Path, 0);
				break;
			case PROCESS_SUBIDX_RunStatus:
				p->Status = *v->val.integer;
				break;
		}
	}
	snmp_free_pdu(response);
	return p;
}

static void print_proc_info(struct proc_info *p)
{
	printf("Status: %d\n", p->Status);
	printf("CPU: %d\n", p->Perf.CPU);
	printf("Mem: %d\n", p->Perf.Mem);
	printf("Name: %s\n", p->Name);
}

int main(int argc, char **argv)
{
	netsnmp_session session, *ss;
	struct proc_info *p;

	mp_snmp_init("check_snmp_procs", 0);

	snmp_sess_init(&session);
	session.community = (u_char *)"everything";
	session.community_len = (size_t)strlen((char *)session.community);
	session.peername = "localhost";
	session.version = SNMP_VERSION_1;
	session.timeout = 15 * 1000000;
	ss = snmp_open(&session);
	if (1) {
		p = query_process(ss, 1);
		printf("p = %p\n", p);
		print_proc_info(p);
		exit(0);
	}
	if (1) {
		check_proc_names(&session);
		printf("procs: %d\n", procs);
	}
	procs = 0;
	if (1) {
		check_proc_states(&session, ~0);
		printf("procs: %d\n", procs);
	}

	mp_snmp_deinit("check_snmp_procs");
	return 0;
}
