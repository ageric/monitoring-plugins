/**
 * Check system memory over snmp
 */
#include "common.h"
#include "utils.h"
#include "utils_snmp.h"
//#include "bitmap.h"

#define MEMORY_TABLE "1.3.6.1.4.1.2021.4"
#define MEMORY_SUBIDX_MemIndex 1
//#define MEMORY_SUBIDX_MemErrorName 2
#define MEMORY_SUBIDX_MemTotalSwap 3	/* Using this */
#define MEMORY_SUBIDX_MemAvailSwap 4	/* Using this */
#define MEMORY_SUBIDX_MemTotalReal 5	/* Using this */
#define MEMORY_SUBIDX_MemAvailReal 6	/* Using this */
/*
#define MEMORY_SUBIDX_MemTotalSwapTXT 7
#define MEMORY_SUBIDX_MemAvailSwapTXT 8
#define MEMORY_SUBIDX_MemTotalRealTXT 9
#define MEMORY_SUBIDX_MemAvailRealTXT 10
*/
#define MEMORY_SUBIDX_MemTotalFree 11	/* Extra */
#define MEMORY_SUBIDX_MemMinimumSwap 12	/* Extra */
#define MEMORY_SUBIDX_MemShared 13		/* Extra */
#define MEMORY_SUBIDX_MemBuffer 14		/* Using this */
#define MEMORY_SUBIDX_MemCached 15		/* Using this */
/*
#define MEMORY_SUBIDX_MemSwapError 100
#define MEMORY_SUBIDX_MemSwapErrorMsg 101
*/

static thresholds *thresh;

struct mem_info {
	int Index;
	int TotalSwap;
	int AvailSwap;
	int TotalReal;
	int AvailReal;
	int TotalFree;
	int MinimumSwap;
	int Shared;
	int Buffer;
	int Cached;
};

static int pstate_callback(netsnmp_variable_list *v, void *psc_ptr, void *discard)
{
	struct mem_info *psc = (struct mem_info *)psc_ptr;

	switch (v->name[8]) {
		case MEMORY_SUBIDX_MemIndex:
			psc->Index=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemTotalSwap:
			psc->TotalSwap=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemAvailSwap:
			psc->AvailSwap=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemTotalReal:
			psc->TotalReal=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemAvailReal:
			psc->AvailReal=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemTotalFree:
			psc->TotalFree=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemMinimumSwap:
			psc->MinimumSwap=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemShared:
			psc->Shared=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemBuffer:
			psc->Buffer=*v->val.integer;
			break;
		case MEMORY_SUBIDX_MemCached:
			psc->Cached=*v->val.integer;
			break;
	}
}

static int check_proc_states(mp_snmp_context *ss, int statemask)
{
	struct mem_info pstate_count;

	memset(&pstate_count, 0, sizeof(pstate_count));
	mp_snmp_walk(ss, MEMORY_TABLE, pstate_callback, &pstate_count, NULL);
	printf("Memory: %dkb total, %dkb used, %dkb free, %dkb buffers \nSwap: \t%dkb total, %dkb used, %dkb free, %dkb cached\nExtra: \t%dkb total free, %dkb minimumswap, %dkb Shared\n",
	      pstate_count.TotalReal, pstate_count.TotalReal-pstate_count.AvailReal, pstate_count.AvailReal, pstate_count.Buffer, pstate_count.TotalSwap, pstate_count.TotalSwap-pstate_count.AvailSwap, pstate_count.AvailSwap, pstate_count.Cached, pstate_count.TotalFree, pstate_count.MinimumSwap, pstate_count.Shared);
}

/*
static struct mem_info *query_process(mp_snmp_context *ctx, int k)
{
	netsnmp_pdu *pdu, *response = NULL;
	netsnmp_variable_list *v;
	int mask;
	struct mem_info *p;
	int error = 0, count = 0;

	pdu = snmp_pdu_create(SNMP_MSG_GET);
	if (!pdu) {
		return NULL;
	}

	MP_SNMP_PDU_MASK_ADD(mask, MEMORY_SUBIDX_MemIndex);
	MP_SNMP_PDU_MASK_ADD(mask, MEMORY_SUBIDX_MemTotalSwap);
	MP_SNMP_PDU_MASK_ADD(mask, MEMORY_SUBIDX_MemAvailSwap);
	MP_SNMP_PDU_MASK_ADD(mask, MEMORY_SUBIDX_MemTotalReal);
	MP_SNMP_PDU_MASK_ADD(mask, MEMORY_SUBIDX_MemAvailReal);
	MP_SNMP_PDU_MASK_ADD(mask, MEMORY_SUBIDX_MemCached);
	mp_snmp_add_keyed_subtree(pdu, MEMORY_TABLE, mask, k);
	
	if (mp_snmp_query(ctx, pdu, &response)) {
		die(STATE_UNKNOWN, _("Failed to fetch variables for process %d\n"), k);
	}
	if (!(p = calloc(1, sizeof(*p)))) {
		snmp_free_pdu(response);
		snmp_free_pdu(pdu);
		die(STATE_UNKNOWN, _("Failed to allocate memory"));
	}

	for (v = response->variables; v; v = v->next_variable, count++) {
		
		if (v->name[10] == 4) {
			//procperf table
			if (v->name[10] == MEMORY_SUBIDX_MemIndex) {
				printf("out\n");
				p->Index = 1 + *v->val.integer;
			} else if (v->name[10] == MEMORY_SUBIDX_MemTotalSwap) {
				printf("out\n");
				p->TotalSwap = 1 + *v->val.integer;
			}
			continue;
		}
		
		switch (v->name[10]) {
			case MEMORY_SUBIDX_MemIndex:
				p->Index = *v->val.integer;
				break;
			case MEMORY_SUBIDX_MemTotalSwap:
				p->TotalSwap = *v->val.integer;
				break;
			case MEMORY_SUBIDX_MemAvailSwap:
				p->AvailSwap = *v->val.integer;
				break;
			case MEMORY_SUBIDX_MemTotalReal:
				p->TotalReal = *v->val.integer;
				break;
			case MEMORY_SUBIDX_MemAvailReal:
				p->AvailReal = *v->val.integer;
				break;
			case MEMORY_SUBIDX_MemCached:
				p->Cached = *v->val.integer;
				break;
			default:
				printf("default %lu %lu %lu %lu %lu %lu\n",v->name[count], v->name[6], v->name[7], v->name[8], v->name[9], v->name[10]);
		}
	}
	printf("count: %d\n", count);
	snmp_free_pdu(response);
	return p;
}

static void print_mem_info(struct mem_info *p)
{
	printf("Index: %d\n", p->Index);
	printf("Total swap: %d\n", p->TotalSwap);
	printf("Avail swap: %d\n", p->AvailSwap);
	printf("Total real: %d\n", p->TotalReal);
	printf("Avail real: %d\n", p->AvailReal);
	printf("Cached: %d\n", p->Cached);
}

static void destroy_mem_info(struct mem_info *p)
{
	free(p->Index);
	free(p->TotalSwap);
	free(p->AvailSwap);
	free(p->TotalReal);
	free(p->AvailReal);
	free(p->Cached);

	free(p);
}
*/
int main(int argc, char **argv)
{
	int i, x;
	int c, err, option;
	netsnmp_session session, *ss;
	mp_snmp_context *ctx;
	struct mem_info *p;
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
	mp_snmp_init("check_snmp_memory", 0);
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
		check_proc_states(ctx, ~0);
	}
	/*
	if (1) {
		p = query_process(ctx, 1);
		print_mem_info(p);
		destroy_mem_info(p);
	}
	*/

	mp_snmp_deinit("check_snmp_memory");

	return 0;
}
