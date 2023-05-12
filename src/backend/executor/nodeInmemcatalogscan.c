/*-------------------------------------------------------------------------
 *
 * nodeInmemcatalogscan.c
 *	  Support routines for inmem catalog scans of relations.
 *
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/executor/nodeInmemcatalogscan.c
 *
 *-------------------------------------------------------------------------
 */
/*
 * INTERFACE ROUTINES
 *		ExecSeqScan				sequentially scans a relation.
 *		ExecSeqNext				retrieve next tuple in sequential order.
 *		ExecInitSeqScan			creates and initializes a seqscan node.
 *		ExecEndSeqScan			releases any storage allocated.
 *		ExecReScanSeqScan		rescans the relation
 *
 */
#include "postgres.h"

#include "access/relscan.h"
#include "access/tableam.h"
#include "catalog/inmemcatalog.h"
#include "executor/execdebug.h"
#include "executor/nodeInmemcatalogscan.h"
#include "utils/rel.h"

static TupleTableSlot *InmemCatalogScanNext(InmemCatalogScanState * node);

/* ----------------------------------------------------------------
 *						Scan Support
 * ----------------------------------------------------------------
 */

/* ----------------------------------------------------------------
 *		SeqNext
 *
 *		This is a workhorse for ExecSeqScan
 * ----------------------------------------------------------------
 */
static TupleTableSlot *
InmemCatalogScanNext(InmemCatalogScanState * node)
{
	TableScanDesc scandesc;
	EState	   *estate;
	ScanDirection direction;
	TupleTableSlot *slot;

	scandesc = node->ss.ss_currentScanDesc;
	estate = node->ss.ps.state;
	direction = estate->es_direction;
	slot = node->ss.ss_ScanTupleSlot;

	if (scandesc == NULL)
	{
		InMemHeapRelation memheap;

		scandesc = palloc0(sizeof(TableScanDescData));
		memheap = OidGetInMemHeapRelation(RelationGetRelid(node->ss.ss_currentRelation), INMEM_ONLY_MAPPING);
		if (memheap)
			scandesc->inmemonlyscan = InMemHeap_BeginScan(memheap, 0, NULL, NULL, true, estate->es_snapshot, NULL, false);

		node->ss.ss_currentScanDesc = scandesc;
	}

	if (scandesc->inmemonlyscan != NULL)
		scandesc->inmem_started = true;

	if (scandesc->inmem_started)
	{
		HeapTuple	htup = InMemHeap_GetNext(scandesc->inmemonlyscan, direction);

		if (htup)
		{
			if (in_memory_catalog_log)
				elog(WARNING, "hint one record from memcatalog %s by InmemCatalogScanNext", RelationGetRelationName(node->ss.ss_currentRelation));

			ExecForceStoreHeapTuple(htup, slot, false);
			return slot;
		}
	}

	return NULL;
}

static bool
InmemCatalogScanRecheck(InmemCatalogScanState * node, TupleTableSlot *slot)
{
	return true;
}

static TupleTableSlot *
ExecInmemCatalogScan(PlanState *pstate)
{
	InmemCatalogScanState *node = castNode(InmemCatalogScanState, pstate);

	return ExecScan(&node->ss,
					(ExecScanAccessMtd) InmemCatalogScanNext,
					(ExecScanRecheckMtd) InmemCatalogScanRecheck);
}

InmemCatalogScanState *
ExecInitInmemCatalogScan(InmemCatalogScan * node, EState *estate, int eflags)
{
	InmemCatalogScanState *scanstate;

	/*
	 * Once upon a time it was possible to have an outerPlan of a SeqScan, but
	 * not any more.
	 */
	Assert(outerPlan(node) == NULL);
	Assert(innerPlan(node) == NULL);

	/*
	 * create state structure
	 */
	scanstate = makeNode(InmemCatalogScanState);
	scanstate->ss.ps.plan = (Plan *) node;
	scanstate->ss.ps.state = estate;
	scanstate->ss.ps.ExecProcNode = ExecInmemCatalogScan;

	/*
	 * Miscellaneous initialization
	 *
	 * create expression context for node
	 */
	ExecAssignExprContext(estate, &scanstate->ss.ps);

	/*
	 * open the scan relation
	 */
	scanstate->ss.ss_currentRelation =
		ExecOpenScanRelation(estate,
							 node->scan.scanrelid,
							 eflags);

	/* and create slot with the appropriate rowtype */
	ExecInitScanTupleSlot(estate, &scanstate->ss,
						  RelationGetDescr(scanstate->ss.ss_currentRelation),
						  table_slot_callbacks(scanstate->ss.ss_currentRelation));

	/*
	 * Initialize result type and projection.
	 */
	ExecInitResultTypeTL(&scanstate->ss.ps);
	ExecAssignScanProjectionInfo(&scanstate->ss);

	/*
	 * initialize child expressions
	 */
	scanstate->ss.ps.qual =
		ExecInitQual(node->scan.plan.qual, (PlanState *) scanstate);

	return scanstate;
}

void
ExecEndInmemCatalogScan(InmemCatalogScanState * node)
{
	TableScanDesc scanDesc;

	scanDesc = node->ss.ss_currentScanDesc;

	ExecFreeExprContext(&node->ss.ps);

	if (node->ss.ps.ps_ResultTupleSlot)
		ExecClearTuple(node->ss.ps.ps_ResultTupleSlot);

	ExecClearTuple(node->ss.ss_ScanTupleSlot);

	if (scanDesc != NULL)
	{
		if (scanDesc->inmemonlyscan)
		{
			InMemHeap_EndScan(scanDesc->inmemonlyscan, false);
			scanDesc->inmemonlyscan = NULL;
		}
		pfree(scanDesc);
	}
}

void
ExecReScanInmemCatalogScan(InmemCatalogScanState * node)
{
	TableScanDesc scan;

	scan = node->ss.ss_currentScanDesc;

	if (scan != NULL &&
		scan->inmemonlyscan &&
		scan->inmem_started)
	{
		InMemHeap_ReScan(scan->inmemonlyscan, NULL, 0);
		scan->inmem_started = false;
	}

	ExecScanReScan((ScanState *) node);
}
