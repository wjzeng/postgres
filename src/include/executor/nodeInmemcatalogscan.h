/*-------------------------------------------------------------------------
 *
 * nodeInmemcatalogscan
 *
 *
 *
 * Portions Copyright (c) 1996-2022, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/executor/nodeInmemcatalogscan.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef NODEINMEMCATALOGSCAN_H
#define NODEINMEMCATALOGSCAN_H 

#include "access/parallel.h"
#include "nodes/execnodes.h"

extern InmemCatalogScanState *ExecInitInmemCatalogScan(InmemCatalogScan *node, EState *estate, int eflags);
extern void ExecEndInmemCatalogScan(InmemCatalogScanState *node);
extern void ExecReScanInmemCatalogScan(InmemCatalogScanState *node);

#endif							/* NODESEQSCAN_H */
