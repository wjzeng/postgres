/*-------------------------------------------------------------------------
 *
 * vacuumblk.h
 *	  header file for postgres block level vacuum routines
 *
 *
 * Portions Copyright (c) 1996-2020, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 * src/include/commands/vacuumblk.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef VACUUMBLK_H
#define VACUUMBLK_H

#include "commands/vacuum.h"
#include "storage/buf.h"

extern void lazy_vacuum_index(Relation indrel, IndexBulkDeleteResult **stats,
							  LVDeadTuples *dead_tuples, double reltuples, LVRelStats *vacrelstats,
							  BufferAccessStrategy vac_strategy, int elevel);
extern void lazy_cleanup_index(Relation indrel, IndexBulkDeleteResult **stats,
							   double reltuples, bool estimated_count, LVRelStats *vacrelstats,
							   BufferAccessStrategy vac_strategy, int elevel);
extern bool should_attempt_truncation(VacuumParams *params, LVRelStats *vacrelstats);
extern void lazy_truncate_heap(Relation onerel, LVRelStats *vacrelstats,
							   BufferAccessStrategy vac_strategy, int elevel);
extern void lazy_record_dead_tuple(LVDeadTuples *dead_tuples,
								   ItemPointer itemptr);

extern void update_vacuum_error_info(LVRelStats *errinfo, LVSavedErrInfo *saved_err_info, int phase,
									 BlockNumber blkno);
extern void restore_vacuum_error_info(LVRelStats *errinfo, const LVSavedErrInfo *saved_err_info);

#endif							/* VACUUMBLK_H */
