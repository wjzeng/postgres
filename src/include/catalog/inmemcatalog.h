/*-------------------------------------------------------------------------
 *
 * inmemcatalog.h
 *	 in-memory heap table access method
 *
 *
 *-------------------------------------------------------------------------
 */

#ifndef _INMEMCATALOG_H_
#define _INMEMCATALOG_H_

#include "access/htup.h"
#include "access/relscan.h"
#include "access/skey.h"
#include "access/sdir.h"
#include "storage/lockdefs.h"
#include "nodes/primnodes.h"
#include "nodes/execnodes.h"
#include "utils/relcache.h"
#include "utils/hsearch.h"
#include "utils/snapshot.h"

extern bool in_memory_catalog_log;

/*
 * In memory storage types. When creating/accessing/dropping tables,
 * the mapping type needs to be specified.
 */
enum InMemMappingType
{
	INMEM_ONLY_MAPPING = 0,		/* Tuples that are only kept in memory and do
								 * not have a copy on disk. (e.g. HCatalog) */
	INMEM_MAPPINGS_SIZE			/* Number of mappings - keep last. */
};
typedef enum InMemMappingType InMemMappingType;

enum InMemHeapTupleFlag
{
	INMEM_HEAP_TUPLE_IS_NULL = 1,
	INMEM_HEAP_TUPLE_DISPATCHED
};
typedef enum InMemHeapTupleFlag InMemHeapTupleFlag;

struct InMemHeapTupleData
{
	HeapTuple	tuple;			/* heap tuple */
	uint8		flags;			/* tuple flag such as INMEM_HEAP_TUPLE_DELETED */
};
typedef struct InMemHeapTupleData InMemHeapTupleData;

typedef struct InMemHeapTupleData *InMemHeapTuple;

struct InMemHeapRelationData
{
	MemoryContext memcxt;
	InMemHeapTuple tuples;		/* a vector of InMemHeapTuple */
	TupleDesc	tupledesc;
	int32		tupsize;
	int32		tupmaxsize;
	Oid			relid;
	char		relname[NAMEDATALEN];
	HTAB	   *hashIndex;		/* build a hash index for fast lookup */
	int			keyAttrno;		/* attribute no of hash index key, key must be
								 * Oid type */
	List	   *freelist;
};
typedef struct InMemHeapRelationData InMemHeapRelationData;
typedef struct InMemHeapRelationData *InMemHeapRelation;

extern HTAB *OidInMemMappings[INMEM_MAPPINGS_SIZE];

struct OidInMemHeapMappingEntry
{
	Oid			relid;
	InMemHeapRelation rel;
};

typedef struct InMemHeapScanDescData
{
	InMemHeapRelation rs_rd;	/* heap relation descriptor */
	struct SnapshotData *rs_snapshot;
	int			rs_nkeys;		/* number of scan keys */
	ScanKey		rs_key;			/* array of scan key descriptors */
	AttrNumber *orig_attnos;

	/* scan current state */
	HeapTuple	rs_ctup;		/* current tuple in scan, if any */
	int32		rs_index;		/* current tuple position in in-memory heap
								 * table */

	IndexInfo  *index_info;

#if 0
	TableScanDesc hscan;		/* if there is a heap table with the same Oid,
								 * this a heap scan descriptor */

	Oid			indexScanKey;	/* hash key searched in hash table */
	bool		hashIndexOk;	/* hash index is ok to use */
	bool		indexScanInitialized;	/* hash index scan has initialized */
	int			hashKeyIndexInScanKey;	/* the index of hash key in scan key
										 * array */
	ListCell   *indexNext;		/* cursor in hash index */
	List	   *indexReverseList;	/* reverse list of the scan key for
									 * backward scan */
#endif
}			InMemHeapScanDescData;

typedef InMemHeapScanDescData * InMemHeapScanDesc;

extern void CleanupOidInMemHeapMapping(InMemMappingType mappingType);
extern InMemHeapRelation OidGetInMemHeapRelation(Oid relid, InMemMappingType mappingType);
extern InMemHeapRelation InMemHeap_Create(Oid relid, Relation rel,
										  int32 initSize, const char *relname, bool createIndex, int keyAttrno,
										  InMemMappingType mappingType);
extern void InMemHeap_Drop(Oid relid, InMemMappingType mappingType);
extern void InMemHeap_DropAll(InMemMappingType mappingType);
extern InMemHeapScanDesc InMemHeap_BeginScan(InMemHeapRelation memheap,
											 int nkeys, ScanKey key, AttrNumber *orig_attnos, bool inmemonly,
											 Snapshot snapshot, Relation index, bool addref);
extern void InMemHeap_ReScan(InMemHeapScanDesc scan, ScanKey keys, int nkeys);
extern void InMemHeap_EndScan(InMemHeapScanDesc scan, bool closerel);
extern HeapTuple InMemHeap_GetNext(InMemHeapScanDesc scan, ScanDirection direction);
extern void InMemHeap_Insert(Relation relation, HeapTuple tup);
extern void InMemHeap_Update(Relation relation, HeapTuple tup, uint32 position, bool inplace);
extern void InMemHeap_Delete(Relation relation, uint32 position);
extern bool IsTupleShouldStoreInMemCatalog(Relation relation, HeapTuple newTuple);
extern Datum tuple_getattr(HeapTuple tuple, TupleDesc tupleDesc, int attnum);
extern uint32 GetMemTuplePosition(Relation relation, ItemPointer tid);
extern bool CatalogMaybeStoreInMem(Relation rel);

#endif							/* _INMEMCATALOG_H_ */
