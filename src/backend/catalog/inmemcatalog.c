/*-------------------------------------------------------------------------
 *
 * inmemcatalog.c
 * in-memory heap table access method
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#include "access/genam.h"
#include "access/heapam.h"
#include "access/htup.h"
#include "access/relation.h"
#include "access/valid.h"
#include "access/xact.h"
#include "catalog/catalog.h"
#include "catalog/index.h"
#include "catalog/pg_sequence.h"
#include "catalog/pg_constraint.h"
#include "catalog/pg_depend.h"
#include "catalog/pg_namespace.h"
#include "catalog/pg_type.h"
#include "catalog/pg_attrdef.h"
#include "catalog/pg_publication.h"
#include "catalog/pg_publication_namespace.h"
#include "catalog/pg_publication_rel.h"
#include "catalog/inmemcatalog.h"
#include "common/hashfn.h"
#include "nodes/memnodes.h"
#include "nodes/parsenodes.h"
#include "storage/lock.h"
#include "utils/fmgroids.h"
#include "utils/hsearch.h"
#include "utils/inval.h"
#include "utils/lsyscache.h"
#include "utils/memutils.h"
#include "utils/rel.h"
#include "utils/snapmgr.h"
#include "miscadmin.h"

bool		in_memory_catalog_log = false;
HTAB	   *OidInMemMappings[INMEM_MAPPINGS_SIZE] = {NULL};
static MemoryContext InMemMappingCxt[INMEM_MAPPINGS_SIZE] = {NULL};
static const char *InMemMappingNames[INMEM_MAPPINGS_SIZE] = {"OidInMemOnlyMapping"};

#define HeapTupleGetOid(tuple) \
		HeapTupleHeaderGetOidOld((tuple)->t_data)

#define HeapTupleHeaderGetOidOld(tup) \
( \
	((tup)->t_infomask & HEAP_HASOID_OLD) ? \
	   *((Oid *) ((char *)(tup) + (tup)->t_hoff - sizeof(Oid))) \
	: \
		InvalidOid \
)

typedef bool (*CheckConstraintsFn) (InMemHeapRelation relation, HeapTuple newTuple);

static void InitOidInMemHeapMapping(long initSize, MemoryContext memcxt, InMemMappingType mappingType);
static bool TypeInMemCatalog(Datum typeid);
static bool RelationInMemCatalog(Datum relid);
static bool ConstraintInMemCatalog(Datum cid);
static bool IndexInMemCatalog(Datum indexid);
static bool AttrDefaultInMemCatalog(Datum attrdid);
static bool NamespaceInMemCatalog(Datum nspid);
static uint32 AllocInMemoryCatalogInsertPosition(InMemHeapRelation inmemrel);
static bool InMemHeap_GetNextIndex(InMemHeapScanDesc scan, ScanDirection direction);
static uint32 GetTuplePositionByKeyAttr(InMemHeapRelation inmemtype, AttrNumber keyattr1, Datum key1, AttrNumber keyattr2, Datum key2);
static HeapTuple heaptuple_copy_to(HeapTuple tup, HeapTuple result, uint32 *len);
static bool InMemHeap_CheckConstraints(InMemHeapRelation relation, HeapTuple newTuple);
static bool CheckInMemConstraintsPgNamespace(InMemHeapRelation relation, HeapTuple newTuple);
static bool CheckInMemConstraintsPgClass(InMemHeapRelation relation, HeapTuple newTuple);
static bool CheckInMemConstraintsPgType(InMemHeapRelation relation, HeapTuple newTuple);
static bool CheckInMemConstraintsPgAttribute(InMemHeapRelation relation, HeapTuple newTuple);
static bool tuple_has_oid(HeapTuple tuple);

static HeapTuple
heaptuple_copy_to(HeapTuple tuple, HeapTuple dest, uint32 *destlen)
{
	HeapTuple	newTuple;
	uint32		len;

	if (!HeapTupleIsValid(tuple) || tuple->t_data == NULL)
		return NULL;

/* 	Assert(!is_heaptuple_memtuple(tuple)); */

	len = HEAPTUPLESIZE + tuple->t_len;
	if (destlen && *destlen < len)
	{
		*destlen = len;
		return NULL;
	}

	if (destlen)
	{
		*destlen = len;
		newTuple = dest;
	}
	else
		newTuple = (HeapTuple) palloc0(HEAPTUPLESIZE + tuple->t_len);

	newTuple->t_len = tuple->t_len;
	ItemPointerSetInvalid(&newTuple->t_self);
	newTuple->t_data = (HeapTupleHeader) ((char *) newTuple + HEAPTUPLESIZE);
	memcpy((char *) newTuple->t_data, (char *) tuple->t_data, tuple->t_len);

	return newTuple;
}

/*
 * init relid to in-memory table mapping
 */
static void
InitOidInMemHeapMapping(long initSize, MemoryContext memcxt, InMemMappingType mappingType)
{
	HASHCTL		info;

	Assert(mappingType < INMEM_MAPPINGS_SIZE);
	Assert(NULL == OidInMemMappings[mappingType]);

	info.hcxt = memcxt;
	info.hash = oid_hash;
	info.keysize = sizeof(Oid);
	info.entrysize = sizeof(struct OidInMemHeapMappingEntry);

	OidInMemMappings[mappingType] = hash_create(InMemMappingNames[mappingType], initSize, &info,
												HASH_CONTEXT | HASH_FUNCTION | HASH_ELEM);

	Assert(NULL != OidInMemMappings[mappingType]);

	InMemMappingCxt[mappingType] = memcxt;
}

/*
 * cleanup relid to in-memory table mapping
 */
void
CleanupOidInMemHeapMapping(InMemMappingType mappingType)
{
	Assert(mappingType < INMEM_MAPPINGS_SIZE);

	if (NULL == OidInMemMappings[mappingType])
	{
		return;
	}

	hash_destroy(OidInMemMappings[mappingType]);
	OidInMemMappings[mappingType] = NULL;

	InMemMappingCxt[mappingType] = NULL;
}

/*
 * get a in-memory table by relid,
 */
InMemHeapRelation
OidGetInMemHeapRelation(Oid relid, InMemMappingType mappingType)
{
	bool		found = false;
	struct OidInMemHeapMappingEntry *retval;

	Assert(mappingType < INMEM_MAPPINGS_SIZE);

	if (NULL != OidInMemMappings[mappingType])
	{
		retval = hash_search(OidInMemMappings[mappingType], &relid, HASH_FIND, &found);
		if (NULL != retval)
		{
			return retval->rel;
		}
	}

	return NULL;
}

/*
 * create a in-memory heap table with Oid.
 * the in-memory table and all its tuples are in memcxt memory context.
 * at first, initSize tuples space will be alloced in the tuple,
 * and will re-alloc at runtime if inserting more tuples.
 */
InMemHeapRelation
InMemHeap_Create(Oid relid, Relation rel,
				 int32 initSize, const char *relname, bool createIndex, int keyAttrno,
				 InMemMappingType mappingType)
{
	bool		found = false;
	struct OidInMemHeapMappingEntry *entry;
	InMemHeapRelation memheap = NULL;
	MemoryContext oldcxt;
	static MemoryContext InMemoryContext = NULL;

	if (!InMemoryContext)
	{
		InMemoryContext = AllocSetContextCreate(CacheMemoryContext,
												"InMemoryContext",
												ALLOCSET_DEFAULT_MINSIZE,
												ALLOCSET_DEFAULT_INITSIZE,
												ALLOCSET_DEFAULT_MAXSIZE);

		InitOidInMemHeapMapping(10, InMemoryContext, INMEM_ONLY_MAPPING);
	}

	Assert(mappingType < INMEM_MAPPINGS_SIZE);
	Assert(NULL != OidInMemMappings[mappingType]);

	hash_search(OidInMemMappings[mappingType], &relid, HASH_FIND, &found);

	if (found)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("in-memory table with Oid = %d already exist.", relid)));
	}

	Assert(MemoryContextIsValid(InMemMappingCxt[mappingType]));
	oldcxt = MemoryContextSwitchTo(InMemMappingCxt[mappingType]);
	memheap = palloc0(sizeof(InMemHeapRelationData));

	memheap->memcxt = InMemMappingCxt[mappingType];
	memheap->relid = relid;
	memheap->tupsize = 0;
	memheap->tupmaxsize = initSize;
	memheap->tuples = NULL;
	memheap->tupledesc = palloc(TupleDescSize(RelationGetDescr(rel)));
	TupleDescCopy(memheap->tupledesc, RelationGetDescr(rel));

	memheap->hashIndex = NULL;
	memheap->keyAttrno = 0;
	memheap->freelist = NIL;
	snprintf(memheap->relname, NAMEDATALEN, "%s", relname);

	Assert(!createIndex);
#if 0
	if (createIndex)
	{
		HASHCTL		info;

		memheap->keyAttrno = keyAttrno;

		/* Set key and entry sizes. */
		MemSet(&info, 0, sizeof(info));
		info.keysize = sizeof(Oid);
		info.entrysize = sizeof(MemHeapHashIndexEntry);
		info.hash = oid_hash;
		info.hcxt = memheap->memcxt;

		memheap->hashIndex = hash_create("InMemHeap hash index",
										 10, &info,
										 HASH_ELEM | HASH_FUNCTION | HASH_CONTEXT);
	}
#endif

	initSize = initSize > 1 ? initSize : 1;
	memheap->tuples = palloc(sizeof(InMemHeapTupleData) * initSize);

	entry = hash_search(OidInMemMappings[mappingType], &relid, HASH_ENTER, &found);

	entry->relid = relid;
	entry->rel = memheap;

	MemoryContextSwitchTo(oldcxt);

	return memheap;
}

/*
 * drop a in-memory heap table.
 */
void
InMemHeap_Drop(Oid relid, InMemMappingType mappingType)
{
	bool		found = false;
	struct OidInMemHeapMappingEntry *entry = NULL;

	Assert(mappingType < INMEM_MAPPINGS_SIZE);
	Assert(NULL != OidInMemMappings[mappingType]);

	entry = hash_search(OidInMemMappings[mappingType], &relid, HASH_FIND, &found);

	if (NULL == entry)
	{
		return;
	}

	Assert(NULL != entry->rel);

#if 0
	if (entry->rel->hashIndex)
	{
		hash_destroy(entry->rel->hashIndex);
		entry->rel->hashIndex = NULL;
	}
#endif

	if (entry->rel->tuples)
	{
		int			i;
		HeapTuple	tup;

		for (i = 0; i < entry->rel->tupsize; ++i)
		{
			tup = entry->rel->tuples[i].tuple;
			if (tup)
			{
				pfree(tup);
			}
		}
		pfree(entry->rel->tuples);
	}

	pfree(entry->rel);

	hash_search(OidInMemMappings[mappingType], &relid, HASH_REMOVE, &found);
}

/*
 * drop all in-memory tables of given mapping
 */
void
InMemHeap_DropAll(InMemMappingType mappingType)
{
	HASH_SEQ_STATUS scan;
	struct OidInMemHeapMappingEntry *entry;

	Assert(mappingType < INMEM_MAPPINGS_SIZE);

	if (NULL == OidInMemMappings[mappingType])
	{
		return;
	}

	elog(DEBUG1, "Dropping in memory mapping %s", InMemMappingNames[mappingType]);

	hash_seq_init(&scan, OidInMemMappings[mappingType]);

	while (!!(entry = (struct OidInMemHeapMappingEntry *) hash_seq_search(&scan)))
	{
		InMemHeap_Drop(entry->relid, mappingType);
	}
}

/*
 * begin a in-memory heap table scan.
 */
InMemHeapScanDesc
InMemHeap_BeginScan(InMemHeapRelation memheap, int nkeys,
					ScanKey key, AttrNumber *orig_attnos, bool inmemonly,
					Snapshot snapshot, Relation index, bool addref)
{
	InMemHeapScanDesc scan = palloc0(sizeof(InMemHeapScanDescData));

	Assert(NULL != scan);

	scan->rs_snapshot = snapshot;

#if 0

	/*
	 * The rel in InMemHeapRelation is a pointer, which is the address of heap
	 * relation in relcache. When the heap relation in relcache is clear for
	 * some reason, the value of rel in InMemHeapRelation is wrong. So we
	 * should reopen this relation to make sure it's correct.
	 */
	if (addref)
		memheap->rel = RelationIdGetRelation(memheap->relid);
#endif

	scan->rs_rd = memheap;
	scan->rs_nkeys = nkeys;
	scan->rs_index = -1;

	if (index)
		scan->index_info = BuildIndexInfo(index);

	if (nkeys > 0)
		scan->rs_key = (ScanKey) palloc0(sizeof(ScanKeyData) * nkeys);
	else
		scan->rs_key = NULL;

	if (key != NULL)
	{
		memcpy(scan->rs_key, key, scan->rs_nkeys * sizeof(ScanKeyData));
		if (NULL != orig_attnos)
		{
			/*
			 * restore original key attribute numbers as the they are invalid
			 * in the passed array of keys
			 */
			/*
			 * note: the scankey struct contains the attnos of the keys in the
			 * index scan, and here we need to refer to the original ones from
			 * the heap relation
			 */
			int			i = 0;

			for (i = 0; i < nkeys; i++)
			{
				scan->rs_key[i].sk_attno = orig_attnos[i];
			}
			scan->orig_attnos = orig_attnos;
		}

#if 0

		/*
		 * test if we can use hash index
		 */
		if (memheap->hashIndex)
		{
			int			i;

			for (i = 0; i < nkeys; ++i)
			{
				if (scan->rs_key[i].sk_attno == memheap->keyAttrno
					&& scan->rs_key[i].sk_strategy == BTEqualStrategyNumber)
				{
					/*
					 * we have a hash index on this attribute
					 */
					scan->hashIndexOk = true;
					scan->hashKeyIndexInScanKey = i;
					break;
				}
			}
		}
#endif
	}

	Assert(inmemonly);
#if 0
	if (!inmemonly && (NULL != scan->rs_rd->rel))
	{
		/*
		 * GPSQL-483, GPSQL-486
		 *
		 * When a QE exists on the master, we still want to leverage metadata
		 * that was extracted for query execution via metadata dispatch.
		 * (Otherwise, we'd have to reintroduce snapshot propagation for some
		 * sort of bastardized DTM that exists to coordinate the dispatcher
		 * with a master QE.) In leveraging dispatched metadata on a master
		 * QE, we also need to ensure that we can't read duplicate metadata
		 * from the heap itself. To accomplish this, we constrain the fallback
		 * heap scan to only metadata which could not have been dispatched,
		 * namely the builtin catalog data. Thus, we add OID < FirstNormalOid
		 * to the scan key.
		 */

		int			heap_nkeys = nkeys + 1;
		ScanKey		heap_key = (ScanKey) palloc0(sizeof(ScanKeyData) * heap_nkeys);

		/* Copy the given input keys */
		if (NULL != key)
		{
			memcpy(heap_key, scan->rs_key, nkeys * sizeof(ScanKeyData));
		}

		ScanKeyInit(&heap_key[heap_nkeys - 1],
					ObjectIdAttributeNumber,
					BTLessStrategyNumber, F_OIDLT,
					ObjectIdGetDatum(FirstNormalObjectId));

		scan->hscan = heap_beginscan(scan->rs_rd->rel, SnapshotNow,
									 heap_nkeys, heap_key);

		if (NULL != heap_key)
		{
			pfree(heap_key);
		}
	}
#endif

	return scan;
}

void
InMemHeap_ReScan(InMemHeapScanDesc scan, ScanKey keys, int nkeys)
{
	Assert(NULL != scan);

	scan->rs_index = -1;

	if (scan->rs_nkeys > 0)
	{
		Assert(nkeys == scan->rs_nkeys);
		memmove(scan->rs_key, keys, nkeys * sizeof(ScanKeyData));
		Assert(memcmp(scan->rs_key, keys, (nkeys * sizeof(ScanKeyData))) == 0);

		if (scan->orig_attnos)
		{
			int			i;

			for (i = 0; i < scan->rs_nkeys; i++)
				scan->rs_key[i].sk_attno = scan->orig_attnos[i];

		}
	}

	if (in_memory_catalog_log)
		elog(WARNING, "rescan memcatalog %s", scan->rs_rd->relname);
}

/*
 * end a in-memory heap table scan.
 */
void
InMemHeap_EndScan(InMemHeapScanDesc scan, bool closerel)
{
	Assert(NULL != scan);

#if 0
	if (in_memory_catalog_log)
		elog(WARNING, "endscan memcatalog %s", RelationGetRelationName(scan->rs_rd->rel));
#endif

#if 0
	if (closerel)
		RelationClose(scan->rs_rd->rel);
#endif

	if (NULL != scan->rs_key)
	{
		pfree(scan->rs_key);
	}

	if (scan->orig_attnos)
		pfree(scan->orig_attnos);

#if 0
	if (NULL != scan->hscan)
	{
		heap_endscan(scan->hscan);
	}

	if (NIL != scan->indexReverseList)
	{
		list_free(scan->indexReverseList);
	}
#endif
	pfree(scan);
}

/*
 * Increment scan->rs_index based on scan direction.
 * Returns false when scan reaches its end.
 */
static bool
InMemHeap_GetNextIndex(InMemHeapScanDesc scan, ScanDirection direction)
{
	if (BackwardScanDirection == direction)
	{
		if (-1 == scan->rs_index)	/* scan beginning */
		{
			scan->rs_index = scan->rs_rd->tupsize;
		}
		scan->rs_index--;
		return (scan->rs_index > -1);
	}
	else
	{
		scan->rs_index++;
		return (scan->rs_index < scan->rs_rd->tupsize);
	}
}

/*
 * get next tuple in in-memory heap table.
 */
HeapTuple
InMemHeap_GetNext(InMemHeapScanDesc scan, ScanDirection direction)
{
	bool		valid = true;

	InMemHeapTuple pmemtup = NULL;

	Assert(NULL != scan);

#if 0
	if (scan->hashIndexOk)
	{
		if (false == scan->indexScanInitialized)
		{
			Oid			key;
			bool		found;
			MemHeapHashIndexEntry *entry;

			key = DatumGetObjectId(scan->rs_key[scan->hashKeyIndexInScanKey].sk_argument);

			entry = (MemHeapHashIndexEntry *) hash_search(scan->rs_rd->hashIndex, &key,
														  HASH_FIND, &found);

			if (found)
			{
				if (BackwardScanDirection == direction)
				{
					/* if direction is backward, reverse list */
					scan->indexReverseList = list_reverse_ints(entry->values);
					entry->values = scan->indexReverseList;
				}
				scan->indexNext = list_head(entry->values);
			}
			else
				scan->indexNext = NULL;

			scan->indexScanInitialized = true;
			scan->indexScanKey = key;
		}

		for (; scan->indexNext != NULL;
			 scan->indexNext = lnext(scan->indexReverseList, scan->indexNext))
		{
			int32		index = lfirst_int(scan->indexNext);

			elog(DEBUG1, "read index %d key %d for relation %s", index, scan->indexScanKey, scan->rs_rd->relname);

			pmemtup = &scan->rs_rd->tuples[index];

			if (pmemtup->flags == INMEM_HEAP_TUPLE_IS_NULL)
				continue;
			else if (!HeapTupleSatisfiesVisibility(pmemtup->tuple, scan->rs_snapshot, InvalidBuffer))
				continue;

			valid = HeapKeyTest(pmemtup->tuple, RelationGetDescr(scan->rs_rd->rel),
								scan->rs_nkeys, scan->rs_key);

			if (!valid)
			{
				continue;
			}

			scan->rs_ctup = pmemtup->tuple;
			scan->indexNext = lnext(scan->indexReverseList, scan->indexNext);
			return scan->rs_ctup;
		}
	}
	else
#endif
	{
		/* for backward scan, change direction of iterator */
		while (InMemHeap_GetNextIndex(scan, direction))
		{
			pmemtup = &scan->rs_rd->tuples[scan->rs_index];

			if (pmemtup->flags == INMEM_HEAP_TUPLE_IS_NULL)
				continue;
			else if (!HeapTupleSatisfiesVisibility(pmemtup->tuple, scan->rs_snapshot, InvalidBuffer))
				continue;
			else if (scan->rs_key != NULL)
			{
				valid = HeapKeyTest(pmemtup->tuple, scan->rs_rd->tupledesc,
									scan->rs_nkeys, scan->rs_key);
			}

			if (!valid)
			{
				continue;
			}

			scan->rs_ctup = pmemtup->tuple;
			return scan->rs_ctup;
		}
	}
#if 0

	/*
	 * read from local read only heap table.
	 */
	if (NULL != scan->hscan)
	{
		return heap_getnext(scan->hscan, direction);
	}
#endif
	return NULL;
}

/*
 * insert a tuple into in-memory heap table.
 */
void
InMemHeap_Insert(Relation relation, HeapTuple tup)
{
	InMemHeapTuple inmemtup;
	InMemHeapRelation inmemrel = NULL;
	Oid			relid = RelationGetRelid(relation);
	MemoryContext oldctx;
	uint32		insert_pos = -1;
	TransactionId xid = GetCurrentTransactionId();
	CommandId	cid = GetCurrentCommandId(true);

	Assert(RelationIsValid(relation) && tup);
	inmemrel = OidGetInMemHeapRelation(relid, INMEM_ONLY_MAPPING);
	if (!inmemrel)
	{
		inmemrel = InMemHeap_Create(relid, relation, 10,
									RelationGetRelationName(relation), false, 0, INMEM_ONLY_MAPPING);
	}

	Assert(InMemHeap_CheckConstraints(inmemrel, tup));

	oldctx = MemoryContextSwitchTo(inmemrel->memcxt);

	insert_pos = AllocInMemoryCatalogInsertPosition(inmemrel);
	inmemtup = &inmemrel->tuples[insert_pos];
	inmemtup->flags = INMEM_HEAP_TUPLE_DISPATCHED;
	inmemtup->tuple = heaptuple_copy_to(tup, NULL, NULL);

	Assert(inmemtup->tuple != NULL);
	Assert(!HeapTupleHasExternal(inmemtup->tuple));
/* 	Assert(inmemtup->tuple->t_len <= TOAST_TUPLE_THRESHOLD); */
	inmemtup->tuple = heap_prepare_insert(relation, inmemtup->tuple, xid, cid, 0);
	ItemPointerSet(&inmemtup->tuple->t_self, insert_pos, MaxOffsetNumber);

#if 0
	if (inmemrel->hashIndex)
	{
		Oid			key;
		bool		isNull,
					found;
		MemHeapHashIndexEntry *entry;

		key = DatumGetObjectId(
							   heap_getattr(tup, inmemrel->keyAttrno,
											RelationGetDescr(inmemrel->rel), &isNull));

		Insist(!isNull && "index key cannot be null");

		entry = (MemHeapHashIndexEntry *) hash_search(inmemrel->hashIndex, &key,
													  HASH_ENTER, &found);

		if (!found)
		{
			entry->key = key;
			entry->values = NIL;
		}

		entry->values = lappend_int(entry->values, insert_pos);

		elog(DEBUG1, "add index %d key %d relation %s", insert_pos, key, inmemrel->relname);
	}
#endif

	MemoryContextSwitchTo(oldctx);

	CacheInvalidateHeapTuple(relation, tup, NULL);

	if (relid == NamespaceRelationId)
		CommandCounterIncrement();
}

/*
 * update a tuple in in-memory heap table.
 *
 * if the target tuple already in the memory,
 * update it in-place with flag INMEM_HEAP_TUPLE_UPDATED.
 * else report an error.
 *
 * update should not change the otid of the old tuple,
 * since updated tuple should write back to the master and update there.
 */
void
InMemHeap_Update(Relation relation, HeapTuple tup, uint32 position, bool inplace)
{
	HeapTuple	target;
	MemoryContext oldmem;
	InMemHeapRelation inmemrel;
	Oid			relid = RelationGetRelid(relation);
	TransactionId xid = GetCurrentTransactionId();
	CommandId	cid = GetCurrentCommandId(true);

	Assert(RelationIsValid(relation));
	Assert(position >= 0);
	inmemrel = OidGetInMemHeapRelation(relid, INMEM_ONLY_MAPPING);
	Assert(inmemrel);

	if (position >= inmemrel->tupsize)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("update a tuple which does not exist,"
						" relname = %s, relid = %u", inmemrel->relname,
						inmemrel->relid)));
	}

	Assert(inmemrel->hashIndex == NULL);
	oldmem = MemoryContextSwitchTo(inmemrel->memcxt);

	Assert(inmemrel->tuples[position].flags == INMEM_HEAP_TUPLE_DISPATCHED);

	target = heaptuple_copy_to(tup, NULL, NULL);
	Assert(target != NULL);
	target->t_tableOid = relid;
	Assert(!HeapTupleHasExternal(target));
/* 	Assert(target->t_len <= TOAST_TUPLE_THRESHOLD); */
	target = heap_prepare_insert(relation, target, xid, cid, 0);

	if (inplace)
	{
		ItemPointerSet(&target->t_self, position, MaxOffsetNumber);
		CacheInvalidateHeapTuple(relation, inmemrel->tuples[position].tuple, target);
		pfree(inmemrel->tuples[position].tuple);
		inmemrel->tuples[position].tuple = target;
	}
	else
	{
		HeapTuple	oldtup = inmemrel->tuples[position].tuple;
		TransactionId xmax_old_tuple;
		uint16		infomask_old_tuple,
					infomask2_old_tuple;
		bool		iscombo;
		uint32		new_pos;

		compute_new_xmax_infomask(HeapTupleHeaderGetRawXmax(oldtup->t_data),
								  oldtup->t_data->t_infomask,
								  oldtup->t_data->t_infomask2,
								  xid, LockTupleNoKeyExclusive, true,
								  &xmax_old_tuple, &infomask_old_tuple,
								  &infomask2_old_tuple);

		HeapTupleHeaderAdjustCmax(oldtup->t_data, &cid, &iscombo);

		/* Clear obsolete visibility flags, possibly set by ourselves above... */
		oldtup->t_data->t_infomask &= ~(HEAP_XMAX_BITS | HEAP_MOVED);
		oldtup->t_data->t_infomask2 &= ~HEAP_KEYS_UPDATED;
		/* ... and store info about transaction updating this tuple */
		Assert(TransactionIdIsValid(xmax_old_tuple));
		HeapTupleHeaderSetXmax(oldtup->t_data, xmax_old_tuple);
		oldtup->t_data->t_infomask |= infomask_old_tuple;
		oldtup->t_data->t_infomask2 |= infomask2_old_tuple;
		HeapTupleHeaderSetCmax(oldtup->t_data, cid, iscombo);

		new_pos = AllocInMemoryCatalogInsertPosition(inmemrel);

		inmemrel->tuples[new_pos].tuple = target;
		inmemrel->tuples[new_pos].flags = INMEM_HEAP_TUPLE_DISPATCHED;
		ItemPointerSet(&target->t_self, new_pos, MaxOffsetNumber);
		target->t_data->t_infomask |= HEAP_UPDATED;

		CacheInvalidateHeapTuple(relation, inmemrel->tuples[position].tuple, target);
	}

	MemoryContextSwitchTo(oldmem);

	if (relid == NamespaceRelationId)
		CommandCounterIncrement();
}

void
InMemHeap_Delete(Relation relation, uint32 position)
{
	InMemHeapRelation inmemrel;
	Oid			relid = RelationGetRelid(relation);
	MemoryContext oldmem;
	TransactionId xid = GetCurrentTransactionId();
	CommandId	cid = GetCurrentCommandId(true);

	Assert(RelationIsValid(relation));
	Assert(position >= 0);
	inmemrel = OidGetInMemHeapRelation(relid, INMEM_ONLY_MAPPING);
	Assert(inmemrel);

	if (position >= inmemrel->tupsize)
	{
		ereport(ERROR,
				(errcode(ERRCODE_INTERNAL_ERROR),
				 errmsg("delete a tuple which does not exist,"
						" relname = %s, relid = %u", inmemrel->relname,
						inmemrel->relid)));
	}

	oldmem = MemoryContextSwitchTo(inmemrel->memcxt);

	Assert(inmemrel->hashIndex == NULL);
	Assert(inmemrel->tuples[position].flags == INMEM_HEAP_TUPLE_DISPATCHED);
	Assert(inmemrel->tuples[position].tuple);

#if 0
	inmemrel->tuples[position].flags = INMEM_HEAP_TUPLE_IS_NULL;
	pfree(inmemrel->tuples[position].tuple);
	inmemrel->tuples[position].tuple = NULL;
	Assert(!list_member_oid(inmemrel->freelist, position));
	inmemrel->freelist = lappend_oid(inmemrel->freelist, position);
#endif

	{
		TransactionId new_xmax;
		uint16		new_infomask,
					new_infomask2;
		bool		iscombo;
		HeapTuple	oldtup = inmemrel->tuples[position].tuple;

		compute_new_xmax_infomask(HeapTupleHeaderGetRawXmax(oldtup->t_data),
								  oldtup->t_data->t_infomask, oldtup->t_data->t_infomask2,
								  xid, LockTupleExclusive, true,
								  &new_xmax, &new_infomask, &new_infomask2);

		HeapTupleHeaderAdjustCmax(oldtup->t_data, &cid, &iscombo);

		/* store transaction information of xact deleting the tuple */
		oldtup->t_data->t_infomask &= ~(HEAP_XMAX_BITS | HEAP_MOVED);
		oldtup->t_data->t_infomask2 &= ~HEAP_KEYS_UPDATED;
		oldtup->t_data->t_infomask |= new_infomask;
		oldtup->t_data->t_infomask2 |= new_infomask2;
		HeapTupleHeaderClearHotUpdated(oldtup->t_data);
		HeapTupleHeaderSetXmax(oldtup->t_data, new_xmax);
		HeapTupleHeaderSetCmax(oldtup->t_data, cid, iscombo);
	}

	MemoryContextSwitchTo(oldmem);

	CacheInvalidateHeapTuple(relation, inmemrel->tuples[position].tuple, NULL);

	if (relid == NamespaceRelationId)
		CommandCounterIncrement();
}

/*
 * CheckInMemConstraintsPgNamespace
 * 		Check uniqueness constraints for pg_namespace in-memory tuples upon insert
 */
static bool
CheckInMemConstraintsPgNamespace(InMemHeapRelation relation, HeapTuple newTuple)
{
	TupleDesc	tupleDesc = relation->tupledesc;
	char	   *nspnameNew;
	Oid			newOid;
	int			i;
	bool		hasoid;

	Assert(newTuple);
	Assert(relation);
	nspnameNew = DatumGetCString(tuple_getattr(newTuple, tupleDesc, Anum_pg_namespace_nspname));
	newOid = HeapTupleGetOid(newTuple);
	hasoid = tuple_has_oid(newTuple);

	for (i = 0; i < relation->tupsize; i++)
	{
		char	   *nspname;
		HeapTuple	tuple = relation->tuples[i].tuple;

		if (relation->tuples[i].flags == INMEM_HEAP_TUPLE_IS_NULL)
			continue;

		if (!HeapTupleSatisfiesVisibility(tuple, SnapshotSelf, InvalidBuffer))
			continue;

		Assert(tuple);
		if (hasoid && HeapTupleGetOid(tuple) == newOid)
			elog(ERROR, "in-memory tuple with Oid = %d already exists in pg_namespace.", newOid);

		nspname = DatumGetCString(tuple_getattr(tuple, tupleDesc, Anum_pg_namespace_nspname));
		if (pg_strcasecmp(nspname, nspnameNew) == 0)
			elog(ERROR, "in-memory tuple with nspname = %s already exists in pg_namespace.", nspnameNew);
	}

	return true;
}

/*
 * CheckInMemConstraintsPgClass
 * 		Check uniqueness constraints for pg_class in-memory tuples upon insert
 */
static bool
CheckInMemConstraintsPgClass(InMemHeapRelation relation, HeapTuple newTuple)
{
	TupleDesc	tupleDesc = relation->tupledesc;
	Oid			relnamespaceNew;
	char	   *relnameNew;
	int			i;
	Oid			newOid;
	bool		hasoid;

	Assert(newTuple);
	Assert(relation);
	relnamespaceNew = DatumGetObjectId(tuple_getattr(newTuple, tupleDesc, Anum_pg_class_relnamespace));
	relnameNew = DatumGetCString(tuple_getattr(newTuple, tupleDesc, Anum_pg_class_relname));
	newOid = HeapTupleGetOid(newTuple);
	hasoid = tuple_has_oid(newTuple);

	for (i = 0; i < relation->tupsize; i++)
	{
		Oid			relnamespace;
		char	   *relname;
		HeapTuple	tuple = relation->tuples[i].tuple;

		if (relation->tuples[i].flags == INMEM_HEAP_TUPLE_IS_NULL)
			continue;

		if (!HeapTupleSatisfiesVisibility(tuple, SnapshotSelf, InvalidBuffer))
			continue;

		Assert(tuple);
		if (hasoid && HeapTupleGetOid(tuple) == newOid)
			elog(ERROR, "in-memory tuple with Oid = %d already exists in pg_class.", newOid);

		relnamespace = DatumGetObjectId(tuple_getattr(tuple, tupleDesc, Anum_pg_class_relnamespace));
		relname = DatumGetCString(tuple_getattr(tuple, tupleDesc, Anum_pg_class_relname));
		if (relnamespace == relnamespaceNew && pg_strcasecmp(relname, relnameNew) == 0)
			elog(ERROR, "in-memory tuple with relname = %s and relnamespace = %d already exists in pg_class.", relnameNew, relnamespaceNew);
	}

	return true;
}

/*
 * CheckInMemConstraintsPgType
 * 		Check uniqueness constraints for pg_type in-memory tuples upon insert
 */
static bool
CheckInMemConstraintsPgType(InMemHeapRelation relation, HeapTuple newTuple)
{
	TupleDesc	tupleDesc = relation->tupledesc;
	Oid			relnamespaceNew;
	char	   *typnameNew;
	int			i;
	Oid			newOid;
	bool		hasoid;

	Assert(NULL != newTuple);
	Assert(NULL != relation);
	relnamespaceNew = DatumGetObjectId(tuple_getattr(newTuple, tupleDesc, Anum_pg_type_typnamespace));
	typnameNew = DatumGetCString(tuple_getattr(newTuple, tupleDesc, Anum_pg_type_typname));
	newOid = HeapTupleGetOid(newTuple);
	hasoid = tuple_has_oid(newTuple);

	for (i = 0; i < relation->tupsize; i++)
	{
		Oid			relnamespace;
		char	   *typname;
		HeapTuple	tuple = relation->tuples[i].tuple;

		if (relation->tuples[i].flags == INMEM_HEAP_TUPLE_IS_NULL)
			continue;

		if (!HeapTupleSatisfiesVisibility(tuple, SnapshotSelf, InvalidBuffer))
			continue;

		Assert(tuple);
		if (hasoid && HeapTupleGetOid(tuple) == newOid)
			elog(ERROR, "in-memory tuple with Oid = %d already exists in pg_type.", newOid);

		relnamespace = DatumGetObjectId(tuple_getattr(tuple, tupleDesc, Anum_pg_type_typnamespace));
		typname = DatumGetCString(tuple_getattr(tuple, tupleDesc, Anum_pg_type_typname));
		if ((relnamespace == relnamespaceNew && pg_strcasecmp(typname, typnameNew) == 0))
			elog(ERROR, "in-memory tuple with typname = %s and typnamespace = %d already exists in pg_type.", typnameNew, relnamespaceNew);
	}

	return true;
}

/*
 * CheckInMemConstraintsPgAttribute
 * 		Check uniqueness constraints for pg_attribute in-memory tuples upon insert
 */
static bool
CheckInMemConstraintsPgAttribute(InMemHeapRelation relation, HeapTuple newTuple)
{
	TupleDesc	tupleDesc = relation->tupledesc;
	Oid			attrelidNew;
	char	   *attnameNew;
	AttrNumber	attnoNew;
	int			i;

	Assert(newTuple);
	Assert(relation);
	attrelidNew = DatumGetObjectId(tuple_getattr(newTuple, tupleDesc, Anum_pg_attribute_attrelid));
	attnameNew = DatumGetCString(tuple_getattr(newTuple, tupleDesc, Anum_pg_attribute_attname));
	attnoNew = DatumGetInt16((tuple_getattr(newTuple, tupleDesc, Anum_pg_attribute_attnum)));

	for (i = 0; i < relation->tupsize; i++)
	{
		HeapTuple	tuple = relation->tuples[i].tuple;
		Oid			attrelid;
		char	   *attname;
		AttrNumber	attno;

		if (relation->tuples[i].flags == INMEM_HEAP_TUPLE_IS_NULL)
			continue;

		if (!HeapTupleSatisfiesVisibility(tuple, SnapshotSelf, InvalidBuffer))
			continue;

		Assert(tuple);
		attrelid = DatumGetObjectId(tuple_getattr(tuple, tupleDesc, Anum_pg_attribute_attrelid));
		attname = DatumGetCString(tuple_getattr(tuple, tupleDesc, Anum_pg_attribute_attname));
		attno = DatumGetInt16((tuple_getattr(tuple, tupleDesc, Anum_pg_attribute_attnum)));
		if (attrelid != attrelidNew)
			continue;

		if (attno == attnoNew)
			elog(ERROR, "in-memory tuple with attrelid = %d and attno = %d already exists in pg_attribute.", attrelidNew, attnoNew);

		if (pg_strcasecmp(attname, attnameNew) == 0)
			elog(ERROR, "in-memory tuple with attrelid = %d and attname = %s already exists in pg_attribute.", attrelidNew, attnameNew);
	}

	return true;
}

static bool
InMemHeap_CheckConstraints(InMemHeapRelation relation, HeapTuple newTuple)
{
	Oid			relid = relation->relid;
	CheckConstraintsFn fn = NULL;

	Assert(relation);
	Assert(newTuple);

	switch (relid)
	{
		case NamespaceRelationId:
			fn = CheckInMemConstraintsPgNamespace;
			break;
		case RelationRelationId:
			fn = CheckInMemConstraintsPgClass;
			break;
		case TypeRelationId:
			fn = CheckInMemConstraintsPgType;
			break;
		case AttributeRelationId:
			fn = CheckInMemConstraintsPgAttribute;
			break;
		default:
			return true;
	}

	if (fn)
		fn(relation, newTuple);

	return true;
}

/* ----------------
 *      tuple_getattr
 *
 *      Extracts an attribute from a HeapTuple given its attnum and
 *      returns it as a Datum.
 *
 *      <tuple> is the pointer to the heap tuple.  <attnum> is the attribute
 *      number of the column (field) caller wants.  <tupleDesc> is a
 *      pointer to the structure describing the row and all its fields.
 *
 * ----------------
 */
Datum
tuple_getattr(HeapTuple tuple, TupleDesc tupleDesc, int attnum)
{
	bool		isnull;
	Datum		attr = heap_getattr(tuple, attnum, tupleDesc, &isnull);

	Assert(NULL != tupleDesc);
	Assert(NULL != tuple);
	if (isnull)
		elog(ERROR, "attribute cannot be null in inmem tuple_getattr");

	return attr;
}

bool
IsTupleShouldStoreInMemCatalog(Relation relation, HeapTuple newTuple)
{
	Oid			relid = RelationGetRelid(relation);
	TupleDesc	tupleDesc = RelationGetDescr(relation);
	bool		recordInMemCatalog = false;

	if (IsBootstrapProcessingMode() || !CatalogMaybeStoreInMem(relation))
		return false;

	switch (relid)
	{
		case NamespaceRelationId:
			{
				char	   *nspname = DatumGetCString(tuple_getattr(newTuple, tupleDesc, Anum_pg_namespace_nspname));

				recordInMemCatalog = (strncmp(nspname, "pg_temp_", 8) == 0) || (strncmp(nspname, "pg_toast_temp_", 14) == 0);
			}
			break;
		case RelationRelationId:
			{
				char		relpersistence = DatumGetChar(tuple_getattr(newTuple, tupleDesc, Anum_pg_class_relpersistence));

				if (relpersistence == RELPERSISTENCE_TEMP)
				{
					char	   *relname = DatumGetCString(tuple_getattr(newTuple, tupleDesc, Anum_pg_class_relname));
					Oid			id = DatumGetObjectId(tuple_getattr(newTuple, tupleDesc, Anum_pg_class_relname));

					recordInMemCatalog = true;
					if (in_memory_catalog_log)
						elog(WARNING, "record pg_class %u %s into memcatalog", id, relname);
				}
			}
			break;
		case TypeRelationId:
			{
				Datum		typensp_datum = tuple_getattr(newTuple, tupleDesc, Anum_pg_type_typnamespace);

				if (NamespaceInMemCatalog(typensp_datum))
					recordInMemCatalog = true;
			}
			break;
		case AttributeRelationId:
			{
				Datum		attrelid_datum = tuple_getattr(newTuple, tupleDesc, Anum_pg_attribute_attrelid);

				if (RelationInMemCatalog(attrelid_datum))
					recordInMemCatalog = true;
			}
			break;
		case IndexRelationId:
			{
				Datum		indrelid_datum = tuple_getattr(newTuple, tupleDesc, Anum_pg_index_indrelid);

				if (RelationInMemCatalog(indrelid_datum))
					recordInMemCatalog = true;
			}
			break;

		case ConstraintRelationId:
			{
				Datum		conrelid_datum = tuple_getattr(newTuple, tupleDesc, Anum_pg_constraint_conrelid);

				if (RelationInMemCatalog(conrelid_datum))
					recordInMemCatalog = true;
			}
			break;

		case AttrDefaultRelationId:
			{
				Datum		attrrelid_datum = tuple_getattr(newTuple, tupleDesc, Anum_pg_attrdef_adrelid);

				if (RelationInMemCatalog(attrrelid_datum))
					recordInMemCatalog = true;
			}
			break;

		case SequenceRelationId:
			{
				Datum		seqrelid_datum = tuple_getattr(newTuple, tupleDesc, Anum_pg_sequence_seqrelid);

				if (RelationInMemCatalog(seqrelid_datum))
					recordInMemCatalog = true;
			}
			break;

		case DependRelationId:
			{
				Datum		depend_class_datum = tuple_getattr(newTuple, tupleDesc, Anum_pg_depend_classid);
				Datum		depend_oid_datum = tuple_getattr(newTuple, tupleDesc, Anum_pg_depend_objid);
				Oid			depend_classid = DatumGetObjectId(depend_class_datum);

				if (depend_classid == IndexRelationId &&
					IndexInMemCatalog(depend_oid_datum))
					recordInMemCatalog = true;
				else if (depend_classid == ConstraintRelationId &&
						 ConstraintInMemCatalog(depend_oid_datum))
					recordInMemCatalog = true;
				else if (depend_classid == RelationRelationId &&
						 RelationInMemCatalog(depend_oid_datum))
					recordInMemCatalog = true;
				else if (depend_classid == TypeRelationId &&
						 TypeInMemCatalog(depend_oid_datum))
					recordInMemCatalog = true;
				else if (depend_classid == AttrDefaultRelationId &&
						 AttrDefaultInMemCatalog(depend_oid_datum))
					recordInMemCatalog = true;
			}
			break;

		default:
			{
#if 0
				if (in_memory_catalog_log)
					elog(WARNING, "catalog %s tuple not record to memcatalog", get_rel_name(relid));
#endif
			}
			break;
	}

	if (in_memory_catalog_log && recordInMemCatalog)
		elog(WARNING, "insert record %s into memcatalog", get_rel_name(relid));

	return recordInMemCatalog;
}

static bool
NamespaceInMemCatalog(Datum nspid)
{
	InMemHeapRelation inmemrel = OidGetInMemHeapRelation(NamespaceRelationId, INMEM_ONLY_MAPPING);
	uint32		pos;

	if (!inmemrel || !OidIsValid(DatumGetObjectId(nspid)))
		return false;

	pos = GetTuplePositionByKeyAttr(inmemrel, Anum_pg_namespace_oid, nspid, InvalidAttrNumber, 0);

	return BlockNumberIsValid(pos);
}

static bool
AttrDefaultInMemCatalog(Datum attrdid)
{
	InMemHeapRelation inmemrel = OidGetInMemHeapRelation(AttrDefaultRelationId, INMEM_ONLY_MAPPING);
	uint32		pos;

	if (!inmemrel || !OidIsValid(DatumGetObjectId(attrdid)))
		return false;

	pos = GetTuplePositionByKeyAttr(inmemrel, Anum_pg_attrdef_adrelid, attrdid, InvalidAttrNumber, 0);

	return BlockNumberIsValid(pos);
}

static bool
TypeInMemCatalog(Datum typeid)
{
	InMemHeapRelation inmemrel = OidGetInMemHeapRelation(TypeRelationId, INMEM_ONLY_MAPPING);
	uint32		pos;

	if (!inmemrel || !OidIsValid(DatumGetObjectId(typeid)))
		return false;

	pos = GetTuplePositionByKeyAttr(inmemrel, Anum_pg_type_oid, typeid, InvalidAttrNumber, 0);

	return BlockNumberIsValid(pos);
}

static bool
RelationInMemCatalog(Datum relid)
{
	InMemHeapRelation inmemrel = OidGetInMemHeapRelation(RelationRelationId, INMEM_ONLY_MAPPING);
	uint32		pos;

	if (!inmemrel || !OidIsValid(DatumGetObjectId(relid)))
		return false;

	pos = GetTuplePositionByKeyAttr(inmemrel, Anum_pg_class_oid, relid, InvalidAttrNumber, 0);

	return BlockNumberIsValid(pos);
}

static bool
ConstraintInMemCatalog(Datum cid)
{
	InMemHeapRelation inmemrel = OidGetInMemHeapRelation(ConstraintRelationId, INMEM_ONLY_MAPPING);
	uint32		pos;

	if (!inmemrel || !OidIsValid(DatumGetObjectId(cid)))
		return false;

	pos = GetTuplePositionByKeyAttr(inmemrel, Anum_pg_constraint_oid, cid, InvalidAttrNumber, 0);

	return BlockNumberIsValid(pos);
}

static bool
IndexInMemCatalog(Datum indexid)
{
	InMemHeapRelation inmemrel = OidGetInMemHeapRelation(IndexRelationId, INMEM_ONLY_MAPPING);
	uint32		pos;

	if (!inmemrel || !OidIsValid(DatumGetObjectId(indexid)))
		return false;

	pos = GetTuplePositionByKeyAttr(inmemrel, Anum_pg_index_indexrelid, indexid, InvalidAttrNumber, 0);

	return BlockNumberIsValid(pos);
}

static uint32
GetTuplePositionByKeyAttr(InMemHeapRelation inmemrel, AttrNumber keyattr1, Datum key1, AttrNumber keyattr2, Datum key2)
{
	TupleDesc	tupleDesc;
	int			i;
	uint32		pos = InvalidBlockNumber;

	if (IsBootstrapProcessingMode())
		return InvalidBlockNumber;

	if (!inmemrel)
		return InvalidBlockNumber;

	Assert(AttributeNumberIsValid(keyattr1));
	tupleDesc = inmemrel->tupledesc;
	for (i = 0; i < inmemrel->tupsize; i++)
	{
		Datum		tmp1;

		if (inmemrel->tuples[i].flags == INMEM_HEAP_TUPLE_IS_NULL)
		{
			Assert(list_member_oid(inmemrel->freelist, i));
			continue;
		}

		tmp1 = tuple_getattr(inmemrel->tuples[i].tuple, tupleDesc, keyattr1);
		if (AttributeNumberIsValid(keyattr2))
		{
			Datum		tmp2 = tuple_getattr(inmemrel->tuples[i].tuple, tupleDesc, keyattr2);

			if (tmp1 == key1 && tmp2 == key2)
			{
				pos = i;
				break;
			}
		}
		else if (tmp1 == key1)
		{
			pos = i;
			break;
		}
	}

	return pos;
}

uint32
GetMemTuplePosition(Relation relation, ItemPointer tid)
{
	uint32		pos;
	Oid			relid = RelationGetRelid(relation);
	InMemHeapRelation inmemrel = OidGetInMemHeapRelation(relid, INMEM_ONLY_MAPPING);

	if (!IsCatalogRelation(relation))
		return InvalidBlockNumber;

	if (IsToastRelation(relation))
		return InvalidBlockNumber;

	if (ItemPointerGetOffsetNumber(tid) != MaxOffsetNumber)
		return InvalidBlockNumber;

	pos = ItemPointerGetBlockNumber(tid);
	Assert(!inmemrel || inmemrel->tuples[pos].flags == INMEM_HEAP_TUPLE_DISPATCHED);

	return pos;
}

static uint32
AllocInMemoryCatalogInsertPosition(InMemHeapRelation inmemrel)
{
	uint32		insert_pos;

	Assert(inmemrel);
	Assert(CurrentMemoryContext == inmemrel->memcxt);
	if (inmemrel->freelist != NIL)
	{
		uint32		free_pos = linitial_oid(inmemrel->freelist);

		Assert(inmemrel->tuples[free_pos].flags == INMEM_HEAP_TUPLE_IS_NULL);
		inmemrel->freelist = list_delete_oid(inmemrel->freelist, free_pos);
		insert_pos = free_pos;
	}
	else
	{
		if (inmemrel->tupsize >= inmemrel->tupmaxsize)
		{
			Assert(NULL != inmemrel->tuples);
			inmemrel->tuples = repalloc(inmemrel->tuples,
										sizeof(InMemHeapTupleData) * inmemrel->tupmaxsize * 2);
			inmemrel->tupmaxsize *= 2;
		}
		insert_pos = inmemrel->tupsize;
		inmemrel->tupsize++;
	}

	Assert(BlockNumberIsValid(insert_pos));

	return insert_pos;
}

bool
CatalogMaybeStoreInMem(Relation rel)
{
	return IsCatalogRelation(rel) && (RelationGetRelid(rel) != PublicationNamespaceRelationId);
}

static bool
tuple_has_oid(HeapTuple tuple)
{
	HeapTupleHeader tup = tuple->t_data;

	if (tup->t_infomask & HEAP_HASOID_OLD)
		return true;
	else
		return false;
}
