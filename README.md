# ZHEAP on PostgreSQL 13

This is a temporal working repository for ZHEAP upgrading, which developing branch is `REL_13_ZHEAP`.

## Current status

This is based on PG version 13.0.  (REL_13_STABLE: commit db8e60b82d6af88a4c8e1f9572abd5f5d84906b2)

+ pgbench can be done.
+ All regression test and isolation test are passed except six tests shown bellow.
+ There are six serious issues which are inherited from the original EDB's zheap.
  - Regression test
    + TRIGGER related issue in src/test/regress/sql/trigger.sql
    + SAVEPOINT related issue in src/test/regress/sql/transactions.sql
    + ROW LEVEL SECURITY related issue in src/test/regres/sql/rowsecrity.sql
  - Isolation test
    + TRIGGER related issue in src/test/isolation/specs/eval-plan-qual-trigger.specs
    + SERIALIZABILITY related issue in src/test/isolation/specs/update-conflict-out.specs
    + DEADLOCK DETECTING related issue in src/test/isolation/specs/tuplelock-upgrade-no-deadlock.specs

## Compile

```
$ cd postgresql_zheap
$ git checkout REL_13_ZHEAP
$ ./configure --prefix=/some/where/dir
$ make && make install
```

## zheap test suites

zheap test suites is added.


### Initialization

Before running the zheap test for the first time, `make check` should be run in `src/test/regress` to initialize the environment.

```
$ cd src/test/regress
$ make check
```

### regression


After initialization, you can run the zheap test any number of times.

```
$ cd src/test/regress
$ make check-zheap
```

It will be currently returned 3 errors (trigger.sql, transactions.sql, rowsecrity.sql).

### isolation

```
$ cd src/test/isolation
$ make check-zheap
```

It will be currently returned 3 errors (eval-plan-qual, update-conflict-out, tuplelock-upgrade-no-deadlock).

Note:
 1. eval-plan-qual.spec returns error, however, the cause comes from ctid. Therefore, there is no problem with zheap.
 2. Since eval-plan-qual-trigger.spec causes an unrecoverable database cluster corruption by heapam (not zheapam), we have omitted this test from the isolation_schedule.


## TODO

 + Fix the issues shown above.
 + Porting PREFETCH feature.
