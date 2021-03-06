## Current status

There are six serious issues which are inherited from the original EDB's zheap.

- Regression test
  + TRIGGER related issue in src/test/regress/sql/trigger.sql
  + SAVEPOINT related issue in src/test/regress/sql/transactions.sql
  + ROW LEVEL SECURITY related issue in src/test/regres/sql/rowsecrity.sql
- Isolation test
    + TRIGGER related issue in src/test/isolation/specs/eval-plan-qual-trigger.specs
    + SERIALIZABILITY related issue in src/test/isolation/specs/update-conflict-out.specs
    + DEADLOCK DETECTING related issue in src/test/isolation/specs/tuplelock-upgrade-no-deadlock.specs


## zheap test suites

zheap test suites is added.

### Initialization

Before running the zheap test for the first time, `make check` should be run in `src/test/regress` to initialize the environment.

```
$ cd src/test/regress
$ make check
```

### regression tests

After initialization, you can run the zheap test any number of times.

```
$ cd src/test/regress
$ make check-zheap
```

It will be currently returned 3 errors (trigger.sql, transactions.sql, rowsecrity.sql).

If you find other errors, check	`src/regress/regression.diffs` file. In almost cases, there is no problem.


### isolation tests

```
$ cd src/test/isolation
$ make check-zheap
```

It will be currently returned 3 errors (eval-plan-qual, update-conflict-out, tuplelock-upgrade-no-deadlock).

If you find other errors, check	`src/test/isolation/output_iso/regression.diffs` file. In almost cases, there is no problem.

Note:
 1. eval-plan-qual.spec returns error, however, the cause comes from ctid. Therefore, there is no problem with zheap.
 2. Since eval-plan-qual-trigger.spec causes an unrecoverable database cluster corruption by heapam (not zheapam), we omit this test from the isolation_schedule.

