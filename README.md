# ZHEAP on PostgreSQL 13

This is a *TEMPORAL WORKING* repository for ZHEAP upgrading, which developing branch is `REL_13_ZHEAP`.


The original ZHEAP repository doesn't consider version upgrades. Therefore, upgrade work will be done in this temporary repository.

In the future, I plan to merge it with the ZHEAP repository.


## Current status and Branch

This is based on PG version 13 beta 3 (2020.9.9 version).


The developing branch is `REL_13_ZHEAP`.

+ pgbench can be done.
+ Passed regression test (make check).
+ Passed tests (make check-world) without `eval-plan-qual-trigger`.

## Compile

```
$ cd postgresql_zheap
$ git checkout REL_13_ZHEAP
$ ./configure --prefix=/some/where/dir
$ make && make install
```

## How to set up  pgbench

After issuing `initdb` command, edit `postgresql.conf` file.

```
default_table_access_method = 'zheap'
```

Then, issue `pg_ctl start`, `createdb` and `pgbench` commands.

```
$ pg_ctl -D data start
$ createdb zheap
$ pgbench -i zheap
```

Check the relations.

```
$ ./bin/psql zheap
psql (13beta3)
Type "help" for help.

zheap=# \d+ pgbench_accounts
                                  Table "public.pgbench_accounts"
  Column  |     Type      | Collation | Nullable | Default | Storage  | Stats target | Description
----------+---------------+-----------+----------+---------+----------+--------------+-------------
 aid      | integer       |           | not null |         | plain    |              |
 bid      | integer       |           |          |         | plain    |              |
 abalance | integer       |           |          |         | plain    |              |
 filler   | character(84) |           |          |         | extended |              |
Indexes:
    "pgbench_accounts_pkey" PRIMARY KEY, btree (aid)
Access method: zheap
Options: fillfactor=100

```

Issue pgbench.

```
$ pgbench zheap
starting vacuum...end.
transaction type: <builtin: TPC-B (sort of)>
scaling factor: 1
query mode: simple
number of clients: 1
number of threads: 1
number of transactions per client: 10
number of transactions actually processed: 10/10
latency average = 1.938 ms
tps = 516.027931 (including connections establishing)
tps = 661.774871 (excluding connections establishing)
```

## How to do regression test

Delete the line "test: eval-plan-qual-trigger" test from  `~/src/test/isonation/isolation_schedule` file, and do:

```
$ make check-world
```

## TODO

 + Check trigger feature to pass the `eval-plan-qual-trigger` test.
 + Porting PREFETCH feature.
 + Check recovery feature and replication feature.
 + Check *ALL ZHEAP FEATURES* since the native regression tests are not enough to check them.
