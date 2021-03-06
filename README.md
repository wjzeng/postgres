# ZHEAP on PostgreSQL 13

This is a temporal working repository for ZHEAP upgrading, which developing branch is `REL_13_ZHEAP`.

(At first, this branch was created to understand the zheap architecture, and also to understand the pluggable storage infrastructure in PostgreSQL.)

## Current status

This is based on PG version 13.0.  (REL_13_STABLE: commit db8e60b82d6af88a4c8e1f9572abd5f5d84906b2)

+ pgbench can be done.
+ All regression test and isolation test are passed except six tests. See the [README in src/test](src/test/README.md) in details.

## Compile

```
$ git checkout REL_13_ZHEAP
$ ./configure --prefix=/some/where/dir
$ make && make install
```

## TODO

 + Fix the issues shown in [README in src/test](src/test/README.md).
 + Porting PREFETCH feature.
