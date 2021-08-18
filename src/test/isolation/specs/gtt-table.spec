# Tests for global temporary relations

initialize
{
  create global temp table gtt_on_commit_delete_row(a int primary key, b text) on commit delete rows;
  create global temp table gtt_on_commit_preserve_row(a int primary key, b text) on commit preserve rows;
}

destroy
{
  DROP TABLE gtt_on_commit_delete_row;
  DROP TABLE gtt_on_commit_preserve_row;
}

# Session 1
session "s1"
step "s1_begin" { begin; }
step "s1_commit" { commit; }
step "s1_rollback" { rollback; }
step "s1_insert" { insert into gtt_on_commit_delete_row values(1, 'test1'); }
step "s1_select" { select * from gtt_on_commit_delete_row order by a,b; }
teardown
{
  TRUNCATE gtt_on_commit_delete_row;
  TRUNCATE gtt_on_commit_preserve_row;
}

# Session 2
session "s2"
step "s2_begin" { begin; }
step "s2_commit" { commit; }
step "s2_rollback" { rollback; }
step "s2_insert" { insert into gtt_on_commit_preserve_row values(10, 'test10'); }
step "s2_select" { select * from gtt_on_commit_preserve_row order by a,b; }
teardown
{
  TRUNCATE gtt_on_commit_delete_row;
  TRUNCATE gtt_on_commit_preserve_row;
}

permutation "s1_select" "s2_select" "s1_insert" "s2_insert" "s1_select" "s2_select"
permutation "s1_select" "s2_select" "s1_begin" "s2_begin" "s1_insert" "s2_insert" "s1_select" "s2_select" "s1_commit" "s2_commit" "s1_select" "s2_select"
permutation "s1_select" "s2_select" "s1_begin" "s2_begin" "s1_insert" "s2_insert" "s1_select" "s2_select" "s1_rollback" "s2_rollback" "s1_select" "s2_select"

