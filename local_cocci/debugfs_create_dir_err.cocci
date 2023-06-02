// Confidence: High

virtual report

@r exists@
expression E1;
position p1;
@@

E1 = \(debugfs_create_dir\|debugfs_create_file\|debugfs_rename\|debugfs_create_symlink\)(...);
(
!E1 || IS_ERR(E1)
|
* !E1@p1
)

@script:python depends on report@
p1 << r.p1;
@@
msg = "Wrong debugfs call error processing on line %s" % (p1[0].line)
coccilib.report.print_report(p1[0], msg)
