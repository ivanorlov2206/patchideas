import sys
import os
import time
import hashlib
import sqlite3
import re
import subprocess
from pathlib import Path

linux_path = os.getenv("LINUX_SRC")
scripts_dirs = ["{}/local_cocci/".format(os.getcwd()), "{}/scripts/coccinelle/".format(linux_path)]

class Issue():
	fname = ""
	messages = []
	diff = ""

def find_cocci():
	res = []
	for sdir in scripts_dirs:
		for path in Path(sdir).rglob("*.cocci"):
			p = str(path)
			f = open(p, 'r')
			data = f.read(1024)
			f.close()
			if 'Confidence: High' in data:
				res.append(p)
	return res

def exec_cocci(script_path):
	result = subprocess.run(['spatch', '-D', 'report', '--sp-file', script_path, '--very-quiet', '--dir', '.'], cwd=linux_path, stdout=subprocess.PIPE);
	return result.stdout.decode('utf-8')

def get_fname(line):
	return line.split(":")[0]

def parse_cocci_res(data):
	diff_lines = []
	info_lines = {}

	info_pattern = re.compile("^.+:[0-9]+:[0-9]+-[0-9]+:.+$")

	data_lines = data.split("\n")
	for line in data_lines:
		if info_pattern.match(line):
			fname = get_fname(line)
			if not fname in info_lines:
				info_lines[fname] = []
			info_lines[fname].append(line)
		else:
			diff_lines.append(line)

	diff_str = '\n'.join(diff_lines)
	res = []
	diffs = diff_str.split("diff -u -p ");
	for i in range(len(diffs)):
		if diffs[i].rstrip() == "":
			continue
		fname = diffs[i].split()[0]
		d = Issue()
		d.fname = fname
		d.messages = info_lines[fname]
		d.diff = "diff -u -p " + diffs[i]
		res.append(d)
	return res

def get_issues_colnums(cur):
	cur.execute("SELECT * FROM issues LIMIT 1")
	colnames = [desc[0] for desc in cur.description]
	return {colnames[i]: i for i in range(len(colnames))}

def update_is_actual(cur, new_issues):
	hashes = set()
	for issue in new_issues:
		hashes.add(hashlib.sha256(issue.diff.encode('utf-8')).hexdigest())
	cur.execute("SELECT * FROM issues")
	rows = cur.fetchall()
	colnums = get_issues_colnums(cur)
	try:
		cur.execute("begin")
		for row in rows:
			if row[colnums['hash']] not in hashes:
				cur.execute("UPDATE issues SET is_actual = 0 WHERE id = ?", (row[colnums['id']],))
		cur.execute("commit")
	except Exception as e:
		print("Error during set is_actual", e)
		cur.execute("rollback")


def load_issues(cur, issues):
	colnums = get_issues_colnums(cur)
	try:
		cur.execute("begin")
		for issue in issues:
			curhash = hashlib.sha256(issue.diff.encode('utf-8')).hexdigest()
			cur.execute("SELECT * FROM issues WHERE hash = ?", (curhash,))
			r = cur.fetchone()
			if r is None:
				cur.execute("INSERT INTO issues (id, fname, messages, diff, hash, is_actual, timest) VALUES(NULL, ?, ?, ?, ?, ?, ?)", \
					    (issue.fname, "\n".join(issue.messages), issue.diff, curhash, 1, int(time.time())))
			else:
				cur.execute("UPDATE issues SET is_actual = 1 WHERE id = ?", (r[0],))
		cur.execute("commit")
	except Exception as e:
		print("Error during inserting", e);
		cur.execute("rollback")


def update_issues():
	conn = sqlite3.connect('db.db')
	cur = conn.cursor()
	scripts = find_cocci()
	res = []
	for script in scripts:
		print("Script:", script)
		try:
			data = exec_cocci(script)
			tres = parse_cocci_res(data)
			print("Found", len(tres), "files")
			load_issues(cur, tres)
			conn.commit()
			res.extend(tres)
		except Exception as e:
			ex_type, ex_obj, ex_tb = sys.exc_info()
			print(ex_type, ex_tb.tb_lineno)
			print("Error")
	update_is_actual(cur, res)
	conn.close()

def fetch_kernel_ver():
	f = open("{}/Makefile".format(linux_path), 'r')
	lines = f.readlines()
	version = lines[1].rstrip().split()[-1]
	patchlevel = lines[2].rstrip().split()[-1]
	sublevel = lines[3].rstrip().split()[-1]
	extraversion = lines[4].rstrip().split()[-1]

	return "{}.{}.{}{}".format(version, patchlevel, sublevel, extraversion)

def update_info():
	conn = sqlite3.connect('db.db')
	cur = conn.cursor()
	cur.execute("UPDATE info SET kernel_ver = ?, last_update = ?", (fetch_kernel_ver(),int(time.time())))
	conn.commit()
	conn.close()

update_issues()
update_info()
