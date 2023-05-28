import os
import time
import hashlib
import sqlite3
import re
import subprocess
from pathlib import Path

NUM_CORES = 12
linux_path = os.getenv("LINUX_SRC")
scripts_dirs = ["{}/scripts/coccinelle/".format(linux_path), "./local_cocci/"]

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

def find_all_issues():
	scripts = find_cocci()
	res = []
	for script in scripts:
		print("Script:", script)
		try:
			data = exec_cocci(script)
			tres = parse_cocci_res(data)
			print("Found", len(tres), "files")
			res.extend(tres)
		except Exception as e:
			print(e)
			print("Error")
	return res


def update_issues():
	issues = find_all_issues()
	hashes = set()
	for issue in issues:
		hashes.add(hashlib.sha256(issue.diff.encode('utf-8')).hexdigest())
	conn = sqlite3.connect('db.db')
	cur =  conn.cursor()
	cur.execute("SELECT * FROM issues")
	rows = cur.fetchall()
	colnames = [desc[0] for desc in cur.description]
	print(colnames)
	colnums = {colnames[i]: i for i in range(len(colnames))}
	print(colnums)
	try:
		cur.execute("begin")
		for row in rows:
			if row[colnums['hash']] not in hashes:
				cur.execute("UPDATE issues SET is_actual = 0 WHERE id = ?", (row[colnums['id']],))
		cur.execute("commit")
	except Exception as e:
		print(str(e))
		print("Error during set is_actual")
		cur.execute("rollback")

	try:
		cur.execute("begin")
		for issue in issues:
			curhash = hashlib.sha256(issue.diff.encode('utf-8')).hexdigest()
			cur.execute("SELECT * FROM issues WHERE hash = ?", (curhash,))
			r = cur.fetchone()
			if r is None:
				cur.execute("INSERT INTO issues (id, fname, messages, diff, hash, is_actual, timest) VALUES(NULL, ?, ?, ?, ?, ?, ?)", \
					    (issue.fname, "\n".join(issue.messages), issue.diff, curhash, 1, int(time.time())))
		cur.execute("commit")
	except Exception as e:
		print("Error", e);
		cur.execute("rollback")
	conn.commit()
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
	cur.execute("UPDATE info SET kernel_ver = ?", (fetch_kernel_ver(),))
	conn.commit()
	conn.close()

update_issues()
update_info()
