from flask import Flask, render_template, request
import sqlite3
from datetime import datetime

def open_db():
	conn = sqlite3.connect("db.db")
	return conn

app = Flask(__name__)

@app.route('/')
def index():
	conn = open_db()
	cur = conn.cursor()

	cur.execute("SELECT * FROM info LIMIT 1")
	info = cur.fetchone()

	cur.execute("SELECT * FROM issues WHERE is_actual = 1 ORDER BY id")
	issues = cur.fetchall()
	columns = [desc[0] for desc in cur.description]
	col_nm = {columns[i]: i for i in range(len(columns))}
	date = datetime.fromtimestamp(issues[0][col_nm['timest']])
	conn.close()
	return render_template('index.html', kver=info[0], issues=issues, last_update=str(date), count=len(issues))

@app.route("/view")
def view():
	iid = request.args.get("id")
	conn = open_db()
	cur = conn.cursor()
	cur.execute("SELECT * FROM issues WHERE id=?", (int(iid),))
	issue = cur.fetchone()
	conn.close()
	return render_template('view.html', iid=issue[0], fname=issue[1], diff=issue[3].replace("\t", "&nbsp;&nbsp;&nbsp;&nbsp;").replace("\n", "<br>"), messages=issue[2].split("\n"))
