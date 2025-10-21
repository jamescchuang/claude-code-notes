import pymysql
from requests import session

def get_user_input():
	username = input("Enter username: ")
	password = input("Enter password: ")
	return username, password

username, password = get_user_input()
db = pymysql.connect("localhost")
cursor = db.cursor()
cursor.execute("SELECT * FROM users WHERE username = '%s' AND password = '%s'" % (username, password))

record = cursor.fetchone()

if record:
	session['logged_user'] = username

db.close()