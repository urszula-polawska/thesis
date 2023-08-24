from flask import Flask, session, request, render_template
from pymongo import MongoClient
from argon2 import PasswordHasher
import os

app = Flask(__name__) # app instance
ph = PasswordHasher() # Argon2 instance
app.secret_key = os.urandom(42) # session

'''from dotenv import load_dotenv
load_dotenv() # to store "CONNECTION_STRING" in ".env" file
connection_string = os.getenv("CONNECTION_STRING") # get "CONNECTION_STRING" from ".env"
client = MongoClient(connection_string, tlsAllowInvalidCertificates=True)'''
client = MongoClient('localhost', 27017) # http://127.0.0.1:5000

db = client['thesis_database'] # define "mongo_database" database in MongoDB
thesis_users = db['thesis_users'] # define "mongo_users" collection in "mongo_database"

@app.route('/')
def home_page():
    return render_template('home_page.html')

@app.route('/login', methods=['POST'])
def mongoDB_login():
    u_name = request.form['username']
    u_pass = request.form['password']
    mongoDB_user = thesis_users.find_one({'username': u_name})
    if mongoDB_user: # if username exists in collection:
        if ph.verify(mongoDB_user['password'], u_pass):
            session['username'] = u_name # start session with "app.secret_key"
    return render_template('home_page.html', WRONG_LOGIN_CREDENTIALS=True)

@app.route('/register', methods=['POST', 'GET'])
def mongoDB_register():
    if request.method == 'POST':
        email = request.form['email']
        username = request.form['username']
        password = request.form['password']
        argon2_password = ph.hash(password) # encrypt entered password with Argon2
        if thesis_users.find_one({'username': username}):
            username = request.form['username']
            return render_template('home_page.html', USERNAME_NOT_AVAILABLE=True)
        thesis_users.insert_one({'email': email, 'username': username, 'password': argon2_password})
        session['username'] = username # start session with "app.secret_key"
    return render_template('home_page.html')  

@app.route('/logout', methods=['POST'])
def mongoDB_logout():
    session.pop('username', None)
    return render_template('home_page.html')  

if __name__ == '__main__':
    app.run()
