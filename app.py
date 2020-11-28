from flask import Flask, render_template, flash, render_template, url_for, session, logging, request, redirect, session
from flask_pymongo import PyMongo
from flask_login import current_user
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
import configparser
#from data import Jobs
from functools import wraps


app = Flask(__name__)
app.secret_key='secret123'
app.config['SESSION_TYPE'] = 'mongodb'

#config Mongo
app.config["MONGO_URI"] = "mongodb+srv://coen6313:coen6313@cluster0.00qnm.mongodb.net/<Help&_db>?retryWrites=true&w=majority"
#init Mongo
mongo = PyMongo(app)

#Jobs = Jobs()
@app.route('/')
def index():
    return render_template('home.html')

@app.route('/jobs')
def jobs():

    result = mongo.db.Jobs
    result.find()

    if result:
        return render_template('jobs.html', jobs=jobs)
    else:
        msg = 'No jobs Found'
        return render_template('jobs.html', msg=msg)

@app.route('/job/<string:id>/')
def job(id):

    result = mongo.db.Jobs
    result.find({_id:id})
    return render_template('dashboard.html', job=job)
    
class SignupForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    username  = StringField('Username', [validators.Length(min=1, max=50)])
    email = StringField('Email', [validators.Length(min=1, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))
        users = mongo.db.Users
        users.insert({'Name' : name, 'Email' : email, 'Username': username, 'Password': password})

        flash('You are registered')

        redirect(url_for('index'))
    return render_template("signup.html", form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password_candidate = request.form['password']

        result = mongo.db.Users
        result.find({username: username})

        if result:
            data = mongo.db.Users.find_one()
            password = data['Password']
            #comp pass
            if sha256_crypt.verify(password_candidate, password):
                app.logger.info('SUCCESSFUL')

                #passed
                session['logged_in'] = True
                session['username'] = username

                flash('You are logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)
        else: 
            error = 'Username not found'
            return render_template('login.html', error=error)
    return render_template('login.html')

def is_logged_in(i):
    @wraps(i)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return i(*args, **kwargs)
        else: 
            flash('Unathorized! Please login', 'danger')
            return redirect(url_for('login'))
    return wrap

@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('login'))

@app.route('/dashboard')
@is_logged_in
def dashboard():

    result = mongo.db.Jobs
    result.find()

    if result:
        return render_template('dashboard.html', jobs=jobs)
    else:
        msg = 'No jobs Found'
        return render_template('dashboard.html', msg=msg)

class JobForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=50)])
    description  = StringField('Description', [validators.Length(min=10)])

@app.route('/add_job', methods=['GET','POST'])
@is_logged_in
def add_job():
    form = JobForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        description = form.description.data

        jobs = mongo.db.Jobs
        jobs.insert({'title' : title, 'description' : description, 'creator': session['username']})

        flash('Job created sucessfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('add_job.html', form=form)

if __name__ == "__main__":
    app.secret_key='secret123'
    app.config['SESSION_TYPE'] = 'mongodb'
    app.run(debug=True) #debug true is for not to restart the server everytime