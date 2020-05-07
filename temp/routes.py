import os
from flask import Flask, flash, redirect, render_template, request, session, abort, url_for
from flask import send_from_directory
from flask_pymongo import PyMongo
from . forms import LoginForm, RegistrationForm
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from app import app


UPLOAD_FOLDER = "app/uploads"
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}


app.config['UPLOAD_FOLDER']= UPLOAD_FOLDER
client = MongoClient('localhost', 27017)
db = client.wad

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if not session.get('username'):
        flash('You are not authenticated')
        return redirect(url_for('login'))
    else:
        return render_template('index.html')


@app.route('/cabinet')
def cabinet():
    if session['username']:
        return render_template('cabinet.html')
    else:
        flash('You are not authenticated')
    return redirect(url_for('login'))


@app.route('/static/images/<path:filename>')
def imgFile(filename):
    if session['username']:
        return send_from_directory('/app/static/images', filename)
    else:
        flash('You are not authenticated')
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    try:
        if session['username']:
            return  redirect(url_for('index'))
    except Exception:
        pass
    form = LoginForm(request.form)
    if form.validate_on_submit():
        user = form.username.data
        password = form.password.data
        login_user = mongo.db.users.find_one({'username':user})
        if login_user is None or not check_password_hash(login_user['password'], password):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        session['username'] = True
        return redirect(url_for('index'))
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = form.username.data
        email = form.email.data
        password = generate_password_hash(form.password.data)
        mongo.db.users.insert({'username':user, 'email':email,'password':password})
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    else:
        flash('Wrong')
    return render_template('register.html', title='Register', form=form)

@app.route('/logout')
def logout():
    session.clear()
    session['username'] = False
    return redirect(url_for('login'))

@app.route('/cabinet', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            return redirect(url_for('uploaded_file',filename=filename))
    return render_template('cabinet.html')

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],filename)