from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask import send_from_directory
from werkzeug.utils import secure_filename
from flask_login import LoginManager
from flask_login import login_required, logout_user, current_user, login_user
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from werkzeug.urls import url_parse
import re, os
import pymongo

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}
basedir = os.path.abspath(os.path.dirname(__file__))

client = pymongo.MongoClient("mongodb+srv://wad:Pablin1492@cluster0-s8hsf.mongodb.net/test")
db = client["wad"]
users = db["users"]
users.create_index("username")
app.secret_key = "super secret key"

login_manager = LoginManager(app)
login_manager.login_view = 'login'

app.config['UPLOAD_FOLDER']= UPLOAD_FOLDER
bootstrap = Bootstrap(app)

 
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'), 'favicon.ico', mimetype='favicon.ico')

def add_user_to_db(username,email,password):
      users.insert({
            "username": username,
            "password": password,
            "email": email
        })
    
def check_user_in_db(username):
    # user = users.find({"username":username})
    user = users.find_one({"username":username})
    print (user)
    if user :        
       
        return True

def check_pass_in_db(username,password):
        user=users.find_one({"username":username})
        if user["password"] == password:
            return username

class User:
    def __init__(self, username):
        self.username = username

    @staticmethod
    def is_authenticated():
        return True

    @staticmethod
    def is_active():
        return True

    @staticmethod
    def is_anonymous():
        return False

    def get_id(self):
        return self.username

    @staticmethod
    def check_password(password_hash, password):
        return check_password_hash(password_hash, password)


@login_manager.user_loader
def load_user(username):
        u = users.find_one({"username":username})
        print (u)
        if not u:
            return None
        return User(username=u['username'])



def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS   

class Login(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')
    login = SubmitField('Login')
   

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Login()

    if form.validate_on_submit():
        user = users.find_one({"username": form.username.data})
        print("textoIn")
        print(user)
        print("textoOut")
        if user and User.check_password(user['password'], form.password.data):
                user_obj = User(username=user['username'])
                login_user(user_obj, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        user = users.find_one({"username": form.username.data})
        if user:
            return '<h1>Existing user, please create a different user!</h1>'
        
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        add_user_to_db(username=form.username.data, email=form.email.data, password=hashed_password)
                 
                     

        return '<h1>New user has been created!</h1>'
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

                        
@app.route('/cabinet', methods=['Get','POST'])
@login_required
def dashboard():
    
        return render_template('cabinet.html', name=current_user.username)
 
  

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
            
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
            
        if not allowed_file(file.filename):
            flash('Invalid file extension', 'danger')
            return redirect(request.url)
            
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            
            flash('Successfully saved', 'success')
            return redirect(url_for('uploaded_file', filename=filename))
    return render_template('upload.html', name=current_user.username)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],filename)

@app.route('/logout')

def logout():
    session.pop('username', None)
    return redirect(url_for('index'))
  
if __name__ == '__main__':
    
    app.run( port='5000',threaded=True)