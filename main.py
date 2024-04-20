from flask import Flask, request, render_template, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from random import randint
from flask_mail import Mail, Message
import os
from flask import Flask, redirect, url_for, session, request
from flask_oauthlib.client import OAuth
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Change this to your own secret key

oauth = OAuth(app)

google = oauth.remote_app(
    'google',
    consumer_key= os.getenv("CONSUMER_KEY"),
    consumer_secret=os.getenv("CONSUMER_SECRET"),  
    request_token_params={
        'scope': 'email'
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)


secret_key = os.urandom(24)

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = secret_key 
app.config['MAIL_SERVER'] = 'imap.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'dhruvkumawatdk3@gmail.com'
app.config['MAIL_PASSWORD'] = os.getenv("APP_PASSWORD")

db = SQLAlchemy(app)
mail = Mail(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(50), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    dob = db.Column(db.String(20), nullable=False)
    email = db.Column(db.String(50), unique=True, nullable=False)

def send_otp(email):
    otp = str(randint(100000, 999999))
    msg = Message('One Time Password', sender='your_email@example.com', recipients=[email])
    msg.body = f'Your One Time Password is: {otp}'
    mail.send(msg)
    return otp

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        print(request.form)
        username = request.form['username']
        password = request.form['password']
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        dob = request.form['dob']
        email = request.form['email']
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose another username.', 'error')
            return redirect(request.url)

        otp = send_otp(email)
        # After sending OTP
        return render_template('verify_otp.html', email=email, otp=otp, form_data=request.form)


        # return render_template('verify_otp.html', email=email, otp=otp)

    return render_template('signup.html')




@app.route('/verify_otp', methods=['POST'])
def verify_otp():
    username = request.form['username']
    password = request.form['password']
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    dob = request.form['dob']
    email = request.form['email']
    entered_otp = request.form['otp']
    otp = request.form['original_otp']
    global fn, ln
    
    if entered_otp == otp:
        new_user = User(username=request.form['username'],
                        password=request.form['password'],
                        first_name=request.form['first_name'],
                        last_name=request.form['last_name'],
                        dob=request.form['dob'],
                        email=email)
        try:
            db.session.add(new_user)
            db.session.commit()
            
            flash('Signup successful!', 'success')
        except IntegrityError:
            db.session.rollback()
            flash('Error: User already exists.', 'error')

        return redirect('/')
    else:
        flash('Incorrect OTP. Please try again.', 'error')
        return redirect(request.referrer)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()

        if user and user.password == password:
            # Password is correct, redirect to welcome page
            return render_template('welcome.html', username=username, first_name = user.first_name, last_name = user.last_name)
        else:
            # Incorrect username or password
            flash('Incorrect username or password.', 'error')
            return redirect(request.url)

    return render_template('login.html')



@app.route('/logingoogle')
def logingoogle():
    return google.authorize(callback=url_for('authorized', _external=True))

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.pop('google_token', None)
    session.pop('user_info', None)
    session.clear()
    return render_template("index.html")

@app.route('/logingoogle/authorized')
def authorized():
    resp = google.authorized_response()
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason={}, error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    session['google_token'] = (resp['access_token'], '')
    user_info = google.get('userinfo')
    # Here you can handle user_info data, like displaying user information
    # return 'Logged in as: ' + user_info.data['email']
    return render_template('googlelogin.html', email = user_info.data['email'])

@google.tokengetter
def get_google_oauth_token():
    return session.get('google_token')

@app.route('/view_users')
def view_users():
    users = User.query.all()
    return render_template('view_users.html', users=users)


@app.route('/remove_user', methods=['GET'])
def remove_user_form():
    return render_template('remove_user.html')

@app.route('/remove_user', methods=['POST'])
def remove_user():
    username = request.form['username']
    user_to_remove = User.query.filter_by(username=username).first()
    if user_to_remove:
        db.session.delete(user_to_remove)
        db.session.commit()
        return f'Removed user with username: {username}'
    else:
        return f'User with username {username} not found'

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
