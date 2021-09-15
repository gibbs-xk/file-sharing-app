from flask import (
	Flask,
	abort,
	render_template,
	request,
	redirect,
	session
)

from flask_pymongo import PyMongo
import pymongo
from cfg import config
from hashlib import sha256
from datetime import datetime
from utils import get_random_string
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config["MONGO_URI"] = config['mongo_uri']
app.config['UPLOAD_FOLDER'] = r"\Project\uploads"
app.secret_key = b'afsd#@%$@asdf'

mongo = PyMongo(app)

@app.route('/')
def home_page():
	error = ''
	if 'error' in session:
		error = session['error']
		session.pop('error', None)

	if not 'userToken' in session:
		session['error'] : 'You must login to access this page'
		return redirect('/login')
	
	# Validate user token
	token_document = mongo.db.user_tokens.find_one({
		'sessionHash': session['userToken']
		})

	if token_document is None:
		session.pop('userToken', None)
		session['error'] = 'You must login again to access this page'
		return redirect('/login')



	userId = token_document['userId']

	user = mongo.db.users.find_one({
		'_id': userId
	})

	uploaded_files = mongo.db.files.find({
		'userId' : userId,
		'isActive' : True
	}).sort('createdAt', pymongo.DESCENDING)

	# TODO format file data: size and date

	return render_template('files.html',
						   uploaded_files=uploaded_files,
						   user=user,
						   error=error
	)

@app.route('/signup')
def signup():
	error = ''
	if 'error' in session:
		error = session['error']
		session.pop('error', None)
	#return abort(404)
	return render_template('signup.html',error=error)

@app.route('/login')
def login():

	# Check if valid session exists
	if 'userToken' in session:
		# Validate user token from database
		token_document = mongo.db.user_tokens.find_one({
		'sessionHash': session['userToken']
		})
		
		# Redirect to / if session is valid
		if token_document is not None:
			return redirect('/')

	signupSuccess = ''
	if 'signupSuccess' in session:
		signupSuccess = session['signupSuccess']
		session.pop('signupSuccess', None)

	error = ''
	if 'error' in session:
		error = session['error']
		session.pop('error', None)

	#return abort(404)
	return render_template('login.html',
		error=error,
		signupSuccess=signupSuccess
	)

@app.route('/check_login', methods = ['POST'])
def check_login():
	try :
		email = request.form['email']
	except KeyError:
		email = ''
	try:
		password = request.form['password']
	except KeyError:
		password = ''

	# Check if email is blank
	if not len(email) > 0:
		session['error'] = 'Email is required'
		return redirect('/login')

	# Check if password is blank
	if not len(password) > 0:
		session['error'] = 'Password is required'
		return redirect('/login')

	# Check if email is in DB
	user_document = mongo.db.users.find_one({"email": email})
	if user_document is None:
		session['error'] = 'There is no registered user with this email'
		return redirect('/login')

	# Verify password hash match
	password_hash = sha256(password.encode('utf-8')).hexdigest()
	if user_document['password'] != password_hash:
		session['error'] = 'Password is wrong'
		return redirect('/login')

	# Generate token and save it in session
	random_string = get_random_string()
	randomSessionHash = sha256(random_string.encode('utf-8')).hexdigest()

	token_object = mongo.db.user_tokens.insert_one({
		'userId': user_document['_id'],
		'sessionHash': randomSessionHash,
		'created_at': datetime.utcnow(),
		})

	session['userToken'] = randomSessionHash



	return redirect('/')

@app.route('/handle_signup', methods = ['POST'])
def handle_signup():
	try :
		email = request.form['email']
	except KeyError:
		email = ''
	try:
		password = request.form['password']
	except KeyError:
		password = ''

	# Check if email is blank
	if not len(email) > 0:
		session['error'] = 'Email is required'
		return redirect('/signup')

	# Check if email is valid
	if not '@' in email or not '.' in email:
		session['error'] = 'Email is invalid'
		return redirect('/signup')

	# Check if password is blank
	if not len(password) > 0:
		session['error'] = 'Password is required'
		return redirect('/signup')

	
	# Check if email already used
	matching_user_count = mongo.db.users.count_documents ({"email": email})
	if matching_user_count > 0:
		session['error'] = 'Email already exists'
		return redirect('/signup')

	password = sha256(password.encode('utf-8')).hexdigest()
	# Create user record
	result = mongo.db.users.insert_one({
		'email': email,
		'password': password,
		'name': '',
		'lastLoginDate': None,
		'createdAt': datetime.utcnow(),
		'updatedAt': datetime.utcnow()
		})

	# Redirect to login page
	session['signupSuccess'] = 'Your user account is ready. Please log in'
	return redirect('/login')

@app.route('/logout')
def logout_user():
	session.pop('userToken', None)
	session['signupSuccess'] = 'You are now logged out.'
	return redirect('/login')

def allowed_file(filename):
	ALLOWED_EXTENSIONS = ['jpg', 'gif','png', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'pdf', 'csv']
	return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


UPLOAD_FOLDER = '//uploads'
@app.route('/handle_file_upload', methods = ['POST'])
def handle_file_upload():\

	# Validate Session
	if not 'userToken' in session:
		session['error']: 'You must login to access this page'
		return redirect('/login')

		# Validate user token
	token_document = mongo.db.user_tokens.find_one({
		'sessionHash': session['userToken']
	})

	if token_document is None:
		session.pop('userToken', None)
		session['error'] = 'You must login again to access this page'
		return redirect('/login')

	# File checks
	if 'uploadedFile' not in request.files:
		session['error'] = 'No file uploaded'
		return redirect('/')

	file = request.files['uploadedFile']


	if file.filename == '':
		session['error'] = 'No file selected'
		return redirect('/')
	if not allowed_file(file.filename):
		session['error'] = 'Unsupported File Format'
		return redirect('/')
	# TODO Check file size check 20MB

	extension = file.filename.rsplit('.', 1)[1].lower()
	filename = secure_filename(file.filename)
	filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
	file.save(filepath)

	result = mongo.db.files.insert_one({
		'userId' : token_document['userId'],
		'originalFileName' : file.filename,
		'fileType' : extension,
		'fileSize': "",
		'fileHash' : '',
		'filePath' : filepath,
		'isActive' : True,
		'createdAt': datetime.utcnow()

	})


	return redirect('/')
