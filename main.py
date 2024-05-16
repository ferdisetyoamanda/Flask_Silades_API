from urllib.request import urlopen
import pymysql
from dotenv import load_dotenv
pymysql.install_as_MySQLdb()
from io import StringIO
from flask import Flask, request, render_template, make_response, send_file, after_this_request, jsonify
from functools import wraps
import json
from flask_restx import Resource, Api, reqparse
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, send, emit, join_room, leave_room

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.datastructures import FileStorage
from werkzeug.utils import secure_filename
import datetime as dt
from datetime import timedelta, datetime, date
from functools import wraps
import csv

import os
import shutil
import subprocess
import cloudinary
from cloudinary.uploader import upload
from cloudinary.utils import cloudinary_url

# Flask Configuration.
load_dotenv()
app = Flask(__name__, template_folder='web')
api = Api(app, version='1.0', title='Silades Api', description='Silades API Documentation')
mail= Mail(app)
#socketio = SocketIO(app, cors_allowed_origins="*", async_mode='ev')

# JWT Configuration.
SECRET_KEY = os.getenv('SECRET_KEY')
ISSUER = os.getenv('ISSUER')
AUDIENCE_MOBILE = os.getenv('AUDIENCE_MOBILE')

import jwt
port = 8081
# Cloudinary Configuration.
cloudinary.config(
	cloud_name = os.getenv('CLOUDINARY_CLOUD_NAME'),
	api_key = os.getenv('CLOUDINARY_API_KEY'),
	api_secret = os.getenv('CLOUDINARY_API_SECRET'),
	secure = True,
)

upload_options = {
	'folder': 'silades',
}

# Email Configuration.
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True
mail = Mail(app)

# File Upload Configuration.
UPLOAD_FOLDER = './public/images'
DOKUMEN_FOLDER = './public/dokumen'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', "mp4"}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['DOKUMEN_FOLDER'] = DOKUMEN_FOLDER

# Database Configuration.
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv('DATABASE_URL')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SQLALCHEMY_ECHO"] = True
db = SQLAlchemy(app)

# Database Class Model.
class User(db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer(), primary_key=True, nullable=False)
    email = db.Column(db.String(32), unique=True, nullable=False)
    name = db.Column(db.String(64), nullable=False)
    password = db.Column(db.String(256), nullable=False)
    verified = db.Column(db.Boolean(), nullable=False, default=False)
    profile = db.Column(db.String(500), nullable=False, default=False)
    phone_number = db.Column(db.String(20), nullable=True)
    full_address = db.Column(db.String(256), nullable=True)
    bod = db.Column(db.String(64), nullable=True)
    bop = db.Column(db.String(256), nullable=True)
    rt_num = db.Column(db.String(3), nullable=True)
    rw_num = db.Column(db.String(3), nullable=True)
    village_id = db.Column(db.Integer, nullable=True)
    subdistrict_id = db.Column(db.Integer, nullable=True)
    district_id = db.Column(db.Integer, nullable=True)
    province_id = db.Column(db.Integer, nullable=True)
    komisi = db.Column(db.String(256), nullable=True)
    position = db.Column(db.String(256), nullable=True)
    role = db.Column(db.String(64), nullable=True)



#Role-Based Access Control (RBAC)
def admin_required(f):
	@wraps(f)
	def decorated_function(*args, **kwargs):
		bearerAuth = request.headers.get('Authorization')
		if bearerAuth is None:
			return {
				'message': 'Authorization is required!'
			}, 401
		if bearerAuth.split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			if user[0].role != 'admin':
				return {
					'message': 'Access Denied!'
				}, 403
			return f(*args, **kwargs)
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500
	return decorated_function

#register user
parser4SignUp = reqparse.RequestParser()
parser4SignUp.add_argument('email', type=str, location='json', 
	required=True, help='Email Address')
parser4SignUp.add_argument('name', type=str, location='json', 
	required=True, help='Fullname')
parser4SignUp.add_argument('password', type=str, location='json', 
	required=True, help='Password')
parser4SignUp.add_argument('re_password', type=str, location='json', 
	required=True, help='Retype Password')
parser4SignUp.add_argument('phone_number', type=str, location='json', 
	required=True, help='Phone Number')
parser4SignUp.add_argument('full_address', type=str, location='json',
    required=True, help='Full Address')
parser4SignUp.add_argument('bod', type=str, location='json',
	required=True, help='Birth Date')
parser4SignUp.add_argument('bop', type=str, location='json',
	required=True, help='Birth Place')
parser4SignUp.add_argument('rt_num', type=int, location='json',
    required=True, help='RT')
parser4SignUp.add_argument('rw_num', type=int, location='json',
	required=True, help='RW')
parser4SignUp.add_argument('village_id', type=int, location='json',
    required=True, help='Village')
parser4SignUp.add_argument('subdistrict_id', type=int, location='json',
    required=True, help='Subdistrict')



#register admin
parser4Admin = reqparse.RequestParser()
parser4Admin.add_argument('email', type=str, location='json',
	required=True, help='Email Address')
parser4Admin.add_argument('name', type=str, location='json',
	required=True, help='Fullname')
parser4Admin.add_argument('password', type=str, location='json',
	required=True, help='Password')
parser4Admin.add_argument('re_password', type=str, location='json',
	required=True, help='Retype Password')
parser4Admin.add_argument('phone_number', type=str, location='json',
	required=True, help='Phone Number')
parser4Admin.add_argument('full_address', type=str, location='json',
	required=True, help='Full Address')
parser4Admin.add_argument('bod', type=str, location='json',
	required=True, help='Birth Date')
parser4Admin.add_argument('bop', type=str, location='json',
	required=True, help='Birth Place')
parser4Admin.add_argument('rt_num', type=int, location='json',
	required=True, help='RT')
parser4Admin.add_argument('rw_num', type=int, location='json',
	required=True, help='RW')
parser4Admin.add_argument('village_id', type=int, location='json',
	required=True, help='Village')
parser4Admin.add_argument('subdistrict_id', type=int, location='json',
	required=True, help='Subdistrict')
parser4Admin.add_argument('district_id', type=int, location='json',
	required=True, help='District')
parser4Admin.add_argument('province_id', type=int, location='json',
	required=True, help='Province')

#register dprd
parser4Dprd = reqparse.RequestParser()
parser4Dprd.add_argument('email', type=str, location='json',
	required=True, help='Email Address')
parser4Dprd.add_argument('name', type=str, location='json',
	required=True, help='Fullname')
parser4Dprd.add_argument('password', type=str, location='json',
	required=True, help='Password')
parser4Dprd.add_argument('re_password', type=str, location='json',
	required=True, help='Retype Password')
parser4Dprd.add_argument('phone_number', type=str, location='json',
	required=True, help='Phone Number')
parser4Dprd.add_argument('full_address', type=str, location='json',
	required=True, help='Full Address')
parser4Dprd.add_argument('bod', type=str, location='json',
	required=True, help='Birth Date')
parser4Dprd.add_argument('bop', type=str, location='json',
	required=True, help='Birth Place')
parser4Dprd.add_argument('rt_num', type=int, location='json',
	required=True, help='RT')
parser4Dprd.add_argument('rw_num', type=int, location='json',
	required=True, help='RW')
parser4Dprd.add_argument('village_id', type=int, location='json',
	required=True, help='Desa')
parser4Dprd.add_argument('subdistrict_id', type=int, location='json',
	required=True, help='Kecamatan')
parser4Dprd.add_argument('district_id', type=int, location='json',
	required=True, help='Kabupaten')
parser4Dprd.add_argument('province_id', type=int, location='json',
	required=True, help='Province')
parser4Dprd.add_argument('komisi', type=str, location='json',
	required=True, help='Komisi')
parser4Dprd.add_argument('position', type=str, location='json',
	required=True, help='Jabatan')








@api.route('/user/auth/signup')
class Registration(Resource):
	@api.expect(parser4SignUp)
	def post(self):
		args 		= parser4SignUp.parse_args()
		email 		= args['email']
		name 		= args['name']
		password 	= args['password']
		rePassword 	= args['re_password']
		phone_number = args['phone_number']
		full_address = args['full_address']
		bod = args['bod']
		bop = args['bop']
		rt_num = args['rt_num']
		rw_num = args['rw_num']
		village_id = args['village_id']
		subdistrict_id = args['subdistrict_id']


		if password != rePassword:
			return {
				'message': 'Password is not the same!'
			}, 400 # HTTP Status Code for Bad Request.

		user = db.session.execute(db.select(User).filter_by(email=email)).first()
		if user:
			return {
                'message': 'This email address has been used!'
			}, 409 # HTTP Status Code for "Conflict".
		
		try:
			user	= User()
			user.email	= email
			user.name	= name
			user.password	= generate_password_hash(password)
			user.verified	= False
			user.profile	= 'https://res.cloudinary.com/dkxt6mlnh/image/upload/v1682927959/drown/images-removebg-preview_nmbyo7.png'
			user.phone_number	= phone_number
			user.full_address	= full_address
			user.bod = bod
			user.bop = bop
			user.rt_num = rt_num
			user.rw_num = rw_num
			user.village_id = village_id
			user.subdistrict_id = subdistrict_id
			user.district_id = "1"
			user.province_id = "1"
			user.role = 'user'
				
			db.session.add(user)
			db.session.commit()
				
			ids = db.session.execute(db.select(User).filter_by(email=email)).first()
			id = ids[0]
			payload = {
				'user_id': id.id,
				'email': email,
				'aud': AUDIENCE_MOBILE,
				'iss': ISSUER,
				'iat': datetime.utcnow(),
				'exp': datetime.utcnow() + timedelta(hours=2)
			}
			verify_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
			url = f"http://127.0.0.1:8081/user/auth/verify?token={verify_token}"
			msg = Message('Email Verification', sender = os.getenv('MAIL_USERNAME'), recipients = [email])
			msg.html = render_template('verifemail.html', name=name, url=url)
			mail.send(msg)

			return {
				'message': 'Successful Registered! Please check your email to verify your account.'
				}, 201 # HTTP Status Code for "Created".

		except Exception as err:
			return {
				'message': str(err)
			}, 500

@api.route('/admin/auth/signup')
class RegistrationAdmin(Resource):
	@api.expect(parser4Admin)
	def post(self):
		args = parser4Admin.parse_args()
		email = args['email']
		name = args['name']
		password = args['password']
		rePassword = args['re_password']
		phone_number = args['phone_number']
		full_address = args['full_address']
		bod = args['bod']
		bop = args['bop']
		rt_num = args['rt_num']
		rw_num = args['rw_num']
		village_id = args['village_id']
		subdistrict_id = args['subdistrict_id']
		district_id = args['district_id']
		province_id = args['province_id']
		

		if password != rePassword:
			return {
				'message': 'Password is not the same!'
			}, 400 # HTTP Status Code for Bad Request.
		user = db.session.execute(db.select(User).filter_by(email=email)).first()
		if user:
			return {'message': 'This email address has been used!'}, 409 # HTTP Status Code for "Conflict".
		try:
			user = User()
			user.email = email
			user.name = name
			user.password = generate_password_hash(password)
			user.verified = False
			user.profile = 'https://res.cloudinary.com/dkxt6mlnh/image/upload/v1682927959/drown/images-removebg-preview_nmbyo7.png'
			user.phone_number = phone_number
			user.full_address = full_address
			user.bod = bod
			user.bop = bop
			user.rt_num = rt_num
			user.rw_num = rw_num
			user.village_id = village_id
			user.subdistrict_id = subdistrict_id
			user.district_id = district_id
			user.province_id = province_id
			user.role = 'admin'

			db.session.add(user)
			db.session.commit()

			ids = db.session.execute(db.select(User).filter_by(email=email)).first()
			id = ids[0]
			payload = {
				'user_id': id.id,
				'email': email,
				'aud': AUDIENCE_MOBILE,
				'iss': ISSUER,
				'iat': datetime.utcnow(),
				'exp': datetime.utcnow() + timedelta(hours=2)
			}
			verify_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
			url = f"http://127.0.0.1:8081/user/auth/verify?token={verify_token}"
			msg = Message('Email Verification', sender = os.getenv('MAIL_USERNAME'), recipients = [email])
			msg.html = render_template('verifemail.html', name=name, url=url)
			mail.send(msg)
		
			return {
				'message': 'Successful Registered! Please check your email to verify your account.'
				}, 201 # HTTP Status Code for "Created".

		except Exception as err:
			return {
				'message': str(err)
			}, 500
	
#dprd
@api.route('/admin/auth/signup/dprd')
class RegistrationDprd(Resource):
	@api.expect(parser4Dprd)
	@admin_required
	def post(self):
		args = parser4Dprd.parse_args()
		email = args['email']
		name = args['name']
		password = args['password']
		rePassword = args['re_password']
		phone_number = args['phone_number']
		full_address = args['full_address']
		bod = args['bod']
		bop = args['bop']
		rt_num = args['rt_num']
		rw_num = args['rw_num']
		village_id = args['village_id']
		subdistrict_id = args['subdistrict_id']
		district_id = args['district_id']
		province_id = args['province_id']
		komisi = args['komisi']
		position = args['position']
		

		if password != rePassword:
			return {
				'message': 'Password is not the same!'
			}, 400 # HTTP Status Code for Bad Request.
		user = db.session.execute(db.select(User).filter_by(email=email)).first()
		if user:
			return {'message': 'This email address has been used!'}, 409
		try:
			user = User()
			user.email = email
			user.name = name
			user.password = generate_password_hash(password)
			user.verified = False
			user.profile = 'https://res.cloudinary.com/dkxt6mlnh/image/upload/v1682927959/drown/images-removebg-preview_nmbyo7.png'
			user.phone_number = phone_number
			user.full_address = full_address
			user.bod = bod
			user.bop = bop
			user.rt_num= rt_num
			user.rw_num = rw_num
			user.village_id = village_id
			user.subdistrict_id = subdistrict_id
			user.district_id = district_id
			user.province_id = province_id
			user.komisi = komisi
			user.position = position
			
			user.role = 'dprd'

			db.session.add(user)
			db.session.commit()

			ids = db.session.execute(db.select(User).filter_by(email=email)).first()
			id = ids[0]
			payload = {
				'user_id': id.id,
				'email': email,
				'aud': AUDIENCE_MOBILE,
				'iss': ISSUER,
				'iat': datetime.utcnow(),
				'exp': datetime.utcnow() + timedelta(hours=2)
			}
			verify_token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
			url = f"http://127.0.0.1:8081/user/auth/verify?token={verify_token}"
			msg = Message('Email Verification', sender = os.getenv('MAIL_USERNAME'), recipients = [email])
			msg.html = render_template('verifemail.html', name=name, url=url)
			mail.send(msg)

			return {
				'message': 'Successful Registered! Please check your email to verify your account.'
				}, 201 # HTTP Status Code for "Created".
		
		except Exception as err:
			return {
				'message': str(err)
			}, 500
		

#login
parser4SignIn = reqparse.RequestParser()
parser4SignIn.add_argument('email', type=str, location='json', 
	required=True, help='Email Address')
parser4SignIn.add_argument('password', type=str, location='json', 
	required=True, help='Password')

@api.route('/auth/signin')
class LogIn(Resource):
	@api.expect(parser4SignIn)
	def post(self):
		args 		= parser4SignIn.parse_args()
		email 		= args['email']
		password 	= args['password']
		
		try:
			if not email or not password:
				return {
					'message': 'Please type email and password!'
				}, 400

			user = db.session.execute(db.select(User).filter_by(email=email)).first()
			if not user:
				return {
					'message': 'Wrong email!'
				}, 400
			else:
				user = user[0] # Unpack the array

			if user.verified == False:
				return {
					'message': 'Please verify your email first!'
				}, 400

			if check_password_hash(user.password, password):
				payload = {
					'user_id': user.id,
					'email': user.email,
					'aud': AUDIENCE_MOBILE,
					'iss': ISSUER,
					'iat': datetime.utcnow(),
					'exp': datetime.utcnow() + timedelta(days=7)
				}
				token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
				return {
					'message': 'Successful Logged In!',
					'email': user.email,
					'name' : user.name,
					'profile': user.profile,
					'role': user.role,
					'token': token
				}, 200
			else:
				return {'message': 'Wrong email or password!'}, 400
		
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#token cek
parser4Basic = reqparse.RequestParser()
parser4Basic.add_argument('Authorization', type=str, location='headers', required=True)

@api.route('/user/auth/token-check')
class BasicAuth(Resource):
	@api.expect(parser4Basic)
	def get(self):
		args 		= parser4Basic.parse_args()
		basicAuth 	= args['Authorization']
		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Token is invalid!'
			}, 400
		token = basicAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload["user_id"])).first()
			expiration_date = dt.datetime.fromtimestamp(payload['exp'])
			if user:
				user = user[0]
				return {
					'message': 'Success Token Check!',
					'nama': user.name,
					'email': user.email,
					'verified': user.verified,
					'profile': user.profile,
					'expired': expiration_date.strftime("%d %B %Y %H:%M:%S")
				}, 200
			else:
				return {
					'message': 'Token is invalid!'
				}, 400
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Token is invalid!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

parserToken = reqparse.RequestParser()
parserToken.add_argument('token', type=str, location='args', required=True)

@api.route('/user/auth/verify')
class Verify(Resource):
	@api.expect(parserToken)
	def get(self):
		args = parserToken.parse_args()
		if args is None:
			return {
				'message': 'Token is invalid!'
			}, 400
		token = args['token']

		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(email=payload['email'])).first()

			if user:
				user = user[0]
				if user.verified == True:
					return make_response(render_template('veriffailed.html'),200, {'Content-Type': 'text/html'})
				user.verified = True
				db.session.commit()
				return make_response(render_template('verif.html'),200, {'Content-Type': 'text/html'})
			else:
				return {
					'message': 'User not found!'
				}, 404
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500


#allowed file
def allowed_file(filename):
	return '.' in filename and \
		filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

#profile
parserProfile = reqparse.RequestParser()
parserProfile.add_argument('Authorization', type=str, location='headers', required=True)
parserProfile.add_argument('name', type=str, location='form', required=False)
parserProfile.add_argument('email', type=str, location='form', required=False)
parserProfile.add_argument('profile', type=FileStorage, location='files', required=False)

@api.route('/user/profile')
class Profile(Resource):
	@api.expect(parserProfile)
	def put(self):
		args = parserProfile.parse_args()
		bearerAuth = args['Authorization']
		name = args['name']
		email = args['email']
		profile = args['profile']

		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]

		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()

			if user:
				user = user[0]
				if profile and allowed_file(profile.filename):
					filename = secure_filename(profile.filename)
					profile.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
					try:
						upload_result = upload(os.path.join(app.config['UPLOAD_FOLDER'], filename), **upload_options)
						image = upload_result['secure_url']
						os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))

					except Exception as err:
						return {
							'message': str(err)
						}, 500
						
				if name is not None and name != '':
					user.name = name
				if email is not None and email != '':
					user.email = email
				if profile is not None and profile != '':
					user.profile = image
				
				db.session.commit()
				return {
					'message': 'Profile updated!'
				}, 200
			else:
				return {
					'message': 'User not found!'
				}, 404
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500
		
@api.route('/user/forgotpassword')
class ForgotPassword(Resource):
	@api.expect(parser4Basic)
	def get(self):
		args = parser4Basic.parse_args()
		bearer = args['Authorization']
		if bearer.split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearer.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			email = user[0].email
			print(email)
			payload = {
				'user_id': payload['user_id'],
				'email': email,
				'aud': AUDIENCE_MOBILE,
				'iss': ISSUER,
				'exp': datetime.utcnow() + timedelta(minutes=30),
			}
			code = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
			url = f'http://127.0.0.1:8081//user/pagereset?code={code}'
			msg = Message('Forgot Password', sender = os.getenv('MAIL_USERNAME'), recipients=[email])
			msg.html = render_template('forgotpassword.html', url=url , name=user[0].name)
			mail.send(msg)
			return {
				'message': 'Success send email forgot password!',
			}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

parserLupa = reqparse.RequestParser()
parserLupa.add_argument('email', type=str, location='json', required=True)
@api.route('/user/lupa')
class LupaPassword(Resource):
	@api.expect(parserLupa)
	def post(self):
		args = parserLupa.parse_args()
		email = args['email']
		if email is None:
			return {
				'message': 'Email is required!'
			}, 400
		try:
			user = db.session.execute(db.select(User).filter_by(email=email)).first()
			if not user:
				return {
					'message': 'User not found!'
				}, 404
			payload = {
				'user_id': user[0].id,
				'email': email,
				'aud': AUDIENCE_MOBILE,
				'iss': ISSUER,
				'exp': datetime.utcnow() + timedelta(minutes=30),
			}
			code = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
			url = f'https://api-drown.up.railway.app/user/pagereset?code={code}'
			msg = Message('Forgot Password', sender = os.getenv('MAIL_USERNAME'), recipients=[email])
			msg.html = render_template('forgotpassword.html', url=url , name=user[0].name)
			mail.send(msg)
			return {
				'message': 'Success send email forgot password!',
			}, 200
		except Exception as err:
			return {
				'message': str(err)
			}, 500

parserCode = reqparse.RequestParser()
parserCode.add_argument('code', type=str, location='args', required=True)
@api.route('/user/pagereset')
class PageResetPassword(Resource):
	def get (self):
		try:
			args = parserCode.parse_args()
			code = args['code']
			payload = jwt.decode(code, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			return make_response(render_template('resetpassword.html', name=user[0].name, code=code))
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#resetpassword
parserResetPassword = reqparse.RequestParser()
parserResetPassword.add_argument('code', type=str, location='form', required=True)
parserResetPassword.add_argument('password', type=str, location='form', required=True)
parserResetPassword.add_argument('confirm_password', type=str, location='form', required=True)

@api.route('/user/resetpassword')
class ResetPassword(Resource):
	@api.expect(parserResetPassword)
	def post(self):
		args = parserResetPassword.parse_args()
		code = args['code']
		if code is None:
			return {
				'message': 'Code is required!'
			}, 401
		password = args['password']
		confirm_password = args['confirm_password']
		if password != confirm_password:
			return {
				'message': 'Password and confirm password not match!'
			}, 400

		try:
			payload = jwt.decode(code, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			email = payload['email']
			user = db.session.execute(db.select(User).filter_by(email=payload['email'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			user[0].password = generate_password_hash(password)
			db.session.commit()
			return make_response(render_template('resetsuccess.html'))
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500


#database laporan
class Laporan(db.Model):
	__tablename__ = "laporan"
	id = db.Column(db.Integer(), primary_key=True, nullable=False)
	user_id = db.Column(db.Integer(), nullable=False)
	title = db.Column(db.String(256), nullable=False)
	description = db.Column(db.String(256), nullable=False)
	image = db.Column(db.String(256), nullable=True)
	location = db.Column(db.String(256), nullable=False)
	latitude = db.Column(db.String(256), nullable=False)
	longitude = db.Column(db.String(256), nullable=False)
	status = db.Column(db.String(256), nullable=True)
	progress = db.Column(db.String(256), nullable=True)
	rt_num = db.Column(db.Integer(), nullable=False)
	rw_num = db.Column(db.Integer(), nullable=False)
	village_id = db.Column(db.Integer(), nullable=False)
	subdistrict_id = db.Column(db.Integer(), nullable=False)
	type_infra = db.Column(db.String(256), nullable=False)
	#menambahkan hasil prediksi kerusakan dengan model cnn
	prediction = db.Column(db.String(256), nullable=True)



#user post laporan kerusakan
parserLaporan = reqparse.RequestParser()
parserLaporan.add_argument('Authorization', type=str, location='headers', required=True)
parserLaporan.add_argument('title', type=str, location='form', required=True)
parserLaporan.add_argument('description', type=str, location='form', required=True)
parserLaporan.add_argument('image', type=FileStorage, location='files', required=False)
parserLaporan.add_argument('location', type=str, location='form', required=True)
parserLaporan.add_argument('latitude', type=str, location='form', required=True)
parserLaporan.add_argument('longitude', type=str, location='form', required=True)
parserLaporan.add_argument('status', type=str, location='form', required=False)
#progres laporan
parserLaporan.add_argument('progress', type=str, location='form', required=False)
#menambahkan rt rw village subdistrict
parserLaporan.add_argument('rt_num', type=int, location='form', required=True)
parserLaporan.add_argument('rw_num', type=int, location='form', required=True)
parserLaporan.add_argument('village_id', type=int, location='form', required=True)
parserLaporan.add_argument('subdistrict_id', type=int, location='form', required=True)
#menambahkan jenis infrastruktur
parserLaporan.add_argument('type_infra', type=str, location='form', required=True)
#menambahkan hasil prediksi kerusakan dengan model cnn
parserLaporan.add_argument('prediction', type=str, location='form', required=False)


@api.route('/user/laporan')
class Laporan(Resource):
	@api.expect(parserLaporan)
	def post(self):
		args = parserLaporan.parse_args()
		bearerAuth = args['Authorization']
		title = args['title']
		description = args['description']
		image = args['image']
		location = args['location']
		latitude = args['latitude']
		longitude = args['longitude']
		status = args['status']
		rt_num = args['rt_num']
		rw_num = args['rw_num']
		village_id = args['village_id']
		subdistrict_id = args['subdistrict_id']
		type_infra = args['type_infra']
		prediction = args['prediction']


		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			if image and allowed_file(image.filename):
				filename = secure_filename(image.filename)
				image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
				try:
					upload_result = upload(os.path.join(app.config['UPLOAD_FOLDER'], filename), **upload_options)
					image = upload_result['secure_url']
					os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
				except Exception as err:
					return {
						'message': str(err)
					}, 500
			
			
			laporan = Laporan()
			laporan.user_id = user[0].id
			laporan.title = title
			laporan.description = description
			laporan.image = image
			laporan.location = location
			laporan.latitude = latitude
			laporan.longitude = longitude
			laporan.status = status
			laporan.rt_num = rt_num
			laporan.rw_num = rw_num
			laporan.village_id = village_id
			laporan.subdistrict_id = subdistrict_id
			laporan.type_infra = type_infra
			laporan.prediction = prediction
			db.session.add(laporan)
			db.session.commit()
			return {
				'message': 'Laporan berhasil dibuat!'
			}, 201
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#user get laporan kerusakan
parserLaporan = reqparse.RequestParser()
parserLaporan.add_argument('Authorization', type=str, location='headers', required=True)

@api.route('/user/laporan')
class Laporan(Resource):
	@api.expect(parserLaporan)
	def get(self):
		args = parserLaporan.parse_args()
		bearerAuth = args['Authorization']
		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			laporan = db.session.execute(db.select(Laporan).filter_by(user_id=payload['user_id'])).all()
			if laporan is None:
				return {
					'message': 'Laporan not found!'
				}, 404
			laporan = laporan[0]
			laporan = [{
				'id': laporan.id,
				'title': laporan.title,
				'description': laporan.description,
				'image': laporan.image,
				'location': laporan.location,
				'latitude': laporan.latitude,
				'longitude': laporan.longitude,
				'status': laporan.status,
				'rt_num': laporan.rt_num,
				'rw_num': laporan.rw_num,
				'village_id': laporan.village_id,
				'subdistrict_id': laporan.subdistrict_id,
				'type_infra': laporan.type_infra,
				'prediction': laporan.prediction

			} for laporan in laporan]
			return {
				'message': 'Success get laporan!',
				'data': laporan
			}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#user get laporan kerusakan by id
parserLaporan = reqparse.RequestParser()
parserLaporan.add_argument('Authorization', type=str, location='headers', required=True)
parserLaporan.add_argument('id', type=int, location='args', required=True)

@api.route('/user/laporan/id')
class Laporan(Resource):
	@api.expect(parserLaporan)
	def get(self):
		args = parserLaporan.parse_args()
		bearerAuth = args['Authorization']
		id = args['id']
		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			laporan = db.session.execute(db.select(Laporan).filter_by(user_id=payload['user_id'], id=id)).first()
			if laporan is None:
				return {
					'message': 'Laporan not found!'
				}, 404
			laporan = laporan[0]
			laporan = {
				'id': laporan.id,
				'title': laporan.title,
				'description': laporan.description,
				'image': laporan.image,
				'location': laporan.location,
				'latitude': laporan.latitude,
				'longitude': laporan.longitude,
				'status': laporan.status,
				'rt_num': laporan.rt_num,
				'rw_num': laporan.rw_num,
				'village_id': laporan.village_id,
				'subdistrict_id': laporan.subdistrict_id,
				'type_infra': laporan.type_infra,
				'prediction': laporan.prediction
			}
			return {
				'message': 'Success get laporan!',
				'data': laporan
			}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#user update laporan kerusakan
parserLaporan = reqparse.RequestParser()
parserLaporan.add_argument('Authorization', type=str, location='headers', required=True)
parserLaporan.add_argument('id', type=int, location='form', required=True)
parserLaporan.add_argument('title', type=str, location='form', required=False)
parserLaporan.add_argument('description', type=str, location='form', required=False)
parserLaporan.add_argument('image', type=FileStorage, location='files', required=False)
parserLaporan.add_argument('location', type=str, location='form', required=False)
parserLaporan.add_argument('latitude', type=str, location='form', required=False)
parserLaporan.add_argument('longitude', type=str, location='form', required=False)
parserLaporan.add_argument('status', type=str, location='form', required=False)
parserLaporan.add_argument('rt_num', type=int, location='form', required=False)
parserLaporan.add_argument('rw_num', type=int, location='form', required=False)
parserLaporan.add_argument('village_id', type=int, location='form', required=False)
parserLaporan.add_argument('subdistrict_id', type=int, location='form', required=False)
parserLaporan.add_argument('type_infra', type=str, location='form', required=False)
parserLaporan.add_argument('prediction', type=str, location='form', required=False)

@api.route('/user/laporan')
class Laporan(Resource):
	@api.expect(parserLaporan)
	def put(self):
		args = parserLaporan.parse_args()
		bearerAuth = args['Authorization']
		id = args['id']
		title = args['title']
		description = args['description']
		image = args['image']
		video = args['video']
		location = args['location']
		latitude = args['latitude']
		longitude = args['longitude']
		status = args['status']

		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			laporan = db.session.execute(db.select(Laporan).filter_by(user_id=payload['user_id'], id=id)).first()
			if laporan is None:
				return {
					'message': 'Laporan not found!'
				}, 404
			laporan = laporan[0]
			if image and allowed_file(image.filename):
				filename = secure_filename(image.filename)
				image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
				try:
					upload_result = upload(os.path.join(app.config['UPLOAD_FOLDER'], filename), **upload_options)
					image = upload_result['secure_url']
					os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
				except Exception as err:
					return {
						'message': str(err)
					}, 500
			if video and allowed_file(video.filename):
				filename = secure_filename(video.filename)
				video.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
				try:
					upload_result = upload(os.path.join(app.config['UPLOAD_FOLDER'], filename), **upload_options)
					video = upload_result['secure_url']
					os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
				except Exception as err:
					return {
						'message': str(err)
					}, 500
			if title is not None and title != '':
				laporan.title = title
			if description is not None and description != '':
				laporan.description = description
			if image is not None and image != '':
				laporan.image = image
			if location is not None and location != '':
				laporan.location = location
			if latitude is not None and latitude != '':
				laporan.latitude = latitude
			if longitude is not None and longitude != '':
				laporan.longitude = longitude
			if status is not None and status != '':
				laporan.status = status
			db.session.commit()
			return {
				'message': 'Laporan berhasil diupdate!'
			}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#user delete laporan kerusakan
parserLaporan = reqparse.RequestParser()
parserLaporan.add_argument('Authorization', type=str, location='headers', required=True)
parserLaporan.add_argument('id', type=int, location='args', required=True)

@api.route('/user/laporan')
class Laporan(Resource):
	@api.expect(parserLaporan)
	def delete(self):
		args = parserLaporan.parse_args()
		bearerAuth = args['Authorization']
		id = args['id']
		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			laporan = db.session.execute(db.select(Laporan).filter_by(user_id=payload['user_id'], id=id)).first()
			if laporan is None:
				return {
					'message': 'Laporan not found!'
				}, 404
			laporan = laporan[0]
			db.session.delete(laporan)
			db.session.commit()
			return {
				'message': 'Laporan berhasil dihapus!'
			}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#admin get laporan kerusakan
parserLaporan = reqparse.RequestParser()
parserLaporan.add_argument('Authorization', type=str, location='headers', required=True)

@api.route('/admin/laporan')
class Laporan(Resource):
	@api.expect(parserLaporan)
	def get(self):
		args = parserLaporan.parse_args()
		bearerAuth = args['Authorization']
		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			if user[0].role != 'admin':
				return {
					'message': 'You are not admin!'
				}, 401
			laporan = db.session.execute(db.select(Laporan)).all()
			if laporan is None:
				return {
					'message': 'Laporan not found!'
				}, 404
			laporan = laporan[0]
			laporan = [{
				'id': laporan.id,
				'title': laporan.title,
				'description': laporan.description,
				'image': laporan.image,
				'location': laporan.location,
				'latitude': laporan.latitude,
				'longitude': laporan.longitude,
				'status': laporan.status
			} for laporan in laporan]
			return {
				'message': 'Success get laporan!',
				'data': laporan
			}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#admin get laporan kerusakan by id
parserLaporan = reqparse.RequestParser()
parserLaporan.add_argument('Authorization', type=str, location='headers', required=True)
parserLaporan.add_argument('id', type=int, location='args', required=True)

@api.route('/admin/laporan/id')
class Laporan(Resource):
	@api.expect(parserLaporan)
	def get(self):
		args = parserLaporan.parse_args()
		bearerAuth = args['Authorization']
		id = args['id']
		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			if user[0].role != 'admin':
				return {
					'message': 'You are not admin!'
				}, 401
			laporan = db.session.execute(db.select(Laporan).filter_by(id=id)).first()
			if laporan is None:
				return {
					'message': 'Laporan not found!'
				}, 404
			laporan = laporan[0]
			laporan = {
				'id': laporan.id,
				'title': laporan.title,
				'description': laporan.description,
				'image': laporan.image,
				'video': laporan.video,
				'location': laporan.location,
				'latitude': laporan.latitude,
				'longitude': laporan.longitude,
				'status': laporan.status
			}
			return {
				'message': 'Success get laporan!',
				'data': laporan
			}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#admin update laporan kerusakan
parserLaporan = reqparse.RequestParser()
parserLaporan.add_argument('Authorization', type=str, location='headers', required=True)
parserLaporan.add_argument('id', type=int, location='form', required=True)
parserLaporan.add_argument('title', type=str, location='form', required=False)
parserLaporan.add_argument('description', type=str, location='form', required=False)
parserLaporan.add_argument('image', type=FileStorage, location='files', required=False)
parserLaporan.add_argument('video', type=FileStorage, location='files', required=False)
parserLaporan.add_argument('location', type=str, location='form', required=False)
parserLaporan.add_argument('latitude', type=str, location='form', required=False)
parserLaporan.add_argument('longitude', type=str, location='form', required=False)
parserLaporan.add_argument('status', type=str, location='form', required=False)

@api.route('/admin/laporan')
class Laporan(Resource):
	@api.expect(parserLaporan)
	def put(self):
		args = parserLaporan.parse_args()
		bearerAuth = args['Authorization']
		id = args['id']
		title = args['title']
		description = args['description']
		image = args['image']
		video = args['video']
		location = args['location']
		latitude = args['latitude']
		longitude = args['longitude']
		status = args['status']

		if args['Authorization'].split(' ')[0] != 'Bearer':
			return {
				'message': 'Authorization type is not Bearer!'
			}, 400
		token = bearerAuth.split(' ')[1]
		try:
			payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"], audience=AUDIENCE_MOBILE, issuer=ISSUER)
			user = db.session.execute(db.select(User).filter_by(id=payload['user_id'])).first()
			if user is None:
				return {
					'message': 'User not found!'
				}, 404
			if user[0].role != 'admin':
				return {
					'message': 'You are not admin!'
				}, 401
			laporan = db.session.execute(db.select(Laporan).filter_by(id=id)).first()
			if laporan is None:
				return {
					'message': 'Laporan not found!'
				}, 404
			laporan = laporan[0]
			if image and allowed_file(image.filename):
				filename = secure_filename(image.filename)
				image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
				try:
					upload_result = upload(os.path.join(app.config['UPLOAD_FOLDER'], filename), **upload_options)
					image = upload_result['secure_url']
					os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
				except Exception as err:
					return {
						'message': str(err)
					}, 500
			if video and allowed_file(video.filename):
				filename = secure_filename(video.filename)
				video.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
				try:
					upload_result = upload(os.path.join(app.config['UPLOAD_FOLDER'], filename), **upload_options)
					video = upload_result['secure_url']
					os.remove(os.path.join(app.config['UPLOAD_FOLDER'], filename))
				except Exception as err:
					return {
						'message': str(err)
					}, 500
			if title is not None and title != '':
				laporan.title = title
			if description is not None and description != '':
				laporan.description = description
			if image is not None and image != '':
				laporan.image = image
			if video is not None and video != '':
				laporan.video = video
			if location is not None and location != '':
				laporan.location = location
			if latitude is not None and latitude != '':
				laporan.latitude = latitude
			if longitude is not None and longitude != '':
				laporan.longitude = longitude
			if status is not None and status != '':
				laporan.status = status
			db.session.commit()
			return {
				'message': 'Laporan berhasil diupdate!'
			}, 200
		except jwt.ExpiredSignatureError:
			return {
				'message': 'Token is expired!'
			}, 400
		except jwt.InvalidTokenError:
			return {
				'message': 'Invalid Token!'
			}, 400
		except Exception as err:
			return {
				'message': str(err)
			}, 500

#admin delete laporan kerusakan
parserLaporan = reqparse.RequestParser()
parserLaporan.add_argument('Authorization', type=str, location='headers', required=True)
parserLaporan.add_argument('id', type=int, location='args', required=True)



if __name__ == '__main__':
    app.run(host='0.0.0.0', port=port, debug=True, threaded=True)