import os
import webapp2
import jinja2
import re
from google.appengine.ext import db
import hmac
import random
import string
import hashlib

SECRET = 'imsosecret'

def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
	val = h.split("|")[0]
	if h == make_secure_val(val):
		return val

def make_salt():
	return "".join(random.choice(string.letters) for x in xrange(5))

def mkae_pw_hash(name, pw):
	salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s|%s" % (h, salt)

def valid_pw(name, pw, h):
	h, salt = h.split("|")
	if hashlib.sha256(name + pw + salt).hexdigest() == h:
		return True

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
								autoescape = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return username and USER_RE.match(username)

PASSWORD_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
	return PASSWORD_RE.match(password)

def valid_verify(password, verify):
	return password == verify

EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
def valid_email(email):
	if not email:
		return True
	return EMAIL_RE.match(email)

def valid_user(username):
	if not username:
		return False
	else:
		q = db.GqlQuery("SELECT * FROM User WHERE username = '%s'" % username)
		user = q.get()
	if user:
		return user
	else:
		return False

class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)

	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.write(self.render_str(template, **kw))

class User(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.StringProperty()

class SignupHandler(Handler):
	def get(self):
		self.render("signup.html")

	def post(self):
		user_username = self.request.get('username')
		user_password = self.request.get('password')
		user_verify = self.request.get('verify')
		user_eamil = self.request.get('email')

		username = valid_username(user_username)
		password = valid_password(user_password)
		verify = valid_verify(user_password, user_verify)
		email = valid_email(user_eamil)
		user_exist = valid_user(user_username)

		if username and password and verify and email and (not user_exist):

			hash_password = mkae_pw_hash(user_username, user_password)
			user = User(username = user_username, password = hash_password)
			user.put()
			user_id = user.key().id()
			hash_user_id = make_secure_val(str(user_id))

			# path=hello-udacity-1103.appspot.com
			self.response.headers.add_header('Set-Cookie',
			 'user_id=%s; Path=/' % hash_user_id)
			self.redirect('/welcome')
		else:
			username_error, password_error, verify_error, email_error = [""]*4
			if not username:
				username_error = "That's not a valid username."
			if not password:
				password_error = "That wasn't a valid password."
			if not verify:
				verify_error = "Your passwords didn't match."
			if not email:
				email_error = "That's not a valid email."
			if user_exist:
				username_error = "User already exists."
			self.render("signup.html", username=user_username, username_error=username_error, 
				password_error=password_error,
				verify_error=verify_error, eamil=email, email_error=email_error)

class LoginHandler(Handler):
	def get(self):
		self.render("login.html")

	def post(self):
		username = self.request.get('username')
		password = self.request.get('password')
		user = valid_user(username)

		if user and valid_pw(username, password, user.password):
			user_id = user.key().id()
			hash_user_id = make_secure_val(str(user_id))
			# path=hello-udacity-1103.appspot.com
			self.response.headers.add_header('Set-Cookie',
			 'user_id=%s; Path=/' % hash_user_id)
			self.redirect('/welcome')
		else:
			error = "Invalid login"
			self.render("login.html", error = error)

class LogoutHandler(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie',
			 'user_id=; Path=/')
		self.redirect('/signup')

class WelcomeHandler(webapp2.RequestHandler):
	def get(self):
		user_id = self.request.cookies.get('user_id')
		user_id = check_secure_val(user_id)
		if user_id:
			user_id = int(user_id)
			user = User.get_by_id(user_id)
			self.response.out.write("<h1>Welcome, %s!</h1>" % user.username)
		else:
			self.redirect('/signup')

app = webapp2.WSGIApplication([
	('/signup', SignupHandler),
	('/login', LoginHandler),
	('/logout', LogoutHandler),
	('/welcome', WelcomeHandler),
	], debug = True)