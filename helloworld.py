import webapp2
import logging
import re
import cgi

def escape_html(s):
	return cgi.escape(s, quote = True)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
	return USER_RE.match(username)

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

form = """
<form method="post">
	What is your birthday?
	<br>
	<label>Month
		<input type="text" name="month" value="%(month)s">
	</label>
	<label>Day
		<input type="text" name="day" value="%(day)s">
	</label>
	<label>Year
		<input type="text" name="year" value="%(year)s">
	</label>
	<div style="color: red">%(error)s</div>
	<br>
	<br>
	<input type="submit">
</form>
"""

form2 = """
<form action="/unit2/rot13" method="post">
	<h1>
	Enter some text to ROT13:
	</h1>
	<br>
	<textarea name="text" rows="10" cols="80">%s</textarea>
	<br>
	<input type="submit">
</form>
"""

form_signup = """
<form action="/unit2/signup" method="post">
	<h1>Signup</h1>

	<label>Username</label>
	<input type="text" name="username" value="%(username)s">
	<span style="color: red">%(username_error)s</span>
	<br>

	<label>Password</label>
	<input type="password" name="password" value="%(password)s">
	<span style="color: red">%(password_error)s</span>
	<br>

	<label>Verfify Password</label>
	<input type="password" name="verify" value="%(verify)s">
	<span style="color: red">%(verify_error)s</span>
	<br>

	<label>Email (optional)</label>
	<input type="text" name="email" value="%(email)s">
	<span style="color: red">%(email_error)s</span>
	<br>
	
	<input type="submit">
</form>
"""

months = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August','September', 'October', 'November', 'December']
month_abbvs = dict((m[:3].lower(), m) for m in months)

def valid_month(month):
	if month:
		short_month = month[:3].lower()
		return month_abbvs.get(short_month)

def valid_day(day):
	if day and day.isdigit():
		day = int(day)
		if day < 32 and day > 0:
			return day

def valid_year(year):
	if year and year.isdigit():
		year = int(year)
		if year < 2020 and year > 1880:
			return year

class MainPage(webapp2.RequestHandler):
	def write_form(self, error="", month="", day="", year=""):
		self.response.out.write(form % {"error": error,
										"month": escape_html(month),
										"day": escape_html(day),
										"year": escape_html(year)})

	def get(self):
		# self.response.headers['Content-Type'] = 'text/html'
		self.write_form()

	def post(self):
		user_month = self.request.get('month')
		user_day = self.request.get('day')
		user_year = self.request.get('year')

		month = valid_month(user_month)
		day = valid_day(user_day)
		year = valid_year(user_year)

		if not (month and day and year):
			self.write_form("That doesn't look valid to me, friend.", user_month, user_day, user_year)
		else:
			self.redirect("/thanks")

class ThanksHandler(webapp2.RequestHandler):
	def get(self):
		self.response.out.write("Thanks! That's a totally valid day!")

def rot13(text):
	result = u""
	for i in text:
		if i.isalpha():
			if i.isupper(): # 65 A
				if  ord(i) <= 77: # 77 M
					rot_char = unichr(ord(i) + 13)
				else:
					rot_char = unichr(ord(i) - 13)
			if i.islower(): # 97 a
				if ord(i) <= 109: # 109 m
					rot_char = unichr(ord(i) + 13)
				else:
					rot_char = unichr(ord(i) - 13)
			result += rot_char
		else:
			result += i
	return result

class Rot13Handler(webapp2.RequestHandler):
	def get(self):
		self.response.out.write(form2 % "")

	def post(self):
		text = self.request.get('text')
		rot13_text = escape_html(rot13(text))
		self.response.out.write(form2 % rot13_text)

class SignupHandler(webapp2.RequestHandler):
	def write_form(self, username="", username_error="", password="", password_error="", verify="", verify_error="", email="", email_error=""):
		self.response.out.write(form_signup % {"username": escape_html(username),
												"username_error": username_error,
												"password": escape_html(password),
												"password_error": password_error,
												"verify": escape_html(verify),
												"verify_error": verify_error,
												"email": escape_html(email),
												"email_error": email_error})

	def get(self):
		self.write_form()

	def post(self):
		user_username = self.request.get('username')
		user_password = self.request.get('password')
		user_verify = self.request.get('verify')
		user_eamil = self.request.get('email')

		username = valid_username(user_username)
		password = valid_password(user_password)
		verify = valid_verify(user_password, user_verify)
		email = valid_email(user_eamil)

		if username and password and verify and email:
			self.redirect('/unit2/welcome?username=%s' % user_username)
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
			self.write_form(user_username, username_error, user_password, password_error, user_verify, verify_error, user_eamil, email_error)
			
class WelcomeHandler(webapp2.RequestHandler):
	def get(self):
		username = self.request.get('username')
		self.response.out.write("<h1>Welcome, %s!</h1>" % username)

app = webapp2.WSGIApplication([
	('/', MainPage),
	('/thanks', ThanksHandler),
	('/unit2/rot13', Rot13Handler),
	('/unit2/signup', SignupHandler),
	('/unit2/welcome', WelcomeHandler),
	], debug = True)