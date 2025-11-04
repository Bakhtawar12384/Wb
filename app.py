from flask import Flask, render_template, redirect, session
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, EmailField, SubmitField
from wtforms.validators import DataRequired, Length, Email, Regexp
from markupsafe import escape
from sqlalchemy import text
from flask_wtf.csrf import CSRFProtect
from datetime import timedelta

app = Flask(__name__)

# App settings
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///firstapp.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'  # required for Flask-WTF CSRF

# Session hardening (adjust SESSION_COOKIE_SECURE for production)
app.config['SESSION_COOKIE_SECURE'] = False
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
csrf = CSRFProtect(app)

class FirstApp(db.Model):
    sno = db.Column(db.Integer, primary_key=True, autoincrement=True)
    fname = db.Column(db.String(100), nullable=False)
    lname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(200), nullable=False)

    def __repr__(self):
        return f"{self.sno} - {self.fname}"

class UserForm(FlaskForm):
    fname = StringField('First Name', validators=[
        DataRequired(), Length(min=2, max=100),
        Regexp(r'^[A-Za-z ]+$', message="Only letters and spaces allowed.")
    ])
    lname = StringField('Last Name', validators=[
        DataRequired(), Length(min=2, max=100),
        Regexp(r'^[A-Za-z ]+$', message="Only letters and spaces allowed.")
    ])
    email = EmailField('Email', validators=[DataRequired(), Email(), Length(max=200)])
    submit = SubmitField('Add User')

@app.route('/', methods=['GET', 'POST'])
def index():
    form = UserForm()

    if form.validate_on_submit():
        # sanitize inputs to help prevent XSS
        fname = escape(form.fname.data.strip())
        lname = escape(form.lname.data.strip())
        email = escape(form.email.data.strip())

        user = FirstApp(fname=fname, lname=lname, email=email)
        db.session.add(user)
        db.session.commit()

        # Post/Redirect/Get pattern to avoid duplicate submits
        return redirect('/')

    allpeople = FirstApp.query.all()
    return render_template('index.html', form=form, allpeople=allpeople)

@app.route('/search/<name>')
def search_user(name):
    """
    Example of a parameterized raw SQL query to avoid injection.
    Uses the model's table name and bound parameters.
    """
    table_name = FirstApp.__table__.name
    query = text(f"SELECT * FROM {table_name} WHERE fname = :fname")
    result = db.session.execute(query, {"fname": name})
    rows = result.fetchall()

    output = ""
    for row in rows:
        try:
            fname = row['fname']
            lname = row['lname']
            email = row['email']
        except Exception:
            # fallback for tuple-like row objects
            fname, lname, email = row[1], row[2], row[3]
        output += f"{fname} {lname} ({email})<br>"
    return output if output else "No records found"

@app.route('/set_session')
def set_session():
    """
    Demo route: mark session permanent and set a value.
    Cookie attributes follow config above.
    """
    session.permanent = True
    session['user'] = 'test_user'
    return "Session set (permanent=True). Check cookie attributes in browser devtools."

@app.route('/home')
def home():
    return 'Welcome to the Home Page'

@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    # avoid showing stack traces to clients; log internally if needed
    return render_template('500.html'), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
