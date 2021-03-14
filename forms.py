from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from flask_login import current_user
from wtforms import StringField, PasswordField, SubmitField, BooleanField, TextAreaField, SelectField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from pro.models import User

class RegistrationForm(FlaskForm):
    username = StringField('Username',
                           validators = [DataRequired(), Length(min=5, max=15)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password',
                                     validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('Username is taken already! Please Choose a different username')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError("Email is taken already! Please Choose a different username")



class LoginForm(FlaskForm):

    email = StringField('Email', validators=[DataRequired(), Email(), Length(min=5, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')

    submit = SubmitField('Login')








class UpdateAccountForm(FlaskForm):
    username = StringField('Username',
                           validators = [DataRequired(), Length(min=5, max=15)])
    email = StringField('Email',
                        validators=[DataRequired(), Email()])
    picture = FileField('Update Profile Picture', validators=[FileAllowed(['jpg','png'])])
    submit = SubmitField('Update')

    def validate_username(self, username):
        if username.data != current_user.username:
            user = User.query.filter_by(username=username.data).first()
            if user:
                raise ValidationError('Username is taken already! Please Choose a different username')

    def validate_email(self, email):
        if email.data !=current_user.email:
            user = User.query.filter_by(email=email.data).first()
            if user:
                raise ValidationError("Email is taken already! Please Choose a different username")




class PostForm(FlaskForm):
    title = StringField('Title', validators=[DataRequired()])
    content = TextAreaField("Content", validators=[DataRequired()])
    submit = SubmitField("Post")

class qna(FlaskForm):

    a1 = SelectField('ID1',choices=[(1,'1'),(2,'2'),(3,'3'),(4,'4'),(5,'5')],validators=[DataRequired()])
    a2 = SelectField('ID2',choices=[(1,'1'),(2,'2'),(3,'3'),(4,'4'),(5,'5')], validators=[DataRequired()])
    a3 = SelectField('ID3',choices=[(1,'1'),(2,'2'),(3,'3'),(4,'4'),(5,'5')], validators=[DataRequired()])
    a4 = SelectField('ID4',choices=[(1,'1'),(2,'2'),(3,'3'),(4,'4'),(5,'5')], validators=[DataRequired()])
    a5 = SelectField('ID5', choices=[(1,'1'),(2,'2'),(3,'3'),(4,'4'),(5,'5')],validators=[DataRequired()])
