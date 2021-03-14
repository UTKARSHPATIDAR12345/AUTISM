import os
from pro import app, db, bcrypt
from uuid import uuid4
import secrets
from PIL import Image
from flask import render_template, url_for, flash, redirect, send_from_directory, request, abort
from pro.forms import RegistrationForm, LoginForm, UpdateAccountForm, PostForm ,qna
from pro.models import User, Post
from flask_login import login_user, current_user, logout_user, login_required





#db.create_all()

APP_ROOT = os.path.dirname(os.path.abspath(__file__))

classes = ['0','1']



@app.route("/")
@app.route("/home")
def home():
    posts = Post.query.all()
    return render_template('home.html',posts=posts)


@app.route("/about")
def about():
    return render_template('about.html', title='about')


@app.route("/register", methods = ['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email = form.email.data, password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash("Your account has been created! You are now able to log in", 'success')
        #return redirect(url_for('home'))
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

#verify login route later
@app.route("/login", methods= ['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            next_page = request.args.get('next')
            #return redirect(url_for('QNA'))
            return redirect(next_page) if next_page else redirect(url_for('QNA'))

        else:
            flash('Login Unsucessful. Please check email and Password','danger')
            return render_template('login.html',title='Login', form=form)

    return render_template('login.html', title='Login', form=form)





@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route("/QNA.html",methods=['GET','POST'])
def QNA():
    form = qna(request.form)

    return render_template('QNA.html',form=form)


