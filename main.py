from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

# INITALIZE GRAVATAR APP (assigns image to user comments).
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##Configure LoginManager
login_manager = LoginManager()
login_manager.init_app(app)


##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    # Establishes one (i.e.User(parent)) to many (i.e. BlogPost(child)) relationship.
    # First arg is the name of the class. The backref is the name of the new column on the child.
    posts = db.relationship('BlogPost', backref='users')
    # Establishes one (i.e.User(parent)) to many (i.e. Comment(child)) relationship.
    comments = db.relationship('Comment', backref='users')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    # Establishes one (i.e.User(parent)) to many (i.e. BlogPost(child)) relationship.
    # Foreignkey is placed on the child. Must reference the name of a table in lowercase.
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    # One-to-many relationship where each BlogPost object (parent) has many associated Comment objects (child).
    comments = db.relationship('Comment', backref='blog_posts')
    author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    blog_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    text = db.Column(db.String(250), nullable=False)

db.create_all()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Decorator only allows user id #1 in database to edit/create/delete posts.
def admin_only(function):
    @wraps(function)
    def wrapper_function(*args, **kwargs):
        if current_user.id == 1:
            print('User is Admin.')
            return function(*args, **kwargs)
        else:
            print('User not Admin.')
            abort(403)

    return wrapper_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=["GET", "POST"])
def register():
    """Saves user's registration data into the database."""
    form = RegForm()
    if request.method == "POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        hashed_pw = generate_password_hash(password=password, method='pbkdf2:sha256', salt_length=8)
        new_user = User(name=name, email=email, password=hashed_pw)
        # Checks if the email is already used for signup.
        existing_user = User.query.filter_by(email=email).first()
        if not existing_user:
            db.session.add(new_user)
            db.session.commit()
        elif existing_user:
            flash("You've already signed up with that email. Login instead.")
            return redirect(url_for('login'))
        return redirect(url_for('get_all_posts'))
    # Registration form (RegForm()) passed into register.html for Flask WTForms.
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    """Authenticates user based on entries in LoginForm"""
    form = LoginForm()
    # POST request occurs once the user hits the login button.
    if request.method == "POST":
        email = request.form['email']
        password = request.form['password']
        # Searches for database record (row) by filtering for the email.
        user = User.query.filter_by(email=email).first()
        # Checks the user's email and password and provides feedback via flash message + redirect to login page.
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for('get_all_posts'))
            elif not check_password_hash(user.password, password):
                flash("Incorrect password. Please try again.")
                return redirect(url_for('login'))
        elif not user:
            flash(
                "That email does not exist. Please enter a registered email or sign up through the registration page.")
            return redirect(url_for('login'))

    return render_template("login.html", form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    """Displays the post selected from index.html based on post.id number."""
    form = CommentForm()
    # If user submits a comment, add it to the relational database and
    # redirects the user to the same post page with all comments displayed.
    if request.method == "POST" and current_user.is_authenticated:
        comment = request.form['comment']
        new_comment = Comment(author_id=current_user.id, blog_id=post_id, text=comment)
        db.session.add(new_comment)
        db.session.commit()
    elif request.method == "POST" and not current_user.is_authenticated:
        flash("Please log in to post a comment.")
        return redirect(url_for('login'))
    requested_post = BlogPost.query.get(post_id)
    all_comments = [comment for comment in db.session.query(Comment).all()]
    return render_template("post.html", post=requested_post, form=form, comments=all_comments)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=['GET', 'POST'])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user.name,
            author_id=current_user.id,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
