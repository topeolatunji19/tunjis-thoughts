from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from sqlalchemy import Table, Column, Integer, String, Text, create_engine, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session
from functools import wraps
from flask_gravatar import Gravatar

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

Base = declarative_base()

login_manager = LoginManager()
login_manager.init_app(app)


gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    with Session(engine) as session:
        return session.query(User).get(user_id)


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id != 1:
            return abort(403)
        return f(*args, **kwargs)
    return decorated_function


##CONFIGURE TABLES
class User(Base, UserMixin):
    __tablename__ = "user"
    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False, unique=True)
    name = Column(String(250), nullable=False)
    password = Column(String(250), nullable=False)
    posts = relationship("BlogPost", back_populates='author')
    comments = relationship("Comments", back_populates='comment_author')


class BlogPost(Base):
    __tablename__ = "blog_posts"
    id = Column(Integer, primary_key=True)
    title = Column(String(250), unique=True, nullable=False)
    subtitle = Column(String(250), nullable=False)
    date = Column(String(250), nullable=False)
    body = Column(Text, nullable=False)
    img_url = Column(String(250), nullable=False)
    author_id = Column(Integer, ForeignKey("user.id"))
    author = relationship("User", back_populates='posts')
    comments = relationship("Comments", back_populates="parent_post")


class Comments(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True)
    comment = Column(Text, nullable=False)
    author_id = Column(Integer, ForeignKey("user.id"))
    comment_author = relationship("User", back_populates='comments')

    post_id = Column(Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")


# db.create_all()


engine = create_engine('sqlite:///blog.db')
Base.metadata.create_all(engine)

@app.route('/')
def get_all_posts():
    with Session(engine) as session:
        posts = session.query(BlogPost).all()
        return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        with Session(engine) as session:
            user_email = form.email.data
            user_name = form.name.data
            user_password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8)
            check_email = session.query(User).filter_by(email=user_email).first()
            if check_email:
                flash("This email already exists. Log in Instead.")
                return redirect(url_for('login'))
            else:
                new_user = User(
                    name=user_name,
                    email=user_email,
                    password=user_password
                )
                session.add(new_user)
                session.commit()
                login_user(new_user)
                return redirect(url_for('get_all_posts'))
    return render_template("register.html", form=form)


@app.route('/login', methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user_email = form.email.data
        user_password = form.password.data
        with Session(engine) as session:
            user = session.query(User).filter_by(email=user_email).first()
            if not user:
                flash("This email address is not registered")
                return redirect(url_for('login'))
            else:
                if check_password_hash(user.password, user_password):
                    login_user(user)
                    return redirect(url_for('get_all_posts'))
                else:
                    flash("Incorrect password. Try again")
                    return redirect(url_for("login"))
    return render_template("login.html", form=form, current_user=current_user)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    with Session(engine) as session:
        form = CommentForm()
        requested_post = session.query(BlogPost).get(post_id)
        if form.validate_on_submit():
            if not current_user.is_authenticated:
                flash("Log in to comment")
                return redirect(url_for('login'))
            else:
                new_comment = Comments(
                    comment=form.comment.data,
                    comment_author=current_user,
                    parent_post=requested_post
                )
                session.add(new_comment)
                session.commit()
        return render_template("post.html", post=requested_post, form=form, current_user=current_user,
                               logged_in=current_user.is_authenticated)


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact")
def contact():
    return render_template("contact.html", logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        with Session(engine) as session:
            new_post = BlogPost(
                title=form.title.data,
                subtitle=form.subtitle.data,
                body=form.body.data,
                img_url=form.img_url.data,
                author=current_user,
                date=date.today().strftime("%B %d, %Y")
            )
            session.add(new_post)
            session.commit()
            return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form, logged_in=current_user.is_authenticated)


@app.route("/edit-post/<int:post_id>")
@admin_only
def edit_post(post_id):
    with Session(engine) as session:
        post = session.query(BlogPost).get(post_id)
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
            session.commit()
            return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    with Session(engine) as session:
        post_to_delete = session.query(BlogPost).get(post_id)
        session.delete(post_to_delete)
        session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    # app.run(host='0.0.0.0', port=5000)
    app.run(debug=True)