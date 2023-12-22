from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship, DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Integer, String, ForeignKey
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm, UserRegistorForm, LoginForm, CommentForm
from functools import wraps
# from flask_gravatar import Gravatar




app = Flask(__name__)

app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'

class Base(DeclarativeBase):
  pass

db = SQLAlchemy(model_class=Base)
#app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# gravatar = Gravatar(app,
#                     size=100,
#                     rating='g',
#                     default='retro',
#                     force_default=False,
#                     force_lower=False,
#                     use_ssl=False,
#                     base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

##CONFIGURE TABLES

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author: Mapped[str] = mapped_column(String(250), nullable=False)
    title: Mapped[str] = mapped_column(String(250), unique=True, nullable=False)
    subtitle: Mapped[str] = mapped_column(String(250), nullable=False)
    date: Mapped[str] = mapped_column(String(250), nullable=False)
    body: Mapped[str] = mapped_column(String(500), nullable=False)
    img_url: Mapped[str] = mapped_column(String(250), nullable=False)
    
    author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    author = relationship("User", back_populates="blog_posts")
    comments = relationship("Comment", back_populates="parent_post")
    
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    password: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    blog_posts = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")
    
class Comment(db.Model):
    __tablename__ = "comments"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[str] = mapped_column(String(250), nullable=False)
    
    comment_author_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    
    parent_post_id: Mapped[int] = mapped_column(Integer, ForeignKey("blog_posts.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    
with app.app_context():
    db.create_all()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.id == 1:
            return f(*args, **kwargs)
       
        return abort(403)
    return decorated_function

@app.route('/')
def get_all_posts():
    posts = db.session.execute(db.select(BlogPost)).scalars()
    return render_template("index.html", all_posts=posts)


@app.route('/register', methods=['POST', 'GET'])
def register():
    form = UserRegistorForm()
    
    if form.validate_on_submit():
        
        if User.query.filter_by(email=form.email.data).first():
            flash("You are already signed in with this email.")
            return redirect(url_for('login'))
        
        hashed_salted_password = generate_password_hash(
            form.password.data,
            method='pbkdf2:sha256',
            salt_length=8)
        
        new_user = User(
            email=form.email.data,
            name=form.name.data,
            password=hashed_salted_password
            )
        db.session.add(new_user)
        db.session.commit()

        
        login_user(new_user)
        
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, current_user=current_user)


@app.route('/login', methods=['POST','GET'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        print('validated')
        email = form.email.data
        password = form.password.data
        # this is where I got the error. With the following codeline I was not able to retrive the user, so I had to switch back to the legendary code line "---.query.filter----".
        #user = db.session.scalars(db.select(User).where(User.email == email[0])).first()
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("This user does not exists. Please try again.")
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash("Password is incorrect. Please try again.")
            return redirect(url_for('login'))
        else:
            login_user(user)
            print(url_for("get_all_posts"))
            return redirect(url_for("get_all_posts"))
    return render_template("login.html",form=form, current_user=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=['POST', 'GET'])
def show_post(post_id):
    requested_post = db.get_or_404(BlogPost, post_id)
    form = CommentForm()
    if form.validate_on_submit():
        if current_user.is_authenticated:
            new_comment = Comment(
                text=form.comment.data,
                comment_author=current_user,
                parent_post=requested_post
                
                )
            db.session.add(new_comment)
            db.session.commit()
        else:
            flash("You need to log in in oder to make a comment.")
            return redirect(url_for('login'))
    
        
    return render_template("post.html",
                           post=requested_post,
                           current_user=current_user,
                           form=form
                           )


@app.route("/about")
def about():
    return render_template("about.html", current_user=current_user)

@app.route("/new-post",methods=['POST','GET'])
@login_required
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=['POST', 'GET'])
@login_required
@admin_only
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=current_user,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, current_user=current_user, is_edit=True)

@app.route("/edit_comment/<int:comment_id>", methods=['POST', 'GET'])
@login_required
def edit_comment(comment_id):
    comment_to_edit = db.get_or_404(Comment, comment_id)
    if current_user.id == comment_to_edit.comment_author_id:
        form = CommentForm(
            comment=comment_to_edit.text
            )
        if form.validate_on_submit():
            comment_to_edit.text = form.comment.data
            db.session.commit()
            return redirect(url_for('show_post', post_id=comment_to_edit.parent_post_id))
        return render_template("edit_comment.html", form=form, current_user=current_user)
    else:
        abort(403)

@app.route("/delete/<int:post_id>")
@login_required
@admin_only
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))

@app.route("/delete_comment/<int:comment_id>/<int:post_id>")
@login_required
def delete_comment(comment_id, post_id):
    comment_to_delete = db.get_or_404(Comment, comment_id)
    if current_user.id == comment_to_delete.comment_author_id:
        db.session.delete(comment_to_delete)
        db.session.commit()
    return redirect(url_for('show_post', post_id=post_id))



if __name__ == "__main__":
    app.run()
