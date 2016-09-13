# import libraries
import jinja2
import os
import re
import webapp2
import string
import hashlib
import hmac
import time
from google.appengine.ext import ndb
# import all the models
from models import *
from urls import *

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")  # for valid username
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")  # for valid email
PASSWD_RE = re.compile(r"^.{3,20}")  # for valid password

SECRET = "macbookpromh840"


def valid_username(username):
    """checks for valid username"""
    return USER_RE.match(username)


def valid_email(email):
    """checks for valid email"""
    return EMAIL_RE.match(email)


def valid_password(password):
    """checks for valid password"""
    return PASSWD_RE.match(password)


def hash_str(s):
    """returns the hmac hash value using secret """
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    """creates a secure value pair of string and hashvalue"""
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    """checks if the hash obtained is valid"""
    hval = h.split("|")[0]
    if h == make_secure_val(hval):
        return hval
    else:
        None


def make_salt():
    """Makes a salt for hashing"""
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pwd_hash(email, pwd, salt=None):
    """creates a hash for the password security"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(email + pw + hash).hexdigest()
    return "%s,%s" % (h, salt)


def valid_login_pw(email, pw, h):
    """checks for password validity from the hashvalue received"""
    salt = h.split(",")[1]
    return h == make_pwd_hash(email, pwd, salt)


def check_valid_cookie(self):
    user_email_cookie = self.request.cookies.get('user_email')
    if user_email_cookie:
        if_valid_cookie = check_secure_val(user_email_cookie)
        if if_valid_cookie:
            return self.request.cookies.get('user_email').split("|")[0]
        else:
            return None
    else:
        return None


def users_key(group='default'):
    """defines user key"""
    return ndb.Key('users', group)


class AppHandler(webapp2.RequestHandler):
    def write(self, *args, **kwargs):
        self.response.out.write(*args, **kwargs)

    def render_str(self, template, **kwargs):
        t = jinja_env.get_template(template)
        return t.render(kwargs)

    def render(self, template, **kwargs):
        self.write(self.render_str(template, **kwargs))

    def set_secure_cookie(self, user_email, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (user_email, cookie_val))

    def read_secure_cookie(self, user_email):
        cookie_val = self.request.cookies.get(user_email)
        return cookie_val and check_secure_val(cookie_val)

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        username = self.read_secure_cookie('user')
        self.user = User.gql("WHERE username = '%s'" % username).get()

    def get_current_user(self):
        user_email = check_valid_cookie(self)
        user = User.query(user_email == User.email).get()
        return user


class MainPageHandler(AppHandler):
    def get(self):
        self.render("index.html")


class SignUpHandler(AppHandler):
    def get(self):
        print "aayaya yyaya"
        self.render("signup.html")

    def post(self):
        field_errors = []
        has_error = False

        name = self.request.get("name")
        username = self.request.get("username")
        password = self.request.get("password")
        c_password = self.request.get("confirm_password")
        email = self.request.get("email")

        # checks to validate form information
        if name and username and password and c_password and email:
            if not valid_email(email):
                field_errors.append("The Email should be in the format"
                                    " : xyz@abc.com")
                has_error = True

            if not valid_username(username):
                field_errors.append("The username should not have any"
                                    " special characters")
                has_error = True

            if not valid_password(password):
                field_errors.append("The password should be greater than 3 "
                                    "characters & less than 20 characters")
                has_error = True

            elif password != c_password:
                field_errors.append("Passwords don't match")
                has_error = True

            # email already taken up
            if User.query(User.email == email).get():
                field_errors.append("This email address exists already!")
                has_error = True

            if User.query(User.username == username).get():
                field_errors.append("OOPs! This username is already taken!")
                has_error = True

            # rendering the signup template with preserved input
            if has_error:
                print "dhatt"
                self.render('signup.html', name=name,
                            email=email,
                            username=username,
                            field_errors=field_errors)

            else:
                new_user = User(name=name,
                                email=email,
                                username=username,
                                password=hash_str(password))
                new_user_key = new_user.put()

                new_user_profile_pic = ProfilePic(user=new_user_key)
                new_user_profile_pic.put()
                print "all done"
                self.render('login.html', new_user_name=new_user.name)

        else:
            print "mandatory"
            field_errors.append("All fields are mandatory!")
            self.render('signup.html', name=name,
                        email=email,
                        username=username,
                        field_errors=field_errors)


class LoginHandler(AppHandler):
    def get(self):
        print "called"
        user_email = check_valid_cookie(self)
        user = User.query(User.email == user_email).get()

        if user:
            self.render("home.html")
        else:
            self.render("login.html")

    def post(self):
        has_error = False

        email = self.request.get('email')
        password = self.request.get('password')
        # user = User.query(email == User.email).get()
        # checking the validity of the password
        if email and password:
            user = User.query(ndb.AND(ndb.OR(User.email == email,
                                             User.username == email),
                                      User.password == hash_str(password))).get()  # noqa
            print user
            if user:
                print user
                user_email_cookie_val = self.request.cookies.get('user_email')
                if user_email_cookie_val:
                    cookie_validity = check_secure_val(user_email_cookie_val)
                    if cookie_validity:
                        self.redirect('/home')
                    else:
                        print "ptani"
                        self.response.headers.add_header('Set-Cookie',
                                                         'user_email=')
                        cookie_error = "Your session has expired! Please log"
                        " in again to continue!"
                        self.render('login.html',
                                    cookie_error=cookie_error)
                else:
                    print "No user"
                    self.response.headers.add_header(
                        'Set-Cookie',
                        'user_email=%s' % make_secure_val(str(user.email)))
                    self.redirect('/home')
            else:
                print "not validated"
                validation_error = "Please enter valid email and password"
                self.render('login.html', validation_error=validation_error)

        else:
            field_error = "Both Email and password fields are required."
            self.render('login.html', field_error=field_error)


class HomeHandler(AppHandler):
    def get(self):
        user = self.get_current_user()
        posts = Post.query().order(-Post.created)
        context = {'posts': posts,
                   'user': user}
        for i in posts:
            print i.key.id()
        self.render('home.html', user=user, posts=posts)


class LogoutHandler(AppHandler):
    """handler for logging out and clearing the cookie value"""
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_email=')
        msg = "Hope you heard and created the echo with fun!!"
        self.render('login.html', msg=msg)


class CreatePostHandler(AppHandler):
    """Handler for creating new posts """
    def get(self):
        user_email = check_valid_cookie(self)
        if user_email:
            user = User.query(user_email == User.email).get()
            self.render('create.html', user=user)
        else:
            self.redirect('/login')

    def post(self):
        user = self.get_current_user()
        post_title = self.request.get('title')
        post_content = self.request.get('content')
        post_tag = self.request.get('tag')

        if post_title and post_content:
            new_post = Post(
                title=post_title,
                content=post_content,
                tag=post_tag,
                user=user.key)
            post_key = new_post.put()
            self.redirect('/home')
        else:
            error = "Both title and content fields are mandatory!"
            self.render('create.html', post_title=post_title,
                        post_content=post_content,
                        error=error)


class BlogDetailPageHandler(AppHandler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        user = self.get_current_user()
        comments = Comment.query(post.key == Comment.post_id).fetch()
        liked = False
        if user:
            liked = Likes.query(ndb.AND(post.key == Likes.post_id,
                                        user.key == Likes.author)).get()

            if liked:
                liked = True
        print "=================="
        print comments[1].author
        print user.key
        if not post:
            self.error(404)
            return
        # print user.key
        self.render('post_detail.html', user=user, post=post,
                    liked=liked, comments=comments)

    def post(self, post_id):
        post = Post.get_by_id(int(post_id))
        author = post.user
        user = self.get_current_user()
        print user
        print author
        if self.request.get("like"):
            print "like ================================="
            if post and user:
                post.likes += 1
                like = Likes(post_id=post.key,
                             author=user.key)
                like.put()
                post.put()
            self.redirect("/home")
        elif self.request.get("unlike"):
            if post and user:
                post.likes -= 1
                like = Likes.query(ndb.AND(post.key == Likes.post_id,
                                   user.key == Likes.author)).get()
                key = like.key
                key.delete()
                post.put()
            self.redirect("/home")
        else:
            text = self.request.get('comment_text')
            if text:
                comment = Comment(text=str(text), author=user.key,
                                  post_id=post.key)
                comment.put()
                self.redirect('/post/%s' % post_id)
            else:
                self.render('post_detail.html', post=post)


class EditBlogHandler(AppHandler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        post_title = post.title
        post_content = post.content
        post_tag = post.tag
        user = self.get_current_user()
        context = {'post_title': post_title, 'post_tag': post_tag,
                   'post_content': post_content}
        self.render('edit_blog.html', user=user, post=post, context=context)

    def post(self, post_id):
        post = Post.get_by_id(int(post_id))
        post_title = self.request.get('title')
        post_tag = self.request.get('tag')
        post_content = self.request.get('content')

        if post_title and post_tag and post_content:
            post.title = post_title
            post.tag = post_tag
            post.content = post_content
            post.put()
            self.redirect("/post/%s" % post.key.id())
        else:
            context = {'post_title': post_title, 'post_tag': post_tag,
                       'post_content': post_content}
            error = "All the fields are mandatory"
            self.render("edit_blog.html", post=post, error=error,
                        context=context)


class DeleteBlogHandler(AppHandler):
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        context = {'post_title': post.title, 'post_tag': post.tag,
                   'post_content': post.content}
        self.render('delete_blog.html', post=post, context=context)

    def post(self, post_id):
        post = Post.get_by_id(int(post_id))
        post.key.delete()
        self.redirect('/home')


class EditCommentHandler(AppHandler):
    """Handles commment editing"""
    def get(self, comment_id):
        if user:
            comment = Comment.get_by_id(int(comment_id))
            comment_text = comment.text
            context = {'comment_text': comment.text,
                       'comment_author': comment.author}
            self.render('post_detail.html', context=context, comment=comment)

    def post(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        comment_text = self.request.get("comment_text")
        if comment_text:
            comment.text = comment_text
            comment.put()
        else:
            error = "Enter the text to edit!!"
            self.render('post_detail.html', error=error)


class DeleteCommentHandler(AppHandler):
    """Handles commment editing"""
    def get(self, comment_id):
        if user:
            comment = Comment.get_by_id(int(comment_id))
            Key = comment.key
            context = {'comment_text': comment.text,
                       'comment_author': comment.author}
            self.render('delete_comment.html', context=context)

    def post(self, comment_id):
        comment = Comment.get_by_id(int(comment_id))
        post_id = comment.post_id
        comment.key.delete()
        self.redirect('/post/%s' % post_id)
