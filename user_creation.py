# import libraries
import jinja2
import os
import re
import webapp2
import hashlib
import random
import string
import hmac
import time
from urls import *
# importing the models
from models import *
# importing google appengine datastore library for python
from google.appengine.ext import ndb

SECRET = 'macbookpromh840'


USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")  # for valid username
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")  # for valid email
PASSWD_RE = re.compile(r"^.{3,20}")  # for valid password


class User(ndb.Model):
    """User related data"""
    username = ndb.StringProperty(required=True)
    pw_hash = ndb.StringProperty(required=True)
    email = ndb.StringProperty()

    @classmethod
    def by_id(self, uid):
        return User.get_by_id(uid, parent=user_key())

    @classmethod
    def by_username(self, username):
        user = User.all().filter('username =', username).get()
        return user


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


def make_pwd_hash(name, pwd, salt=None):
    """creates a hash for the password security"""
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + hash).hexdigest()
    return "%s,%s" % (h, salt)


def valid_pw(name, pw, h):
    """checks for password validity from the hashvalue received"""
    salt = h.split(",")[1]
    return h == make_pwd_hash(name, pwd, salt)


def users_key(group='default'):
    """defines user key"""
    return ndb.Key('users', group)
