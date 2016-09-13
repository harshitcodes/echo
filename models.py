#  appengine datastore package for python
from google.appengine.ext import ndb
#  appengine blobstore api for serving large sized files
from google.appengine.ext import blobstore


class User(ndb.Model):
    """User information collection class"""
    name = ndb.StringProperty(required=True)
    bio = ndb.StringProperty()
    username = ndb.StringProperty(required=True)
    email = ndb.StringProperty(required=True)
    password = ndb.TextProperty(indexed=True, required=True)


class ProfilePic(ndb.Model):
    """User profile pic upload"""
    user = ndb.KeyProperty(kind=User)
    photo_blob_key = ndb.BlobKeyProperty()


class Post(ndb.Model):
    """All the post related fields we need"""
    title = ndb.StringProperty(required=True)
    tag = ndb.StringProperty()
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    user = ndb.KeyProperty(kind=User)
    likes = ndb.IntegerProperty(default=0)


class Likes(ndb.Model):
    """number of likes on each post, who has liked"""
    post_id = ndb.KeyProperty(kind=Post)
    author = ndb.KeyProperty(kind=User)


class Comment(ndb.Model):
    """who has commented, post on which commmented, date,etc """
    author = ndb.KeyProperty(kind=User)
    post_id = ndb.KeyProperty(kind=Post)
    text = ndb.StringProperty(required=True)
    comment_date = ndb.DateTimeProperty(auto_now_add=True)
