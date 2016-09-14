# contains all the urls in the web applications

import webapp2
from handlers import *
from models import *
from google.appengine.ext import ndb

app = webapp2.WSGIApplication([
    ('/', MainPageHandler),
    ('/aboutus', AboutUsHandler),
    ('/signup', SignUpHandler),
    ('/login', LoginHandler),
    ('/home', HomeHandler),
    ('/logout', LogoutHandler),
    ('/create_post', CreatePostHandler),
    ('/post/([0-9]+)', BlogDetailPageHandler),
    ('/edit_post/([0-9]+)', EditBlogHandler),
    ('/delete_post/([0-9]+)', DeleteBlogHandler),
    ('/post/like-unlike/([0-9]+)', LikeUnlikeHandler),
    ('/post/comment/([0-9]+)', CommentHandler),
    ('/post/comment/([0-9]+)/edit', EditCommentHandler),
    ('/post/comment/([0-9]+)/delete', DeleteCommentHandler)],
     debug=True)
