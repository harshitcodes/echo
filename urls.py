import webapp2
from handlers import *
from models import *
from google.appengine.ext import ndb

app = webapp2.WSGIApplication([
    ('/', MainPageHandler),
    ('/signup', SignUpHandler),
    ('/login', LoginHandler),
    ('/home', HomeHandler),
    ('/logout', LogoutHandler),
    ('/create_post', CreatePostHandler),
    ('/post/([0-9]+)', BlogDetailPageHandler),
    ('/edit_post/([0-9]+)', EditBlogHandler),
    ('/delete_post/([0-9]+)', DeleteBlogHandler)], debug=True)
