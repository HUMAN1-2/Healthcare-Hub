import mongoengine as me
from datetime import datetime
import os
from dotenv import load_dotenv
load_dotenv()

# Connect to MongoDB
me.connect('user', host= os.getenv('DB_URI'))

# Define User model
class User(me.Document):
    name = me.StringField(required=True)
    email = me.StringField(required=True, unique=True)
    password = me.StringField(required=True)
    
    meta = {'collection': 'users'}
