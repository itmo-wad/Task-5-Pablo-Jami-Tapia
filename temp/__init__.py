from flask import Flask

app = Flask(__name__)

app.config.from_object(__name__)

app.config['MONGO_URI']="mongodb://localhost:27017/wad"

app.secret_key = b'\xd4\x87\\\x0eJ\x80\x9em=\r\x91d\x9b\xe3c'

from app import routes