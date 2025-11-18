from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_babel import Babel
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
babel = Babel()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
) 