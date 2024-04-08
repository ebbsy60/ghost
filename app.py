
from flask import Flask, request, render_template, redirect, url_for, session, flash, g
from flask_wtf import FlaskForm
from flask_limiter import Limiter
import secrets
from flask_csp.csp import csp_header
from flask_limiter.util import get_remote_address
from wtforms import StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFProtect
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
import base64
import os
from dotenv import load_dotenv

app = Flask(__name__)
load_dotenv()

# Application Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

csrf = CSRFProtect(app)  # Initialize CSRF protection
db = SQLAlchemy(app)

# Configure the Limiter
limiter = Limiter(app=app, key_func=get_remote_address, default_limits=["100/minute"])
limiter.limit("100/minute", key_func=lambda: request.args.get('token') if 'token' in request.args else get_remote_address)

@app.before_request
def generate_nonce():
    g.nonce = secrets.token_urlsafe(16)

@app.after_request
def apply_security_headers(response):
    nonce = g.get('nonce', '')
    csp_policy = f"default-src 'self'; script-src 'self' 'nonce-{nonce}'; style-src 'self'; frame-src https://www.youtube.com; object-src 'none'; base-uri 'none'; require-trusted-types-for 'script';"
    response.headers['Content-Security-Policy'] = csp_policy
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    #response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

class MessageForm(FlaskForm):
    sender = StringField('Your Sender Name', validators=[DataRequired(), Length(max=100)])
    receiver = StringField("Receiver's name", validators=[DataRequired(), Length(max=100)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(max=130)])
    submit = SubmitField('Encrypt and Send')

class Messages(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    sender_username = db.Column(db.String(255), nullable=False)
    receiver_username = db.Column(db.String(255), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    private_key = db.Column(db.Text, nullable=False)

def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_message(public_key, message):
    encrypted = public_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted)

def decrypt_message(private_key_pem, encrypted_message_base64):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )
    encrypted_message_bytes = base64.b64decode(encrypted_message_base64)
    original_message = private_key.decrypt(
        encrypted_message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return original_message.decode()
    
@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/decrypt', methods=['GET', 'POST'])
@csp_header({'script-src':"'self' 'nonce-{nonce}'"})
@limiter.limit("20 per minute")
def decrypt():
    form = MessageForm()  # Initialize the form
    if request.method == 'POST':
        receiver_username = request.form['receiver_username']
        messages = Messages.query.filter_by(receiver_username=receiver_username).all()

        if messages:
            decrypted_messages = []
            for message in messages:
                try:
                    decrypted_message_text = decrypt_message(message.private_key, message.message)
                    decrypted_message = {
                        'text': decrypted_message_text,
                        'sender': message.sender_username,
                        'receiver': message.receiver_username
                    }
                    decrypted_messages.append(decrypted_message)
                    db.session.delete(message)
                except Exception as e:
                    print(f"Decryption failed for message ID {message.id}: {e}")
            db.session.commit()
            # Ensure you pass the form variable here along with any other necessary data
            return render_template('home.html', decrypted_messages=decrypted_messages, form=form)
        else:
            flash("No messages found for that sender!", "info")
            # Redirect to the home route to avoid the form rendering issue
            return redirect(url_for('home'))
    else:
        # For a GET request, render the page without decrypted messages but still include the form
        return render_template('home.html', form=form, nonce=g.nonce)



@app.route('/', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def home():
    form = MessageForm()
    if form.validate_on_submit():
        try:
            sender = form.sender.data
            receiver = form.receiver.data
            message = form.message.data
            
            # Generate keys, encrypt message
            private_key, public_key = generate_keys()
            encrypted_message_base64 = encrypt_message(public_key, message)
            
            # Serialize keys to PEM format
            pem_private_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode()
            
            pem_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()

            # Save message and keys to database
            new_message = Messages(
                message=encrypted_message_base64.decode(),
                sender_username=sender,
                receiver_username=receiver,
                public_key=pem_public_key,
                private_key=pem_private_key
            )
            db.session.add(new_message)
            db.session.commit()

            flash('Message Successfully sent', 'success')
            # Redirect to the /decrypt route after successful message sending
            return redirect(url_for('decrypt'))
        except Exception as e:
            flash('An error occurred. Try again.', 'error')
    return render_template('home.html', form=form)
 
if __name__ == '__main__':
    app.run(debug=False)
