from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = 'assistive_system_secret_key'

# --- Database Setup ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- Mail Configuration ---
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'chandini.patnaik13@gmail.com'
app.config['MAIL_PASSWORD'] = 'hnqnjueyatuwikzv' 
app.config['MAIL_DEFAULT_SENDER'] = 'chandini.patnaik13@gmail.com'

mail = Mail(app)
serializer = URLSafeTimedSerializer(app.secret_key)

# --- Database Tables ---
class User(db.Model):
    uid = db.Column(db.String(50), primary_key=True)
    username = db.Column(db.String(80))
    email = db.Column(db.String(120))
    password = db.Column(db.String(200))

class ExamLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(50))
    event_type = db.Column(db.String(100))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# New Table to store final submissions if needed
class ExamSubmission(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(50))
    exam_name = db.Column(db.String(100))
    content = db.Column(db.Text) 
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


class TableData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uid = db.Column(db.String(50))
    title = db.Column(db.String(200))
    html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

with app.app_context():
    db.create_all()

# --- Existing Routes ---

@app.route('/')
def home():
    return render_template('sign_login.html')

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    if User.query.get(data['uid']):
        return jsonify({"message": "ID already exists!"}), 400
    hashed_pw = generate_password_hash(data['password'])
    new_user = User(uid=data['uid'], username=data['username'], email=data['email'], password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "Registration Successful"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.get(data['uid'])
    if user and check_password_hash(user.password, data['password']):
        session['user_id'] = user.uid
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')
    user = User.query.filter_by(email=email).first()
    if user:
        token = serializer.dumps(email, salt='password-reset-salt')
        link = url_for('reset_password', token=token, _external=True)
        try:
            msg = Message('Secure Password Reset', recipients=[email])
            msg.body = f"Hello {user.username},\n\nClick the link below to reset your password:\n\n{link}\n\nThis link expires in 30 minutes."
            mail.send(msg)
            return jsonify({"message": "Reset link sent to your email!"}), 200
        except Exception as e:
            print(f"SMTP Error: {e}")
            return jsonify({"message": "Mail server connection failed."}), 500
    return jsonify({"message": "Email not found."}), 404

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = serializer.loads(token, salt='password-reset-salt', max_age=1800)
    except:
        return "<h1>The reset link has expired or is invalid.</h1>", 400
    
    if request.method == 'POST':
        data = request.json
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(data['password'])
            db.session.commit()
            return jsonify({"message": "Password updated successfully!"}), 200
    return render_template('reset_password.html', token=token)

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session: return redirect('/')
    return render_template('dashboard.html')

@app.route('/exam')
def exam():
    if 'user_id' not in session: return redirect('/')
    exam_name = request.args.get('name', 'General Exam')
    lang_code = request.args.get('lang', 'en-US') 
    user_id = session.get('user_id')
    return render_template('exam.html', exam_name=exam_name, lang_code=lang_code, user_id=user_id)

@app.route('/log_event', methods=['POST'])
def log_event():
    if 'user_id' not in session: return jsonify({"status": "unauthorized"}), 401
    data = request.json
    new_log = ExamLog(uid=session.get('user_id'), event_type=data.get('event'))
    db.session.add(new_log)
    db.session.commit()
    return jsonify({"status": "logged"})

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# --- NEW UPDATED CODE ADDED BELOW ---

@app.route('/drawing_canvas')
def drawing_canvas():
    if 'user_id' not in session: return redirect('/')
    return render_template('dc.html')


@app.route('/table')
def table_workspace():
    if 'user_id' not in session: return redirect('/')
    return render_template('table.html')

@app.route('/submit_exam', methods=['POST'])
def submit_exam():
    if 'user_id' not in session: return jsonify({"message": "Unauthorized"}), 401
    data = request.json
    # Store the content in the database
    new_submission = ExamSubmission(
        uid=session.get('user_id'),
        exam_name=data.get('exam_name'),
        content=data.get('content')
    )
    db.session.add(new_submission)
    db.session.commit()
    return jsonify({"message": "Exam submitted successfully!", "redirect": "/results"}), 200


@app.route('/save_table', methods=['POST'])
def save_table():
    if 'user_id' not in session: return jsonify({"message": "Unauthorized"}), 401
    data = request.json
    uid = session.get('user_id')
    table_id = data.get('id')
    title = data.get('title')
    html = data.get('html')

    if table_id:
        t = TableData.query.filter_by(id=table_id, uid=uid).first()
        if not t:
            return jsonify({"message": "Not found"}), 404
        t.title = title
        t.html = html
        t.timestamp = datetime.utcnow()
    else:
        t = TableData(uid=uid, title=title, html=html)
        db.session.add(t)

    db.session.commit()
    return jsonify({"message": "saved", "id": t.id}), 200


@app.route('/load_tables', methods=['GET'])
def load_tables():
    if 'user_id' not in session: return jsonify({"message": "Unauthorized"}), 401
    uid = session.get('user_id')
    tables = TableData.query.filter_by(uid=uid).order_by(TableData.timestamp.desc()).all()
    out = [{"id": t.id, "title": t.title, "html": t.html, "timestamp": t.timestamp.isoformat()} for t in tables]
    return jsonify(out), 200


@app.route('/delete_table', methods=['POST'])
def delete_table():
    if 'user_id' not in session: return jsonify({"message": "Unauthorized"}), 401
    data = request.json
    uid = session.get('user_id')
    table_id = data.get('id')
    t = TableData.query.filter_by(id=table_id, uid=uid).first()
    if not t:
        return jsonify({"message": "Not found"}), 404
    db.session.delete(t)
    db.session.commit()
    return jsonify({"message": "deleted"}), 200


@app.route('/save_answer', methods=['POST'])
def save_answer():
    if 'user_id' not in session: return jsonify({"message": "Unauthorized"}), 401
    data = request.json
    uid = session.get('user_id')
    exam_name = data.get('exam_name')
    content = data.get('content', '')

    existing = ExamSubmission.query.filter_by(uid=uid, exam_name=exam_name).first()
    if existing:
        existing.content = content
        existing.timestamp = datetime.utcnow()
    else:
        existing = ExamSubmission(uid=uid, exam_name=exam_name, content=content)
        db.session.add(existing)

    db.session.commit()
    return jsonify({"message": "Saved"}), 200

@app.route('/results')
def results():
    # Pass the user_id from your session to the template
    user_id = session.get('user_id', 'GUEST-101') 
    return render_template('result.html', user_id=user_id)

if __name__ == '__main__':
    app.run(debug=True)