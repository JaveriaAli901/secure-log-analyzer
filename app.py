import os
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from models import db, User, AnalysisResult
from mapreduce import run_mapreduce
import tempfile

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-key-change-in-prod')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
if not app.config['SQLALCHEMY_DATABASE_URI']:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create tables and admin
with app.app_context():
    db.create_all()
    admin_user = User.query.filter_by(username=os.getenv('ADMIN_USERNAME', 'admin')).first()
    if not admin_user:
        admin_user = User(
            username=os.getenv('ADMIN_USERNAME', 'admin'),
            password_hash=generate_password_hash(os.getenv('ADMIN_PASSWORD', 'admin123')),
            role='admin'
        )
        db.session.add(admin_user)
        db.session.commit()
        print("Admin created")

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password_hash, request.form['password']):
            login_user(user)
            return redirect(url_for('admin_dashboard' if user.role == 'admin' else 'user_dashboard'))
        flash('Invalid credentials')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        if User.query.filter_by(username=request.form['username']).first():
            flash('Username taken')
            return redirect(url_for('register'))
        new_user = User(
            username=request.form['username'],
            password_hash=generate_password_hash(request.form['password']),
            role='user'
        )
        db.session.add(new_user)
        db.session.commit()
        flash('Account created! Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if request.method == 'POST':
        file = request.files.get('logfile')
        if not file or not file.filename.endswith('.log'):
            flash('Only .log files allowed')
            return redirect(request.url)
        filename = secure_filename(file.filename)
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix='.log')
        file.save(tmp.name)
        tmp.close()
        try:
            errors, hours = run_mapreduce(tmp.name)
            result = AnalysisResult(
                filename=filename,
                error_counts=errors,
                hour_counts=hours,
                user_id=current_user.id
            )
            db.session.add(result)
            db.session.commit()
            flash('File processed')
            return redirect(url_for('view_result', result_id=result.id))
        finally:
            os.unlink(tmp.name)
    return render_template('upload.html')

@app.route('/result/<int:result_id>')
@login_required
def view_result(result_id):
    result = AnalysisResult.query.get_or_404(result_id)
    if current_user.role != 'admin' and result.user_id != current_user.id:
        abort(403)
    return render_template('dashboard.html', result=result)

@app.route('/admin')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        abort(403)
    return render_template('admin_dashboard.html',
        results=AnalysisResult.query.all(),
        users=User.query.all())

@app.route('/user')
@login_required
def user_dashboard():
    if current_user.role != 'user':
        return redirect(url_for('admin_dashboard'))
    return render_template('user_dashboard.html',
        results=AnalysisResult.query.filter_by(user_id=current_user.id).all())

@app.route('/history')
@login_required
def history():
    if current_user.role == 'admin':
        results = AnalysisResult.query.all()
    else:
        results = AnalysisResult.query.filter_by(user_id=current_user.id).all()
    return render_template('history.html', results=results)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
