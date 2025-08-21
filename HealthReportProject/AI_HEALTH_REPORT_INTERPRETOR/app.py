import os
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from models import db, User, HealthReport
from forms import LoginForm, RegisterForm

# Import AI blueprint + helpers from utils/ai.py
# Ensure utils/__init__.py exists (even empty) to make it a package.
from utils.ai import bp as ai_bp, interpret_file, register_context_from_parts

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['UPLOAD_FOLDER'] = 'uploads'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)

# Expose /ask-text, /analyze-report, /audio/<id> in this same app
app.register_blueprint(ai_bp)

login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_first_request
def create_tables():
    db.create_all()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and check_password_hash(user.password, form.password.data):
            login_user(user)
            return redirect(url_for('dashboard'))
        flash('Invalid email or password')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_pw = generate_password_hash(form.password.data)
        new_user = User(email=form.email.data, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful. You can now log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    ai_result = None
    summary = None
    recommendations = None
    context_id = None  # NEW: pass to template for mic

    if request.method == 'POST':
        file = request.files.get('health_report')
        if file and file.filename:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            file.save(file_path)

            # interpret_file now returns 4 values
            summary, recommendations, raw_text, keywords = interpret_file(file_path)

            new_report = HealthReport(
                user_id=current_user.id,
                raw_text=raw_text or "",
                summary=summary or "",
                recommendations=recommendations or ""
            )

            db.session.add(new_report)
            db.session.commit()

            # NEW: create scoped voice context for this report
            context_id = register_context_from_parts(summary, recommendations, raw_text, keywords)

            ai_result = summary

    reports = (HealthReport.query
               .filter_by(user_id=current_user.id)
               .order_by(HealthReport.date_uploaded.desc())
               .all())

    return render_template(
        'dashboard.html',
        ai_result=ai_result,
        recommendations=recommendations,
        reports=reports,
        user=current_user,
        context_id=context_id  # NEW: template can expose this to JS as window.CONTEXT_ID
    )

# --- NEW: Delete a past summary (AJAX-friendly) ---
@app.post('/report/<int:report_id>/delete')
@login_required
def delete_report(report_id):
    report = HealthReport.query.get_or_404(report_id)
    if report.user_id != current_user.id:
        abort(403)
    db.session.delete(report)
    db.session.commit()
    return jsonify({"ok": True})

if __name__ == '__main__':
    app.run(debug=True, port=5002)
