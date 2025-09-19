from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///quest.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'supersecretkey'

db = SQLAlchemy(app)

# -------------------------
# Модели
# -------------------------
class QuestFinishText(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quest_id = db.Column(db.Integer, db.ForeignKey('quest.id'), unique=True)
    quest = db.relationship('Quest', backref='finish_text')
    text = db.Column(db.Text, nullable=True)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(150))
    role = db.Column(db.String(10))  # admin или player

class Quest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    admin_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    admin = db.relationship('User', backref='quests')

class Level(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quest_id = db.Column(db.Integer, db.ForeignKey('quest.id'))
    quest = db.relationship('Quest', backref='levels')
    code = db.Column(db.String(50))
    text = db.Column(db.Text)
    next_code = db.Column(db.String(50), nullable=True)
    is_final = db.Column(db.Boolean, default=False)

# -------------------------
# Декораторы
# -------------------------
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash("Требуется вход администратора")
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return wrapper

# -------------------------
# Админ
# -------------------------
@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username, role='admin').first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))
        flash("Неверный логин или пароль")
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.clear()
    return redirect(url_for('admin_login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    admin = User.query.get(session['user_id'])
    quests = admin.quests
    return render_template('admin_dashboard.html', quests=quests)

@app.route('/admin/add_quest', methods=['POST'])
@admin_required
def admin_add_quest():
    name = request.form['name']
    quest = Quest(name=name, admin_id=session['user_id'])
    db.session.add(quest)
    db.session.commit()
    flash("Квест создан!")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/quest/<int:quest_id>/levels', methods=['GET', 'POST'])
@admin_required
def admin_levels(quest_id):
    quest = Quest.query.get_or_404(quest_id)
    levels = quest.levels

    if request.method == 'POST':
        code = request.form['code'].strip()
        text = request.form['text'].strip()
        next_code = request.form.get('next_code', '').strip() or None
        is_final = 'is_final' in request.form

        # Проверка на дубликат кода уровня внутри этого квеста
        existing_level = Level.query.filter_by(code=code, quest_id=quest.id).first()
        if existing_level:
            flash("Уровень с таким кодом уже существует!")
        else:
            level = Level(code=code, text=text, next_code=next_code, quest_id=quest.id, is_final=is_final)
            db.session.add(level)
            db.session.commit()
            flash("Уровень добавлен!")

        return redirect(url_for('admin_levels', quest_id=quest.id))

    return render_template('admin_level_edit.html', quest=quest, levels=levels)

# Редактирование уровня
@app.route('/admin/level/<int:level_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_level(level_id):
    level = Level.query.get_or_404(level_id)
    if request.method == 'POST':
        # Проверяем поля формы
        code = request.form.get('code', '').strip()
        text = request.form.get('text', '').strip()
        next_code = request.form.get('next_code', '').strip() or None
        is_final = bool(request.form.get('is_final'))

        if not code or not text:
            flash("Заполните все обязательные поля")
            return redirect(url_for('admin_edit_level', level_id=level.id))

        # Обновляем уровень
        level.code = code
        level.text = text
        level.next_code = next_code
        level.is_final = is_final

        db.session.commit()
        flash("Уровень обновлён")
        return redirect(url_for('admin_levels', quest_id=level.quest_id))

    # GET-запрос — показываем форму с текущими значениями
    return render_template('admin_edit_level_form.html', level=level)

# Удаление уровня
@app.route('/admin/level/<int:level_id>/delete', methods=['POST'])
@admin_required
def admin_delete_level(level_id):
    level = Level.query.get_or_404(level_id)
    quest_id = level.quest_id
    db.session.delete(level)
    db.session.commit()
    flash("Уровень удалён!")
    return redirect(url_for('admin_levels', quest_id=quest_id))


@app.route('/admin/quest/<int:quest_id>/finish_text', methods=['GET', 'POST'])
@admin_required
def admin_finish_text(quest_id):
    quest = Quest.query.get_or_404(quest_id)
    finish_text = QuestFinishText.query.filter_by(quest_id=quest.id).first()

    if request.method == 'POST':
        text = request.form['text'].strip()
        if finish_text:
            finish_text.text = text
        else:
            finish_text = QuestFinishText(quest_id=quest.id, text=text)
            db.session.add(finish_text)
        db.session.commit()
        flash("Текст финальной страницы сохранён!")
        return redirect(url_for('admin_levels', quest_id=quest.id))

    return render_template('admin_finish_text.html', quest=quest, finish_text=finish_text)

# -------------------------
# Игрок
# -------------------------
@app.route('/', methods=['GET', 'POST'])
def player_start():
    if request.method == 'POST':
        start_code = request.form['start_code'].strip()
        level = Level.query.filter_by(code=start_code).first()
        if level:
            session['current_level'] = level.code
            session['current_quest'] = level.quest_id  # сохраняем ID квеста
            session['start_time'] = datetime.datetime.now().timestamp()
            return redirect(url_for('player_level'))
        flash("Неверный стартовый код")
    return render_template('player_start.html')


@app.route('/level', methods=['GET', 'POST'])
def player_level():
    if 'current_level' not in session:
        return redirect(url_for('player_start'))

    level = Level.query.filter_by(code=session['current_level']).first()
    if not level:
        return redirect(url_for('player_start'))

    elapsed = int(datetime.datetime.now().timestamp() - session.get('start_time', datetime.datetime.now().timestamp()))

    if request.method == 'POST':
        next_code = request.form['next_code'].strip()

        # Финальный уровень
        if level.is_final or not level.next_code:
            session['elapsed_time'] = elapsed
            session.pop('current_level')
            # current_quest остаётся для получения текста финала
            return redirect(url_for('player_finish'))

        # Проверка кода для остальных уровней
        if next_code == level.next_code:
            next_level = Level.query.filter_by(code=next_code).first()
            if next_level:
                session['current_level'] = next_level.code
                return redirect(url_for('player_level'))
            else:
                # На случай если следующий уровень не найден, считаем финал
                session['elapsed_time'] = elapsed
                session.pop('current_level')
                return redirect(url_for('player_finish'))

        # Неверный код
        flash("Неверный код")

    return render_template('player_level.html', level=level, elapsed=elapsed)


@app.route('/finish')
def player_finish():
    elapsed_time = session.pop('elapsed_time', 0)
    quest_id = session.pop('current_quest', None)  # берём ID квеста

    finish_text = None
    if quest_id:
        finish_text_obj = QuestFinishText.query.filter_by(quest_id=quest_id).first()
        finish_text = finish_text_obj.text if finish_text_obj else None

    return render_template('player_finish.html', elapsed=elapsed_time, finish_text=finish_text)

# -------------------------
# Создание базы и запуск
# -------------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Создать админа по умолчанию
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password=generate_password_hash('admin123'), role='admin')
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)


