
import os
import threading
import datetime
import logging
import requests

from dotenv import load_dotenv
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# --- Load .env ---
load_dotenv()

TELEGRAM_TOKEN = os.getenv("TELEGRAM_TOKEN")
ADMIN_CHAT_ID = os.getenv("ADMIN_CHAT_ID")

# --- Flask app config from env (fallbacks) ---
DATABASE_URI = os.getenv("DATABASE_URI", "sqlite:///quest.sqlite")
SECRET_KEY = os.getenv("SECRET_KEY", "supersecretkey")

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY

# Logging
logging.basicConfig(level=logging.INFO)

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
    hint = db.Column(db.Text, nullable=True)  # <-- новое поле

# -------------------------
# Telegram bot setup
# -------------------------
bot = None
try:
    if TELEGRAM_TOKEN and ADMIN_CHAT_ID:
        import telebot
        ADMIN_CHAT_ID = int(ADMIN_CHAT_ID)
        bot = telebot.TeleBot(TELEGRAM_TOKEN, threaded=False, skip_pending=True)
        app.logger.info("Telegram bot configured.")
    else:
        app.logger.info("Telegram not configured (TELEGRAM_TOKEN or ADMIN_CHAT_ID missing).")
except Exception as e:
    app.logger.exception("Ошибка инициализации Telegram бота: %s", e)
    bot = None

def send_telegram(message: str):
    """Безопасная отправка сообщения админу в Telegram (с verify=False)."""
    try:
        if bot and ADMIN_CHAT_ID:
            bot.send_message(ADMIN_CHAT_ID, message)
            app.logger.info("Telegram sent: %s", message)
        else:
            app.logger.info("Telegram disabled; would send: %s", message)
    except Exception as e:
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage"
            requests.post(
                url,
                data={"chat_id": ADMIN_CHAT_ID, "text": message},
                verify=False  # 👈 костыль, отключаем проверку SSL
            )
            app.logger.warning("Сообщение отправлено через requests с verify=False")
        except Exception as inner_e:
            app.logger.exception("Не удалось отправить сообщение даже через requests: %s", inner_e)

def run_telegram_bot():
    if not bot:
        return
    try:
        bot.infinity_polling(timeout=60, long_polling_timeout=60)
    except Exception as e:
        app.logger.exception("Telegram polling stopped: %s", e)

# -------------------------
# Хелперы
# -------------------------
def build_chain_from(start_code):
    chain = []
    visited = set()
    code = start_code
    while code and code not in visited:
        visited.add(code)
        lvl = Level.query.filter_by(code=code).first()
        if not lvl:
            break
        chain.append(lvl)
        code = (lvl.next_code or "").strip()
    return chain


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
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = User.query.filter_by(username=username, role='admin').first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = 'admin'
            return redirect(url_for('admin_dashboard'))

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
    name = request.form.get('name', '').strip()
    if not name:
        flash("Введите название квеста")
        return redirect(url_for('admin_dashboard'))
    quest = Quest(name=name, admin_id=session['user_id'])
    db.session.add(quest)
    db.session.commit()
    flash("Квест создан!")
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/quest/<int:quest_id>/delete', methods=['POST'])
@admin_required
def admin_delete_quest(quest_id):
    quest = Quest.query.get_or_404(quest_id)
    # Удаляем все уровни квеста, чтобы не было зависимых записей
    for level in quest.levels:
        db.session.delete(level)
    db.session.delete(quest)
    db.session.commit()
    flash(f'Квест "{quest.name}" и все его уровни удалены!')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/quest/<int:quest_id>/levels', methods=['GET', 'POST'])
@admin_required
def admin_levels(quest_id):
    quest = Quest.query.get_or_404(quest_id)
    levels = quest.levels

    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        text = request.form.get('text', '').strip()
        next_code = request.form.get('next_code', '').strip() or None
        is_final = 'is_final' in request.form
        hint = request.form.get('hint', '').strip()  # Новое поле

        existing_level = Level.query.filter_by(code=code, quest_id=quest.id).first()
        if existing_level:
            flash("Уровень с таким кодом уже существует!")
        else:
            level = Level(
                code=code, text=text, next_code=next_code,
                quest_id=quest.id, is_final=is_final, hint=hint
            )
            db.session.add(level)
            db.session.commit()
            flash("Уровень добавлен!")

        return redirect(url_for('admin_levels', quest_id=quest.id))

    return render_template('admin_level_edit.html', quest=quest, levels=levels)

@app.route('/admin/level/<int:level_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_level(level_id):
    level = Level.query.get_or_404(level_id)
    if request.method == 'POST':
        code = request.form.get('code', '').strip()
        text = request.form.get('text', '').strip()
        next_code = request.form.get('next_code', '').strip() or None
        is_final = bool(request.form.get('is_final'))
        hint = request.form.get('hint', '').strip()  # Подсказка

        if not code or not text:
            flash("Заполните все обязательные поля")
            return redirect(url_for('admin_edit_level', level_id=level.id))

        level.code = code
        level.text = text
        level.next_code = next_code
        level.is_final = is_final
        level.hint = hint  # Сохраняем подсказку

        db.session.commit()
        flash("Уровень обновлён")
        return redirect(url_for('admin_levels', quest_id=level.quest_id))

    return render_template('admin_edit_level_form.html', level=level)

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
        text = request.form.get('text', '').strip()
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
        start_code = request.form.get('start_code', '').strip()
        level = Level.query.filter_by(code=start_code).first()
        if level:
            session['current_level'] = level.code
            session['current_quest'] = level.quest_id
            session['start_level'] = level.code
            session['start_time'] = datetime.datetime.now().timestamp()

            try:
                quest_name = level.quest.name if level.quest else "неизвестный"
                send_telegram(f"Игрок начал квест: {quest_name}")
            except Exception as e:
                app.logger.exception("Ошибка при отправке телеграм уведомления начала квеста: %s", e)

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

    # Инициализация времени в сессии
    if 'start_time' not in session:
        session['start_time'] = datetime.datetime.now().timestamp()
    if 'elapsed_time' not in session:
        session['elapsed_time'] = 0

    # Прошедшее время с начала уровня
    elapsed = int(datetime.datetime.now().timestamp() - session['start_time'])
    total_elapsed = session['elapsed_time'] + elapsed

    if request.method == 'POST':
        next_code = request.form.get('next_code', '').strip()
        use_hint = request.form.get('use_hint')

        # Если игрок нажал "подсказку"
        if use_hint:
            session['hint_shown'] = True
            return redirect(url_for('player_level'))

        # Проверка кода
        if next_code == (level.next_code or '').strip() or level.is_final:
            # Обновляем накопленное время
            session['elapsed_time'] += elapsed
            session['start_time'] = datetime.datetime.now().timestamp()  # сброс таймера на следующем уровне
            session.pop('hint_shown', None)  # сброс подсказки

            # Telegram уведомление
            try:
                quest_name = level.quest.name if level.quest else "неизвестный"
                send_telegram(f"Игрок прошёл уровень {level.code} квеста: {quest_name}")
            except Exception as e:
                app.logger.exception("Ошибка при отправке телеграм уведомления: %s", e)

            # Переход на следующий уровень или финал
            next_level = Level.query.filter_by(code=next_code).first()
            if next_level:
                session['current_level'] = next_level.code
                return redirect(url_for('player_level'))
            else:
                session.pop('current_level', None)
                return redirect(url_for('player_finish'))

        flash("Неверный код")

    hint_shown = session.get('hint_shown', False)

    return render_template(
        'player_level.html',
        level=level,
        elapsed=elapsed,
        hint_shown=hint_shown,
        hint_delay=level.hint_delay if hasattr(level, 'hint_delay') else 30
    )

@app.route('/finish')
def player_finish():
    elapsed_time = session.pop('elapsed_time', 0)
    quest_id = session.pop('current_quest', None)
    start_level = session.pop('start_level', None)

    finish_text = None
    quest_name = "неизвестный"
    if quest_id:
        finish_text_obj = QuestFinishText.query.filter_by(quest_id=quest_id).first()
        finish_text = finish_text_obj.text if finish_text_obj else None
        quest = Quest.query.get(quest_id)
        if quest:
            quest_name = quest.name

    try:
        total = 0
        if start_level:
            chain = build_chain_from(start_level)
            total = len(chain)
        send_telegram(f"Игрок прошёл квест \"{quest_name}\" за {elapsed_time} сек. Этапов: {total or 'неизвестно'}")
    except Exception as e:
        app.logger.exception("Ошибка при отправке телеграм уведомления финиша: %s", e)

    return render_template('player_finish.html', elapsed=elapsed_time, finish_text=finish_text)

# -------------------------
# Создание базы и запуск
# -------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Создать админа по умолчанию
        if not User.query.filter_by(username='admin').first():
            admin = User(username='admin', password=generate_password_hash('admin123'), role='admin')
            db.session.add(admin)
            db.session.commit()

    try:
        if bot and ADMIN_CHAT_ID:
            bot.send_message(ADMIN_CHAT_ID, "✅ Бот запущен и готов!")
    except Exception as e:
        print("Ошибка при отправке в Telegram:", e)

    app.run(debug=True)