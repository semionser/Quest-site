from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    # Создаём все таблицы
    db.create_all()

    # Создаём админа, если его нет
    if not User.query.filter_by(username="admin").first():
        admin = User(username="admin", password=generate_password_hash("password"), role="admin")
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin создан: admin / password")
    else:
        print("⚠️ Admin уже существует")