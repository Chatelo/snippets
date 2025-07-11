from api import db, app

# Create the database and the db table
with app.app_context():
    db.create_all()
    print("Database and tables created!")