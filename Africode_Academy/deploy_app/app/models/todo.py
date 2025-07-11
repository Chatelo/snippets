from app.extensions import db

# Minimal model for demonstration
class Todo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)

    def __repr__(self):
        return f'Todo {self.title}'
