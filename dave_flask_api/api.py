from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_restful import Resource, Api, reqparse, fields, marshal_with, abort

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///api.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
api = Api(app)

user_args = reqparse.RequestParser()
user_args.add_argument('username', type=str, required=True, help='Username cannot be blank')
user_args.add_argument('email', type=str, required=True, help='Email cannot be blank')

user_fields = {
    'id': fields.Integer,
    'username': fields.String,
    'email': fields.String
}

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return f"{self.username} - {self.email}"

class Users(Resource):
    @marshal_with(user_fields)
    def get(self):
        users = User.query.all()
        return users
    @marshal_with(user_fields)
    def post(self):
        args = user_args.parse_args()
        new_user = User(username=args['username'], email=args['email'])
        db.session.add(new_user)
        db.session.commit()
        users = User.query.all()
        return users, 201
class UserById(Resource):
    @marshal_with(user_fields)
    def get(self, user_id):
        user = User.query.filter_by(id=user_id).first()
        if not user:
            abort(404, message="User not found")
        return user

    @marshal_with(user_fields)
    def patch(self, user_id):
        args = user_args.parse_args()
        user = User.query.filter_by(id=user_id).first()
        if not user:
            abort(404, message="User not found")
        user.username = args['username']
        user.email = args['email']
        db.session.commit()
        return user
    @marshal_with(user_fields)
    def delete(self, user_id):
        user = User.query.filter_by(id=user_id).first()
        if not user:
            abort(404, message="User not found")
        db.session.delete(user)
        db.session.commit()
        users = User.query.all()
        return users


api.add_resource(Users, '/api/users')
api.add_resource(UserById, '/api/users/<int:user_id>')



@app.route('/') 
def home():
    return '<h1>Welcome to the Flask API!!!</h1>'



if __name__ == '__main__':
    app.run(debug=True)