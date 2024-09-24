from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS  

app = Flask(__name__)

CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)  

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha = db.Column(db.String(200), nullable=False)

    def __init__(self, nome, email, senha):
        self.nome = nome
        self.email = email
        self.senha = senha

class Comentario(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  
    comentario = db.Column(db.String(500), nullable=False)
    avaliacao = db.Column(db.Float, nullable=False)  
    user = db.relationship('User', backref=db.backref('comentarios', lazy=True))

    def __init__(self, user_id, comentario, avaliacao):
        self.user_id = user_id
        self.comentario = comentario
        self.avaliacao = avaliacao

# Rota para inicializar o banco de dados e criar as tabelas
@app.route('/init_db', methods=['GET'])
def init_db():
    with app.app_context():
        db.create_all()
    return jsonify({"message": "Banco de dados inicializado!"}), 200

if __name__ == '__main__':
    app.run(debug=True)
