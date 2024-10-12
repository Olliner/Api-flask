from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS  
import re
import os
import logging

app = Flask(__name__)
CORS(app)

# Configuração do banco de dados usando variáveis de ambiente
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///db.sqlite3')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Configuração de logging
logging.basicConfig(level=logging.INFO)

# Modelo User
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    senha = db.Column(db.String(200), nullable=False)

    def __init__(self, nome, email, senha):
        self.nome = nome
        self.email = email
        self.senha = senha

# Modelo Comentario
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

# Rota de inicialização do banco de dados
@app.route('/init_db', methods=['GET'])
def init_db():
    with app.app_context():
        db.create_all()
    return jsonify({"message": "Banco de dados inicializado!"}), 200

# Função para validar e-mail
def is_valid_email(email):
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(email_regex, email) is not None

# Rota de registro
@app.route('/users/register', methods=['POST'])
def register():
    data = request.get_json()
    if 'nome' not in data or 'email' not in data or 'senha' not in data:
        return jsonify({"message": "Dados incompletos!"}), 400
    
    if not is_valid_email(data['email']):
        return jsonify({"message": "E-mail inválido!"}), 400

    if User.query.filter_by(nome=data['nome']).first() or User.query.filter_by(email=data['email']).first():
        return jsonify({"message": "Nome ou e-mail já estão em uso!"}), 409

    hashed_password = generate_password_hash(data['senha'], method='pbkdf2:sha256')
    new_user = User(nome=data['nome'], email=data['email'], senha=hashed_password)

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({"message": "Usuário registrado com sucesso!"}), 201
    except Exception as e:
        logging.error(f"Erro ao registrar usuário: {str(e)}")
        return jsonify({"message": "Erro ao registrar usuário!", "error": str(e)}), 400

# Rota de login
@app.route('/users/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(nome=data.get('nome')).first()

    if user and check_password_hash(user.senha, data.get('senha')):
        return jsonify({"message": "Login bem-sucedido!", "nome": user.nome}), 200
    else:
        return jsonify({"message": "Falha no login! Verifique suas credenciais."}), 401

# Rota para obter os detalhes do usuário logado
@app.route('/users/<string:nome>', methods=['GET'])
def get_user_details(nome):
    user = User.query.filter_by(nome=nome).first()

    if user:
        return jsonify({
            "nome": user.nome,
            "email": user.email,
        }), 200
    else:
        return jsonify({"message": "Usuário não encontrado!"}), 404

# Rota para atualizar os dados do usuário
@app.route('/users/<string:nome>', methods=['PUT'])
def update_user_details(nome):
    data = request.get_json()
    user = User.query.filter_by(nome=nome).first()

    if not user:
        return jsonify({"message": "Usuário não encontrado!"}), 404

    if 'email' in data:
        if not is_valid_email(data['email']):
            return jsonify({"message": "E-mail inválido!"}), 400
        user.email = data['email']
        
    if 'senha' in data:
        user.senha = generate_password_hash(data['senha'], method='pbkdf2:sha256')

    try:
        db.session.commit()
        return jsonify({"message": "Dados do usuário atualizados com sucesso!"}), 200
    except Exception as e:
        logging.error(f"Erro ao atualizar dados do usuário: {str(e)}")
        return jsonify({"message": "Erro ao atualizar dados do usuário!", "error": str(e)}), 400

# Rota para adicionar comentário e avaliação
@app.route('/comentarios', methods=['POST'])
def add_comentario():
    data = request.get_json()
    if 'nome' not in data or 'comentario' not in data or 'avaliacao' not in data:
        return jsonify({"message": "Dados incompletos!"}), 400

    user = User.query.filter_by(nome=data['nome']).first()

    if not user:
        return jsonify({"message": "Usuário não encontrado!"}), 404
    
    if not (1 <= data['avaliacao'] <= 5):
        return jsonify({"message": "Avaliação deve ser um número entre 1 e 5!"}), 400

    novo_comentario = Comentario(
        user_id=user.id,
        comentario=data['comentario'],
        avaliacao=data['avaliacao']
    )

    try:
        db.session.add(novo_comentario)
        db.session.commit()
        return jsonify({
            "message": "Comentário e avaliação adicionados com sucesso!",
            "comentario": {
                "nome": user.nome,
                "comentario": novo_comentario.comentario,
                "avaliacao": novo_comentario.avaliacao
            }
        }), 201
    except Exception as e:
        logging.error(f"Erro ao adicionar comentário: {str(e)}")
        return jsonify({"message": "Erro ao adicionar comentário!", "error": str(e)}), 400

# Rota para obter comentários e média de avaliações
@app.route('/comentarios', methods=['GET'])
def get_comentarios():
    comentarios = Comentario.query.all()
    comentarios_lista = [{
        "nome": comentario.user.nome,
        "comentario": comentario.comentario,
        "avaliacao": comentario.avaliacao
    } for comentario in comentarios]

    avaliacoes_soma = sum(comentario.avaliacao for comentario in comentarios)
    media_avaliacao = avaliacoes_soma / len(comentarios) if comentarios else 0

    return jsonify({
        "comentarios": comentarios_lista,
        "media_avaliacao": media_avaliacao
    }), 200

# Rota para verificar e-mail
@app.route('/users/verify-email', methods=['POST'])
def verify_email():
    data = request.get_json()
    
    if 'email' not in data:
        return jsonify({"message": "E-mail não fornecido!"}), 400

    user = User.query.filter_by(email=data['email']).first()
    
    if user:
        return jsonify({"message": "E-mail verificado com sucesso!"}), 200
    else:
        return jsonify({"message": "E-mail não encontrado!"}), 404

# Rota para redefinir senha
@app.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()

    # Verifica se os dados necessários estão presentes
    if 'email' not in data or 'nova_senha' not in data or 'confirmacao_senha' not in data:
        return jsonify({"message": "E-mail ou senhas não fornecidos!"}), 400

    if data['nova_senha'] != data['confirmacao_senha']:
        return jsonify({"message": "As senhas não coincidem!"}), 400

    # Aqui, verificamos se o e-mail existe no banco de dados
    user = User.query.filter_by(email=data['email']).first()
    
    if user:
        # Atualiza a senha do usuário
        hashed_password = generate_password_hash(data['nova_senha'], method='pbkdf2:sha256')
        user.senha = hashed_password

        try:
            db.session.commit()
            return jsonify({"message": "Senha redefinida com sucesso!"}), 200
        except Exception as e:
            logging.error(f"Erro ao redefinir senha: {str(e)}")
            return jsonify({"message": "Erro ao redefinir senha!", "error": str(e)}), 400
    else:
        return jsonify({"message": "E-mail não encontrado!"}), 404

# Rota para deletar Usuario
@app.route('/comentarios/<int:id>', methods=['DELETE'])
def delete_comentario(id):
    comentario = Comentario.query.get(id)
    
    if comentario:
        db.session.delete(comentario)
        db.session.commit()
        return jsonify({"message": "Comentário deletado com sucesso!"}), 200
    else:
        return jsonify({"message": "Comentário não encontrado!"}), 404

if __name__ == '__main__':
    app.run(debug=True)
