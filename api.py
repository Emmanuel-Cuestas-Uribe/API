from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_restx import Api, Resource, fields
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import bcrypt
from marshmallow_sqlalchemy import SQLAlchemySchema, auto_field
from flask_cors import CORS

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.config['SQLALCHEMY_DATABASE_URI'] = "mysql+pymysql://root@localhost/u"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secreta'  # Cambiar en producción

db = SQLAlchemy(app)
api = Api(app, version='1.0', title='API de Usuarios', description='CRUD de usuarios con autenticación')
jwt = JWTManager(app)

ns = api.namespace('api', description='Operaciones de usuarios')

# Modelo de Usuario
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

    def __init__(self, username, email, password):
        self.username = username
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Esquema para serialización
class UserSchema(SQLAlchemySchema):
    class Meta:
        model = User
        load_instance = True

    id = auto_field()
    username = auto_field()
    email = auto_field()


user_schema = UserSchema()
users_schema = UserSchema(many=True)

# Modelos para Swagger
user_model = api.model('Usuario', {
    'id': fields.Integer(readOnly=True),
    'username': fields.String(required=True),
    'email': fields.String(required=True),
    'password': fields.String(required=True)
})

login_model = api.model('Login', {
    'username': fields.String(required=True),
    'password': fields.String(required=True)
})

@ns.route('/registro')
class Registro(Resource):
    @api.expect(user_model)
    def post(self):
        """Registrar nuevo usuario"""
        data = request.get_json()
        
        if User.query.filter_by(username=data['username']).first():
            return {'mensaje': 'El nombre de usuario ya existe'}, 400
            
        if User.query.filter_by(email=data['email']).first():
            return {'mensaje': 'El email ya está registrado'}, 400
            
        nuevo_usuario = User(
            username=data['username'],
            email=data['email'],
            password=data['password']
        )
        
        db.session.add(nuevo_usuario)
        db.session.commit()
        
        return {'mensaje': 'Usuario creado exitosamente', 'usuario': user_schema.dump(nuevo_usuario)}, 201

@ns.route('/login')
class Login(Resource):
    @api.expect(login_model)
    def post(self):
        """Iniciar sesión y obtener token"""
        data = request.get_json()
        user = User.query.filter_by(username=data['username']).first()
        
        if not user or not bcrypt.checkpw(data['password'].encode('utf-8'), user.password.encode('utf-8')):
            return {'mensaje': 'Credenciales inválidas'}, 401
            
        access_token = create_access_token(identity=user.id)
        return {'access_token': access_token}, 200

@ns.route('/usuarios')
class ListaUsuarios(Resource):
    @jwt_required()
    def get(self):
        """Obtener todos los usuarios"""
        usuarios = User.query.all()
        return users_schema.dump(usuarios)

@ns.route('/usuario/<int:id>')
class Usuario(Resource):
    @jwt_required()
    def get(self, id):
        """Obtener un usuario por ID"""
        usuario = User.query.get_or_404(id)
        return user_schema.dump(usuario)

    @jwt_required()
    @api.expect(user_model)
    def put(self, id):
        """Actualizar usuario"""
        usuario = User.query.get_or_404(id)
        data = request.get_json()
        
        current_user_id = get_jwt_identity()
        if usuario.id != current_user_id:
            return {'mensaje': 'No autorizado'}, 403
        
        if 'username' in data:
            usuario.username = data['username']
        if 'email' in data:
            usuario.email = data['email']
        if 'password' in data:
            usuario.password = bcrypt.hashpw(data['password'].encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        db.session.commit()
        return user_schema.dump(usuario)

    @jwt_required()
    def delete(self, id):
        """Eliminar usuario"""
        usuario = User.query.get_or_404(id)
        
        current_user_id = get_jwt_identity()
        if usuario.id != current_user_id:
            return {'mensaje': 'No autorizado'}, 403
        
        db.session.delete(usuario)
        db.session.commit()
        return {'mensaje': 'Usuario eliminado'}, 200

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
