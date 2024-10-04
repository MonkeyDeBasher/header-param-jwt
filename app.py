from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity

app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'secret_key'
jwt = JWTManager(app)


# 1. Авторизация через заголовок (Header)
#URL: http://127.0.0.1:5000/header-auth
#Заголовок: Authorization: Bearer mysecrettoken
@app.route('/header-auth', methods=['GET'])
def header_auth():
    auth_token = request.headers.get('Authorization')
    if auth_token == 'Bearer mysecrettoken':
        return jsonify(message="Authenticated via header"), 200
    return jsonify(message="Unauthorized"), 401


# 2. Авторизация через параметр (Query Parameter)
# Тип запроса: GET
# URL: http://127.0.0.1:5000/param-auth?auth_token=mysecrettoken
@app.route('/param-auth', methods=['GET'])
def param_auth():
    auth_token = request.args.get('auth_token')
    if auth_token == 'mysecrettoken':
        return jsonify(message="Authenticated via parameter"), 200
    return jsonify(message="Unauthorized"), 401


# 3. JWT аутентификация
#http://127.0.0.1:5000/login
#Тело запроса (JSON):
#{
#  "username": "user",
#  "password": "password"
#}
#
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')

    if username == 'user' and password == 'password':
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token), 200
    return jsonify(message="Bad credentials"), 401


@app.route('/jwt-auth', methods=['GET'])
@jwt_required()
def jwt_auth():
    current_user = get_jwt_identity()
    return jsonify(logged_in_as=current_user), 200


if __name__ == '__main__':
    app.run(debug=True)
