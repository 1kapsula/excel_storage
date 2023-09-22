import os
import datetime
import hashlib, json
from db_session import Database
from models import Users, Files, InvalidToken
from flask import Flask, g, jsonify, request, abort
from flask_httpauth import HTTPBasicAuth
from werkzeug.utils import secure_filename
from sqlalchemy import or_
import pandas as pd

app = Flask(__name__)
auth = HTTPBasicAuth()

app.config["SECRET_KEY"] = "mysecretkey"
app.config["VALIDITY_TIME"] = {"exp": datetime.datetime.utcnow() + datetime.timedelta(days=365)}
app.config["ROUNDS"] = 4
app.config["ALLOWED_EXTENSIONS"] = {'xlsx', 'xls'}
app.config['UPLOAD_FOLDER'] = "uploaded_files"

db = Database("excel_storage.db")

@auth.verify_password
def verify_password(username_or_token, password):
    session = db.create_session()
    user = Users.decode_access_token(username_or_token, session)
    if not user:
        user = session.query(Users).filter_by(username=username_or_token).first()
        if not user or not user.check_password(password):
            return False
    g.user = user
    return True

@app.route('/')
def main_win():
    return("Excel storage")

@app.route('/api/get_token', methods=['GET'])
@auth.login_required
def get_auth_token():
    token = g.user.encode_access_token()
    return jsonify({'token': token})

@app.route('/api/users', methods=["POST"])
def create_user():
    if request.method == 'POST':
        with db.create_session() as session:
            username = request.json.get('username')
            password = request.json.get('password')
            if username is None or password is None:
                return abort(400)
            if session.query(Users).filter_by(username=username).first() is not None:
                return abort(400)
            user = Users(username=username)
            user.password = password
            session.add(user)
            session.flush()
            session.commit()
            return jsonify({"username": user.username}), 201
    return abort(400)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config["ALLOWED_EXTENSIONS"]

@app.route('/api/upload_excel_file', methods=["POST"])
@auth.login_required
def upload_excel_file():
    if request.method == 'POST':
        with db.create_session() as session:
            user = g.user
            if 'file' not in request.files:
                return jsonify({"error": "No file in the request"}), 400
            file = request.files['file']
            if file.filename == "":
                return jsonify({"error": "Empty file name"}), 400
            if file and allowed_file(file.filename):
                filename_hash = hashlib.sha256(bytes(secure_filename(file.filename), 'utf-8')).hexdigest()
                username_hash = hashlib.sha256(bytes(user.username, 'utf-8')).hexdigest()

                is_private = request.args.get('is_private', 'True').lower() == 'true'

                if is_private:
                    path = os.path.join(app.config['UPLOAD_FOLDER'], username_hash, filename_hash[:2], filename_hash[2:4])
                else:
                    path = os.path.join(app.config['UPLOAD_FOLDER'], "public", filename_hash[:2], filename_hash[2:4])

                if not os.path.exists(path):
                    os.makedirs(path, exist_ok=True)
                file.save(os.path.join(path, secure_filename(file.filename)))
                excel_file = Files(
                    file_name=file.filename,
                    file_path=os.path.join(path, secure_filename(file.filename)),
                    create_date=datetime.datetime.now(),
                    is_private=is_private,
                    user_id=user.user_id
                )
                session.add(excel_file)
                session.commit()
                return jsonify({"message": f"{secure_filename(file.filename)} uploaded and saved for user {user.user_id}"}), 200
            else:
                return jsonify({"error": "File type not allowed"}), 400
    else:
        return abort(400)


# def delete_empty_directories(base_directory, path_to_file):
#     base_directory = os.path.realpath(base_directory)
#     folder = os.path.dirname(os.path.realpath(path_to_file))
#     while folder.startswith(base_directory):
#         print(f"Checking folder: {folder}")
#         if not os.listdir(folder):
#             print(f"Deleting folder: {folder}")
#             os.rmdir(folder)
#         folder = os.path.dirname(folder)

@app.route('/api/delete_file/<filename>', methods=['DELETE'])
@auth.login_required
def delete_file(filename):
    if request.method == "DELETE":
        with db.create_session() as session:
            user = g.user
            if request.json['from_private']:
                file = session.query(Files).filter(Files.file_name == filename, Files.user_id == user.user_id, Files.is_private).first()
            else:
                file = session.query(Files).filter(Files.file_name == filename, Files.user_id == user.user_id, Files.is_private == 0).first()
            if file:
                path = file.file_path
                if os.path.exists(path):
                    os.remove(path)
                session.delete(file)
                session.commit()
            else:
                return jsonify({"reason": "There is no such file"}), 404
            return jsonify({"deleted": filename}), 200
    return jsonify({"reason": "Method is not allowed"}), 404

@app.route('/api/file_list', methods=['GET'])
@auth.login_required
def files_list():
    if request.method == "GET":
        with db.create_session() as session:
            files = session.query(Files).filter(
                or_(Files.user == g.user, Files.is_private == 0)).all()
            if not files:
                return jsonify({"info": "No files found for the user"}), 200
            file_list = [{
                "file_id": file.file_id,
                "file_name": file.file_name,
                "is_private": file.is_private,
                "user_id": file.user_id
            } for file in files]
            return jsonify({
                "message": "List of files related to the user or in public domain",
                "file_list": file_list
            }), 200
    return abort(400)

@app.route('/api/get_excel_file/<filename>', methods=['GET'])
@auth.login_required
def get_excel_file(filename):
    def process_excel_file(file_path, filters=None, sorting=None):
        df = pd.read_excel(file_path)
        if filters:
            for key, value in filters.items():
                if key in df.columns:
                    df = df[df[key] == value]
        if sorting:
            for key, value in sorting.items():
                if key in df.columns:
                    df = df.sort_values(by=key, ascending=(value.lower() == "asc"))
        return df
    filters = request.args.get('filters')
    sorting = request.args.get('sorting')
    if filters:
        filters = json.loads(filters)
    if sorting:
        sorting = json.loads(sorting)
    with db.create_session() as session:
        file = session.query(Files).filter_by(file_name=filename, user=g.user).first()
        if file:
            file_path = file.file_path
            df = process_excel_file(file_path, filters, sorting)
            return df.to_json(orient="split", index=False)
        else:
            return jsonify({"error": "File not found"}), 404


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=12545)
