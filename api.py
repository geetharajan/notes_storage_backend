from flask import Flask, request, jsonify, session
from flask_cors import CORS
from flask_pymongo import PyMongo
from pymongo import ReturnDocument

from datetime import datetime
import bcrypt
import uuid

app = Flask(__name__)
app.secret_key = 'f3a1c9b7d4e8f26a9b0c3d7e5f8a1246'

CORS(app, supports_credentials=True, origins=["http://localhost:3000"])

app.config["MONGO_URI"] = "mongodb://localhost:27017/notes_db"
mongo = PyMongo(app)
users_collection = mongo.db.users
notes_collection = mongo.db.user_notes



@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    print("data received:", data)

    if not data:
        return jsonify({"error": "No JSON data received"}), 400

    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirmPassword')

    if not username or not email or not password or not confirm_password:
        return jsonify({"error": "All fields are required"}), 400

    if password != confirm_password:
        return jsonify({"error": "Passwords do not match"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"error": "User already exists"}), 409

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    user_data = {
        "user_id": str(uuid.uuid4()),
        "username": username,
        "email": email,
        "password": hashed_password,
        "created_at": datetime.utcnow(),
        "last_updated": datetime.utcnow()
    }

    users_collection.insert_one(user_data)
    return jsonify({"message": "User registered successfully"}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    print("Login payload received:", data)  # Debug log

    if not data:
        return jsonify({"error": "No data provided"}), 400

    email = data.get('email')
    password = data.get('password')

    # Validate required fields
    if not email or not password:
        return jsonify({"error": "Email and password are required"}), 400

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"error": "Invalid email or password"}), 401

    # Compare hashed password
    if not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({"error": "Invalid email or password"}), 401

    session['user_id'] = user['user_id']
    session['username'] = user['username']

    return jsonify({"message": "Login successful", "user_id": user['user_id']}), 200

@app.route('/save_note', methods=['POST'])
def save_note():
   
    # Check if user logged in
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401
     
    print("Session keys:", session.keys())
    print("Session user_id:", session.get('user_id'))

    user_id = session['user_id']
    data = request.get_json()
    
    title = data.get('title')
    content = data.get('content')
    
    if not title or not content:
        return jsonify({"error": "Title and text are required"}), 400
    
    now = datetime.utcnow()
    note_id = f"note{uuid.uuid4().hex[:6]}"
    
    note = {
        "note_id": note_id,
        "user_id": user_id,
        "title": title,
        "content": content,
        "lastModified": now,
        "createdAt": now
    }

    print("note_id", note)
    
    inserted = notes_collection.insert_one(note)

    print("inserted", inserted)
    
    return jsonify({
        "message": "Note created",
        "note_id":  note["note_id"]
    }), 200

@app.route('/get_notes', methods=['GET'])
def get_notes():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session['user_id']

    # Query notes for the user
    notes_cursor = notes_collection.find({"user_id": user_id})

    # Convert cursor to list of dicts and convert ObjectId to string
    notes = []
    for note in notes_cursor:
        note['_id'] = str(note['_id'])
        notes.append(note)

    return jsonify({"notes": notes}), 200

@app.route('/update_note/<note_id>', methods=['PUT'])
def update_note(note_id):
    try:
        data = request.get_json()

        if not data:
            return jsonify({'error': 'Invalid JSON data'}), 400

        update_fields = {
            "title": data.get("title", ""),
            "content": data.get("content", ""),
            "lastModified": datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
        }

        result = notes_collection.update_one(
            {"note_id": note_id}, {"$set": update_fields}
        )

        if result.matched_count == 0:
            return jsonify({'error': 'Note not found'}), 404

        return jsonify({'message': 'Note updated successfully'}), 200
    except Exception as e:
        print(f"Exception occurred: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/delete_note/<note_id>', methods=['DELETE'])
def delete_note(note_id):
    try:
        result = notes_collection.delete_one({"note_id": note_id})

        if result.deleted_count == 0:
            return jsonify({'error': 'Note not found'}), 404

        return jsonify({'message': 'Note deleted successfully'}), 200
    except Exception as e:
        print(f"Exception occurred: {e}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/get_user', methods=['GET'])
def get_user():
    username = session.get('username')
    if username:
        return jsonify({"username": username}), 200
    else:
        return jsonify({"error": "User not logged in"}), 401


if __name__ == '__main__':
    app.run(host='localhost', port=5000)
