from flask import Flask, jsonify, request
import mysql.connector
import bcrypt
import jwt
import datetime
import os
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.exceptions import RequestEntityTooLarge

app = Flask(__name__)

# MySQL configurations
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Ibad'  # Update with your MySQL password
app.config['MYSQL_DB'] = 'flask_api'
app.config['SECRET_KEY'] = 'your_secret_key'  # Change this to a secure random key

# File upload configurations
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'jpg', 'jpeg', 'png', 'gif', 'pdf'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database connection function
def get_db_connection():
    conn = mysql.connector.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB']
    )
    return conn

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required!'}), 400

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", 
                       (username, hashed_password.decode('utf-8')))
        conn.commit()
        return jsonify({'message': 'User registered successfully!'}), 201
    except mysql.connector.Error as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cursor.close()
        conn.close()

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Username and password are required!'}), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'error': 'Invalid username or password!'}), 401

    token = jwt.encode(
        {'user_id': user['id'], 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return jsonify({'token': token}), 200


# JWT Authentication Decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')

        if not token:
            return jsonify({'error': 'Token is missing!'}), 401

        try:
            token = token.split(" ")[1]  # Remove 'Bearer ' from token
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = decoded_token['user_id']
        except:
            return jsonify({'error': 'Token is invalid or expired!'}), 401

        return f(current_user, *args, **kwargs)
    
    return decorated

@app.route('/protected', methods=['GET'])
@token_required
def protected_route(current_user):
    return jsonify({"message": "Access granted!", "user_id": current_user}), 200


# Error handler for file size limit
@app.errorhandler(RequestEntityTooLarge)
def handle_file_too_large(error):
    return jsonify({"error": "File too large", "message": "Max file size is 16MB."}), 413

# Function to check allowed file types
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Secure File Upload Route (Requires Authentication)
@app.route('/upload', methods=['POST'])
@token_required
def upload_file(current_user):
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)  # Secure the filename

        # Generate a unique filename to prevent overwriting
        unique_filename = f"{datetime.datetime.utcnow().timestamp()}_{filename}"

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)  # Save the file securely

        return jsonify({'message': 'File uploaded successfully', 'file_path': file_path}), 201
    else:
        return jsonify({'error': 'File type not allowed'}), 400

# Get All Public Items
@app.route('/public-items', methods=['GET'])
def public_items():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM public_items WHERE is_public = TRUE")
    items = cursor.fetchall()
    cursor.close()
    conn.close()
    return jsonify({"items": items}), 200

# Get a Specific Public Item
@app.route('/public-items/<int:item_id>', methods=['GET'])
def public_item(item_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM public_items WHERE id = %s AND is_public = TRUE", (item_id,))
    item = cursor.fetchone()
    cursor.close()
    conn.close()

    if not item:
        return jsonify({"message": "Item not found or not public"}), 404
    return jsonify({"item": item}), 200

# Create a Public Item
@app.route('/public-items', methods=['POST'])
@token_required
def create_public_item(current_user):
    data = request.json
    name = data.get('name')
    description = data.get('description')

    if not name or not description:
        return jsonify({"error": "Name and description are required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO public_items (name, description, is_public) VALUES (%s, %s, TRUE)", 
                   (name, description))
    conn.commit()
    cursor.close()
    conn.close()
    return jsonify({"message": "Public item created successfully"}), 201

# **🔹 Update a Public Item**
@app.route('/public-items/<int:item_id>', methods=['PATCH'])
@token_required
def update_public_item(current_user, item_id):
    data = request.json
    name = data.get('name')
    description = data.get('description')

    if not name and not description:
        return jsonify({"error": "At least one field (name or description) is required"}), 400

    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the item exists and is public
    cursor.execute("SELECT * FROM public_items WHERE id = %s AND is_public = TRUE", (item_id,))
    item = cursor.fetchone()
    
    if not item:
        cursor.close()
        conn.close()
        return jsonify({"error": "Item not found or not public"}), 404

    # Update the item
    update_query = "UPDATE public_items SET "
    update_values = []
    if name:
        update_query += "name = %s, "
        update_values.append(name)
    if description:
        update_query += "description = %s, "
        update_values.append(description)

    # Remove trailing comma and add WHERE condition
    update_query = update_query.rstrip(", ") + " WHERE id = %s"
    update_values.append(item_id)

    cursor.execute(update_query, tuple(update_values))
    conn.commit()
    cursor.close()
    conn.close()

    return jsonify({"message": "Public item updated successfully"}), 200

# Delete a Public Item
@app.route('/public-items/<int:item_id>', methods=['DELETE'])
@token_required
def delete_public_item(current_user, item_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM public_items WHERE id = %s AND is_public = TRUE", (item_id,))
    conn.commit()

    if cursor.rowcount == 0:
        return jsonify({"message": "Item not found or not public"}), 404

    cursor.close()
    conn.close()
    return jsonify({"message": "Public item deleted successfully"}), 200

if __name__ == '__main__':
    app.run(debug=True)
