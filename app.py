from flask import Flask, request, jsonify
from flask import Flask, render_template, redirect, url_for, request, session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_marshmallow import Marshmallow
from flask_restful import Api, Resource
from flask_cors import CORS
import flask_praetorian
from werkzeug.security import generate_password_hash
from datetime import datetime
import os 
from flask import redirect, url_for
from flask import session

app = Flask(__name__)
app.secret_key =6616
# App configurations
app.config[ 'SQLALCHEMY_DATABASE_URI' ] = 'sqlite:///student.db'
app.config['SECRET_KEY'] = '6616'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_ACCESS_LIFESPAN'] = {'hours': 24}
app.config['JWT_REFRESH_LIFESPAN'] = {'days': 30}

# Initialize extensions
db = SQLAlchemy(app)
ma = Marshmallow(app)
migrate = Migrate(app, db)
guard = flask_praetorian.Praetorian()
CORS(app)



#  First page to display sign_in.html
@app.route("/")
def home():
   return render_template("sign_in.html")




@app.route("/debug")
def debug():
    return f"Templates folder: {os.path.join(os.getcwd(), 'templates')}"





@app.route("/base")
@flask_praetorian.auth_required
def base():
    user= flask_praetorian.current_user()
    user_info = {"id":user.id, "username":user.username, "role":user.roles}
    return render_template("base.html",user=user_info)




# Models
class Student(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(10))
    email = db.Column(db.String(100))
    dob = db.Column(db.String(10))
    town = db.Column(db.String(100))
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id', name='fk_student_user'))


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, unique=True)
    hashed_password = db.Column(db.Text)
    roles = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True, server_default="true")
    created_date = db.Column(db.Text)
    connect_student = db.relationship('Student', backref='student', lazy=True,
                                       foreign_keys='Student.created_by_id')

    @property
    def password(self):
        #this ensures Flask-Praetorian can access the hashed password
        return self.hashed_password

    @password.setter
    def password(self,plaintext_password):
        #hashes the plaintext password when set
        self.hashed_password = guard.hash_password(plaintext_password) 
    
    @property
    def identity(self):
        # Return's the User's ID as their identity
        return self.id

    @property
    def rolenames(self):
        #Splits roles string into a list
        try:
            return self.roles.split(",")
        except Exception:
            return []

    @classmethod
    def lookup(cls, username):
        #Find a user by their username
        return cls.query.filter_by(username=username).one_or_none()

    @classmethod
    def identify(cls, id):
        #Find a user by their ID
        return cls.query.get(id)

    def is_valid(self):
        #check if the user is active
        return self.is_active


# Initialize flask-praetorian
guard.init_app(app, User)


# Marshmallow schema
class StudentSchema(ma.Schema):
    class Meta:
        fields = ("id", "name", "phone", "email", "dob", "town", "created_by_id")


student_schema = StudentSchema(many=True)


#  Register Routes
@app.route("/register", methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Retrieve form data
        username = request.form.get("username")  # Corresponds to `name="email"` in the form
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        # Check if username or password is missing
        if not username or not password:
            jsonify({"message":"Email and password are required!"})
            return redirect('/register')

        # Validate password and confirmation password
        if password != confirm_password:
            jsonify({"message":"Passwords do not match!"})
            return redirect('/register')

        # Hash the password (use a library like bcrypt)
        hashed_password = guard.hash_password(password)  # Replace with your hash logic

        # Assign default role (update logic if dynamic roles are required)
        roles = "user"

        try:
            # Create the user object
            usr = User(
                username=username,
                hashed_password=hashed_password,
                roles=roles,
                created_date=datetime.now().strftime('%Y-%m-%d %H:%M')
            )

            # Add user to the database
            db.session.add(usr)
            db.session.commit()

            # Flash success message
            jsonify({"message":"User Registration Seccessful"})
            return redirect('/login')  # Redirect to the login page

        except Exception as e:
            # Catch database or application errors
            jsonify({"message":"An error occurred","error":str(e)})
            db.session.rollback()  # Rollback in case of error
            return redirect('/register')

    # Render the registration form for GET requests
    return render_template("register.html")

       

#def register():
#    username = request.json["username"]
#    password = request.json["password"]
#    hashed_password = guard.hash_password(password)
#    roles = request.json["roles"]

#    usr = User(username=username, hashed_password=hashed_password, roles=roles,
#               created_date=datetime.now().strftime('%Y-%m-%d %H:%M'))
#    db.session.add(usr)
#    db.session.commit()
#    return jsonify({"message": "User registered successfully"}), 201
#    return flash("User registered successfully")


@app.route('/get_signin_client', methods=['POST'])
def get_signin_client():
    req = request.get_json(force=True)
    username = req.get("username")
    password = req.get( "password")
    roles = req.get("roles")
    try:
        user = guard.authenticate(username, password)
        # Set the user in the session (optional)
        session['user_id'] = user.id
        session['username']=user.username
        session['roles'] = user.roles
        return redirect(url_for('base')),200
        #ret = {"id_token": guard.encode_jwt_token(user)}
    except Exception as e: 
        return jsonify({"message":"Authentication failed","error":str(e)}),401   
        #return ret, 200


@app.route("/get_info", methods=['GET'])
@flask_praetorian.auth_required
def get_info():
    user = flask_praetorian.current_user()
    return jsonify({"id": user.id, "username": user.username, "roles": user.roles}), 200


@app.route("/add-students", methods=["POST"])
@flask_praetorian.auth_required
def add_students():
    students_data = request.json
    if not isinstance(students_data, list):
        return jsonify({"message": "Invalid input format, expected a list of students"}), 400

    try:
        new_students = [
            Student(
                name=student["name"],
                phone=student["phone"],
                email=student["email"],
                dob=student.get("dob"),
                town=student.get("town"),
                created_by_id=flask_praetorian.current_user().id
            )
            for student in students_data
        ]
        db.session.bulk_save_objects(new_students)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"message": "Error adding students", "error": str(e)}), 400

    return jsonify({"message": "Students added successfully"}), 200


@app.route("/delete_student", methods=["DELETE"])
@flask_praetorian.auth_required
def delete_student():
    id = request.json.get("id")
    std = Student.query.filter_by(id=id).first()
    if std:
        db.session.delete(std)
        db.session.commit()
        return jsonify({"message": "Student deleted successfully"}), 200
    else:
        return jsonify({"message": "Student not found"}), 404



# Login route
def get_counts():
    return {
        'student_count': 200,
        'staff_count': 50,
        'department_count': 10
    }

# Login Route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Fetch user from the database
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.hashed_password, password):
            # Store user info in session
            session['user_id'] = user.id
            session['username'] = user.username
            session['roles'] = user.roles
            
            # Redirect to dashboard
            return redirect(url_for('base.html'))
        else:
            flash('Invalid username or password', 'error')
            return redirect(url_for('sign_in.html'))
    
    return render_template('sign_in.html')  # Render your login template

# Dashboard Route
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        #Redirect to login if user is not authenticated
        return redirect(url_for('login'))
    
    # Retrieve dynamic data
    counts = get_counts()
    return render_template(
        'base.html',
        username=session['username'],
        id=session['user_id'],
        roles=session['roles'],
        student_count=counts['student_count'],
        staff_count=counts['staff_count'],
        department_count=counts['department_count']
    )

# Logout Route
@app.route('/logout')
def logout():
    session.clear()  # Clear session
    return redirect(url_for('login'))





if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
