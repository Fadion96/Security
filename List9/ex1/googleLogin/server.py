from flask import Flask, session, redirect, url_for
from flask import render_template
from flask import request
from flask import g
from flask import send_from_directory
import sqlite3

app = Flask(__name__, static_folder='static')
app.secret_key = '5gq0GOnInfL9oqEpWU4kU3ce'

DATABASE = 'database.sql'
USER = '8e994f37d01fd7492ad498de2c213583b8acb7faa1279db626caa2df30d9a242'  #fadion
PASSWORD = '8e994f37d01fd7492ad498de2c213583b8acb7faa1279db626caa2df30d9a242'  #fadion


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        setup_database(db)
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def setup_database(database):
    cursor = database.cursor()
    cursor.execute('CREATE TABLE IF NOT EXISTS users(user TEXT, password TEXT)')
    cursor.execute('CREATE TABLE IF NOT EXISTS payments(user TEXT, account INT, name TEXT, address TEXT, amount INT)')
    cursor.execute('INSERT INTO users(user, password) VALUES(?,?)', (USER, PASSWORD))
#    cursor.execute('INSERT INTO payments(user, account, name, address, amount) VALUES(?,?,?,?,?)',
#                   (USER, 666, 'evil', 'hell', 123))
    database.commit()


def validate(user, password):
    cursor = get_db().cursor()
    print("user=" + user)
    cmd = 'SELECT password FROM users WHERE user=\'' + user + '\''
    print(cmd)
    cursor.execute(cmd)
    for row in cursor:
        print("pass=", row[0])
        return password == row[0]
    print("user not found")
    return False


def add_payment(user, account, name, address, amount):
    database = get_db()
    cursor = database.cursor()
    print("add_payment: ", user, account, name, address, amount)
    cursor.execute('INSERT INTO payments(user, account, name, address, amount) VALUES(?,?,?,?,?)',
                   (user, account, name, address, amount))
    database.commit()


def get_payments(user):
    cursor = get_db().cursor()
    cursor.execute('SELECT account, name, address, amount, user FROM payments')  # WHERE user=\'' + user + '\'')
    payments = []
    for row in cursor:
        print(row)
        payments.append({'account': row[0], 'name': row[1], 'address': row[2], 'amount': row[3]})
    print("get_payments: ", payments)
    return payments


def do_the_login():
    if validate(request.form['user'], request.form['password']):
        session['username'] = request.form['user']
        return redirect(url_for('index'))
    return render_template('login.html', txt="Nieprawidlowy login lub haslo!")


def create_account():
    cursor = get_db().cursor()    
    user = request.form['user']
    password = request.form['password']
    print("INSERT INTO users(user, password) VALUES(" + user + "," + password + ")")
    cursor.execute('INSERT INTO users(user, password) VALUES(?,?)', (user, password))
    

@app.route('/<path:path>')
def static_file(path):
    return send_from_directory('static', path)


@app.route('/index')
def index():
    if 'username' in session:
        return render_template('index.html')
    return redirect(url_for('login'))


@app.route('/make_payment', methods=['GET', 'POST'])
def make_payment():
    if request.method == 'POST':
        return redirect(url_for('confirm_payment',
                                account=request.form['account'],
                                name=request.form['name'],
                                address=request.form['address'],
                                amount=request.form['amount']))
    elif 'username' in session:
        return render_template('make_payment.html')
    return redirect(url_for('login'))


@app.route('/confirm_payment', methods=['GET', 'POST'])
def confirm_payment():
    if request.method == 'POST':
        account = request.form['account']
        name = request.form['name']
        address = request.form['address']
        amount = request.form['amount']
        add_payment(session['username'], account, name, address, amount)
        return render_template('confirm_payment.html',
                               account=account, name=name, address=address,
                               amount=amount, confirmed=True)
    elif 'username' in session:
        account = request.args.get('account', type=int)
        name = request.args.get('name')
        address = request.args.get('address')
        amount = request.args.get('amount', type=int)
        return render_template('confirm_payment.html',
                               account=account, name=name, address=address, amount=amount)
    return redirect(url_for('login'))


@app.route('/payments_list')
def payments_list():
    if 'username' in session:
        payments = get_payments(session['username'])
        return render_template('payments_list.html', payments=payments)
    else:
        return render_template('login.html')


@app.route("/")
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        return do_the_login()
    elif 'username' in session:
        return redirect(url_for('index'))
    else:
        return render_template('login.html')


@app.route('/googleLogin', methods=['POST'])
def googleLogin():
        session['username'] = request.form['user']
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return render_template('login.html', scr='https://mail.google.com/mail/u/0/?logout&hl=en')


if __name__ == "__main__":
    app.run()
