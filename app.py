from flask import Flask,request,jsonify, redirect, url_for, session, flash,render_template,Blueprint,render_template_string
from rotas import rotas
from functools import wraps
from produtos import get_produtos
from datetime import timedelta
import ssl, sqlite3, re, hashlib, os, random, string,json,qrcode,pyotp

app = Flask(__name__)
app.register_blueprint(rotas)
app.secret_key= os.urandom(24)
app.config.update(
        SESSION_COOKIE_NAME = '__Host-session',
        SESSION_COOKIE_DOMAIN = None,
        SESSION_COOKIE_SECURE = True,       
        SESSION_COOKIE_SAMESITE = 'Lax',
        PERMANENT_SESSION_LIFETIME = timedelta(minutes=2)
)

produtos = get_produtos()
carrrinho=[]

def generate_recovery_code():
    return ''.join(random.choices(string.digits, k=6))

with open('Top10000passwords.txt', 'r') as f:
    common_passwords = f.read().splitlines()

def verificar_senha(senha):
    reasons = []
    if not re.search(r'[A-Z]', senha):
        reasons.append("The password must contain at least one uppercase letter.")
    if not re.search(r'[a-z]', senha):
        reasons.append("The password must contain at least one lowercase letter.")
    if not re.search(r'\d', senha):
        reasons.append("The password must contain at least one number.")
    if not re.search(r'\W', senha):
        reasons.append("The password must contain at least one special character.")
    if len(senha) < 12:
        reasons.append("The password must contain at least 12 characters.") 
    elif len(senha) > 128:
        reasons.append("The password must be less than 128 characters long.")
        
    if len(reasons) == 0:
        return True, None
    else:
        return False, reasons
def generate_password_hash(password):
    salt = os.urandom(32)

    key = hashlib.pbkdf2_hmac(
        'sha256',  
        password.encode('utf-8'),  
        salt,  
        100000  
    )
    return salt + key

def verify_password(hashed_password, password_to_check):
    salt = hashed_password[:32]  # O salt tem 32 bytes
    stored_password = hashed_password[32:]

    password_to_check_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password_to_check.encode('utf-8'),
        salt,
        100000
    )
    return stored_password == password_to_check_hash

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def product_exists(product_name, produtos):
    nomes = [produto['Nome'] for produto in produtos]

    if product_name in nomes:
        return True
    else:
        return False

@app.route('/add_to_cart/<product>', methods=['POST'])
def add_to_cart(product, carrinho=carrrinho):
    
    product_info = product.split(',')
    product_name = product_info[0]
    product_price = float(product_info[1])
    products = get_produtos()

    if (product_exists(product_name, products)):
        for item in carrinho:
            if item['Nome'] == product_name:
                item['Quantidade'] += 1
                break
        else:
            carrinho.append({'Nome': product_name, 'Preco': product_price, 'Quantidade': 1})

        return jsonify({'message': 'Product added to cart'}), 200
    else:
        return jsonify({'message': 'Product not found'}), 404
@app.route('/remove_from_cart/<product>', methods=['POST'])
def remove_from_cart(product, carrinho=carrrinho):
    # Obter o nome e o preço do produto
    product_info = product.split(',')
    product_name = product_info[0]

    # Verificar se o produto existe
    if (product_exists(product_name, carrinho)):
        # Remover o produto do carrinho
        for item in carrinho:
            if item['Nome'] == product_name:
                item['Quantidade'] -= 1
                if item['Quantidade'] == 0:
                    carrinho.remove(item)
                break
        return jsonify({'message': 'Product removed from cart'}), 200
    else:
        return jsonify({'message': 'Product not found'}), 404
@app.route('/delete_from_cart/<product>', methods=['POST'])
def delete_from_cart(product, carrinho=carrrinho):
    # Obter o nome e o preço do produto
    product_info = product.split(',')
    product_name = product_info[0]

    # Verificar se o produto existe
    if (product_exists(product_name, carrinho)):
        # Remover o produto do carrinho
        for item in carrinho:
            if item['Nome'] == product_name:
                carrinho.remove(item)
                break
        return jsonify({'message': 'Product removed from cart'}), 200
    else:
        return jsonify({'message': 'Product not found'}), 404

@app.route('/quantidades/<product>')
def quantidades(carrinho=carrrinho):

    return jsonify(quantidades)

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    global carrinho  
    carrinho = []
    return render_template('thankyou.html')
    
@app.route('/cart')
def cart(): 
    global carrrinho
    carrinho=carrrinho
    return render_template('cart.html', carrinho=carrinho, produtos=produtos)

@app.route('/login', methods=['GET', 'POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    otp_code = request.form['otp_code']  

    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()

    cursor.execute("SELECT id, password, otp_secret FROM users WHERE username = ?", (username,))
    result = cursor.fetchone()

    if result is None:
        return render_template('login.html', alert_message="Invalid username or password")

    user_id, stored_password, otp_secret = result

    totp = pyotp.TOTP(otp_secret)
    if not totp.verify(otp_code):
        return render_template('login.html', alert_message="Invalid OTP code")

    if verify_password(stored_password, password):
        session['user_id'] = user_id
        session['username'] = username
        next_url = request.args.get('next')
        if next_url != None:
            return redirect(next_url)
        
        return redirect(url_for('rotas.index'))
    else:
        return render_template('login.html', alert_message="Invalid username or password")


@app.route('/register', methods=['POST'])
def register():
    username = request.form['username']
    password = request.form['password']
    confirm_password = request.form['confirm_password']

    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
    data = cursor.fetchone()

    if data is not None:
        flash('The username already exists', 'alert')
        return redirect(url_for('register'))

    password_valid, reasons = verificar_senha(password)

    if password != confirm_password:
        flash('Passwords don\'t match', 'alert')
        return redirect(url_for('register'))
    elif not password_valid:
        for reason in reasons:
            flash(reason, 'alert')
        return redirect(url_for('register'))
    elif password in common_passwords:
        flash('The password is very common', 'alert')
        return redirect(url_for('register'))
    else:
        hashed_password = generate_password_hash(password)
        recovery_code = generate_recovery_code()
        hashed_recovery_code = generate_password_hash(recovery_code)

        otp_secret = pyotp.random_base32()
        
        uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name='DETIShop')

        cursor.execute("INSERT INTO users (username, password, recovery_code, otp_secret) VALUES (?, ?, ?, ?)", (username, hashed_password, hashed_recovery_code, otp_secret))
        conn.commit()

        session['otp_uri'] = uri

        img = qrcode.make(uri)
        img.save('./static/images/qrcode.png')

        flash('Your recovery code is: ' + recovery_code, 'info')
        return redirect(url_for('rotas.recoveryCode'))

    
@app.route('/recoverCode', methods=['POST'])
def recoveryCode():   
    return render_template('login.html')

@app.route('/change_password', methods=['POST'])
@login_required
def change_password():
    old_password = request.form['old_password']
    new_password = request.form['password']
    
    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()

    cursor.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],))
    result = cursor.fetchone()

    if result is None:
        flash('An error has occurred', 'alert')
        return redirect(url_for('rotas.profile'))

    stored_password = result[0]
    if verify_password(stored_password, old_password):
        password_valid, reasons = verificar_senha(new_password)
        if not password_valid:
            for reason in reasons:
                flash(reason, 'alert')
            return redirect(url_for('rotas.profile'))
        elif new_password in common_passwords:
            flash('The password is very common', 'alert')
            return redirect(url_for('rotas.profile'))
        else:
            # Update the password in the database
            cursor.execute("UPDATE users SET password = ? WHERE id = ?", (generate_password_hash(new_password), session['user_id']))
            conn.commit()
            flash('Password Successfully Changed', 'success')
            return redirect(url_for('rotas.profile'))
    else:
        flash('Incorrect current password', 'alert')
        return redirect(url_for('rotas.profile'))
@app.route('/recovery', methods=['POST'])
def recovery():
    username = request.form['username']
    recovery_code = request.form['recovery_code']

    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute("SELECT recovery_code FROM users WHERE username = ?", (username,))
    stored_recovery_code = cursor.fetchone()

    if stored_recovery_code and verify_password(stored_recovery_code[0], recovery_code):
        flash('Recovery code successfully verified. Please reset your password.', 'info')
        return redirect(url_for('reset_password', username=username))
    else:
        flash('Invalid recovery code.', 'alert')
        return redirect(url_for('rotas.recovery'))

@app.route('/reset_password/<username>', methods=['GET', 'POST'])
def reset_password(username):
    if request.method == 'POST':
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords don\'t match', 'alert')
            return redirect(url_for('reset_password', username=username))

        password_valid, reasons = verificar_senha(password)

        if not password_valid:
            for reason in reasons:
                flash(reason, 'alert')
            return redirect(url_for('reset_password', username=username))
        else:
            hashed_password = generate_password_hash(password)
            conn = sqlite3.connect('user.db')
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_password, username))
            conn.commit()
            flash('Password reset successfully.', 'info')
            return redirect(url_for('login'))
    else:
        return render_template('resetPass.html', username=username)



@app.route('/DeleteAccount')
@login_required
def DeleteAccount():

    conn = sqlite3.connect('user.db')
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (session['user_id'],))
    conn.commit()

    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('password', None)

    return redirect(url_for('rotas.index'))

if __name__ == '__main__':

    # Create SSL context and set SSL/TLS options
    #ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    #CWE-319
    #ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
    #ssl_context.set_ciphers('EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH')
    #ssl_context.load_cert_chain(certfile='./cert.pem', keyfile='./private-key.pem')

    app.run(debug=True, host="0.0.0.0", port="443"), #ssl_context=ssl_context)