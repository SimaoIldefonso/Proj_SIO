from flask import Blueprint,render_template, session, redirect, url_for,make_response
from produtos import get_produtos


rotas = Blueprint('rotas', __name__, static_folder='static', static_url_path='/rotas/static', template_folder='templates')


@rotas.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html', produtos=get_produtos())
    


@rotas.route('/shop')
def shop():
    produtos=get_produtos()
    return render_template('shop.html', produtos=produtos)

@rotas.route('/about')
def about():
    return render_template('about.html')


@rotas.route("/profile")
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('profile.html')

@rotas.route('/login')
def login():
    if 'user_id' in session:
        return redirect(url_for('rotas.profile'))
    
    resp = make_response(render_template('login.html'))

    #anti cache
    resp.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    return resp

@rotas.route('/register')
def register():
    return render_template('register.html')

@rotas.route('/logout')
def logout():
    #Clear sensitive data from session - server side
    session.pop('user_id', None)
    session.pop('username', None)
    session.pop('password', None)
    #TODO: ver ser é necessário
    #Clear sensitive data from local storage - client side
    #localStorage.removeItem('authToken')
    #localStorage.removeItem('userData')

    return redirect(url_for('rotas.index'))

@rotas.route('/recovery')
def recovery():
    return render_template('recoverAcc.html')

@rotas.route('/resetPass')
def recoveryPass():
    return render_template('resetPass.html')

@rotas.route('/recoveryCode')
def recoveryCode():
    return render_template('recoverCode.html')
