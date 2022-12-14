from flask import Flask, redirect, url_for, render_template, request, flash, session
from werkzeug.security import check_password_hash as checkph
from werkzeug.security import generate_password_hash as genph
from flask_login import LoginManager
from werkzeug.urls import url_parse

from models import User
from forms import SignupForm
import basedatos

app = Flask(__name__)
app.config['SECRET_KEY'] = '7110c8ae51a4b5af97be6534caef90e4bb9bdcb3380af008f90b23a5d1616bf319bc298105da20fe'

login_manager = LoginManager(app)

@app.before_request
def before_request():
    ruta = request.path
    if not 'usuario' in session and ruta != '/entrar' and ruta != '/login' and ruta != '/salir' and ruta != '/registro':
        flash("Inicia sesion para continuar")
        return redirect('/entrar')


@app.after_request
def after_request(response):
    #print("Despues de la peticion")
    return response

@app.route('/dentro')
def dentro():
    return render_template('index.html')


@app.route('/')
@app.route('/entrar', methods=['GET', 'POST'])
def entrar():
    if current_user.is_authenticated:
        return redirect(url_for('dentro'))
    form = LoginForm()
    if form.validate_on_submit():
        user = get_user(form.email.data)
        if user is not None and user.check_password(form.password.data):
            login_user(user, remember=form.remember_me.data)
            next_page = request.args.get('next')
            if not next_page or url_parse(next_page).netloc != '':
                next_page = url_for('index')
            return redirect(next_page)
    return render_template('entrar.html', form=form)


@app.route('/login', methods=['POST'])
def login():
    email = request.form['email']
    clave = request.form['clave']
    try:
        usuario = basedatos.obtener_usuario(email)
    except Exception as e:
        flash(f"Error al obtener usuario: {e}")
    if usuario:
        if(checkph(usuario[1], clave)):
            session['usuario'] = email
            return redirect("/dentro")
        else:
            flash("Acceso denegado")
            return redirect('/entrar')
    return redirect('/entrar')

@app.route('/salir')
def salir():
    session.pop("usuario", None)
    flash("Sesion cerrada")
    return redirect("/entrar")

@app.route('/registro', methods=["GET", "POST"])
def registro():
    form = SignupForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data

        next = request.args.get('next', None)
        if next:
            return redirect(next)
        return redirect(url_for('index'))
    return render_template("signup_form.html", form=form)

    email = request.form['email']
    clave = request.form['clave']
    clavehash = genph(clave)
    try:
        basedatos.alta_usuario(email, clavehash)
        flash("Usuario registrado")
        print(f"Usuario: {email}, registrado")
    except Exception as e:
        flash(f"Error al registrar usuario: {e}")
        print(f"Error: {e}")
    finally:
        return redirect('/entrar')

@app.route('/acercade')
def acercade():
    dic = {'titulo':'Acerca de','encabezado':'Acerca de mí'}
    #return "<h1>Acerca de mi</h1>"
    return render_template('acercade.html', datos = dic)

#Pagina no encontrada
def pagina_no_encontrada(error):
    return render_template('errores/404.html'), 404

@login_manager.user_loader
def load_user(user_id):
    for user in users:
        if user.id == int(user_id):
            return user
    return None

if __name__ == '__main__':
    app.register_error_handler(404, pagina_no_encontrada)
    
    app.run(debug=True)
