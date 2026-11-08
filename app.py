import os
import secrets
import sqlite3
from functools import wraps
from urllib.parse import quote

from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

try:
    import stripe
except ImportError:  # Stripe es opcional hasta que pongas tus llaves
    stripe = None

BASE = os.path.dirname(os.path.abspath(__file__))


def load_env():
    """Carga variables desde .env sin dependencias extra."""
    path = os.path.join(BASE, ".env")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())


load_env()

DB_PATH = os.path.join(BASE, "tienda.db")
STORE_NAME = os.environ.get("STORE_NAME", "VOLT Nutrition")
WHATSAPP = "".join(c for c in os.environ.get("WHATSAPP_NUMBER", "5210000000000") if c.isdigit())
STRIPE_SECRET = os.environ.get("STRIPE_SECRET_KEY", "")
CURRENCY = os.environ.get("CURRENCY", "mxn")
FREE_SHIPPING_FROM = 99900   # centavos
SHIPPING_COST = 9900         # centavos

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "cambia-esto-en-produccion")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

if stripe and STRIPE_SECRET:
    stripe.api_key = STRIPE_SECRET

# --------------------------------------------------------------------------
# Base de datos (SQLite)
# --------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    tagline TEXT NOT NULL,
    description TEXT NOT NULL,
    price_cents INTEGER NOT NULL,
    stock INTEGER NOT NULL DEFAULT 100,
    color TEXT NOT NULL DEFAULT '#111111',
    featured INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    total_cents INTEGER NOT NULL,
    shipping_cents INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'pendiente',
    stripe_session_id TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL REFERENCES orders(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    name TEXT NOT NULL,
    price_cents INTEGER NOT NULL,
    qty INTEGER NOT NULL
);
"""

SEED = [
    ("whey-isolate", "Whey Isolate", "Proteína", "Proteína aislada de rápida absorción",
     "Proteína de suero aislada, 25 g por porción, baja en azúcar y grasa. Mezcla fácil y sabor suave. Bote de 2 lb (907 g).",
     89900, "#1a1a1a", 1),
    ("creatina-mono", "Creatina Monohidratada", "Rendimiento", "Creatina pura, sin rellenos",
     "Creatina monohidratada micronizada, 5 g por porción. Sin sabor, se disuelve fácilmente. Bote de 300 g (60 porciones).",
     44900, "#2b2b2b", 1),
    ("pre-ignite", "Pre-Entreno Ignite", "Pre-entreno", "Energía y enfoque para tu sesión",
     "Fórmula con cafeína, beta-alanina y citrulina para entrenar con intensidad. 30 porciones. Contiene cafeína: no apto para menores de edad.",
     64900, "#0f2a14", 1),
    ("bcaa-200", "BCAA 2:1:1", "Recuperación", "Aminoácidos para acompañar tu entrenamiento",
     "Relación 2:1:1 de leucina, isoleucina y valina. Sabor limón, 30 porciones.",
     52900, "#16222e", 0),
    ("omega-3", "Omega-3 Ultra", "Bienestar", "Aceite de pescado concentrado",
     "Cápsulas blandas con EPA y DHA. Frasco de 90 cápsulas.",
     37900, "#2e2410", 0),
    ("multi-daily", "Multivitamínico Daily", "Bienestar", "Tu base diaria, en una cápsula",
     "Vitaminas y minerales esenciales para complementar la dieta. Frasco de 60 cápsulas.",
     32900, "#241a2e", 0),
    ("colageno", "Colágeno Hidrolizado", "Bienestar", "Colágeno en polvo con vitamina C",
     "Colágeno hidrolizado sabor neutro con vitamina C. Bote de 300 g.",
     47900, "#2e1a1a", 0),
    ("electrolitos", "Electrolitos Zero", "Hidratación", "Hidratación sin azúcar",
     "Mezcla de sodio, potasio y magnesio sin azúcar. 40 porciones, sabor frutos rojos.",
     36900, "#10282e", 0),
]


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(SCHEMA)
    if db.execute("SELECT COUNT(*) FROM products").fetchone()[0] == 0:
        db.executemany(
            "INSERT INTO products (slug,name,category,tagline,description,price_cents,color,featured) "
            "VALUES (?,?,?,?,?,?,?,?)", SEED)
    db.commit()
    db.close()


init_db()

# --------------------------------------------------------------------------
# Utilidades: CSRF, sesión, carrito
# --------------------------------------------------------------------------


def csrf_token():
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_hex(16)
    return session["_csrf"]


@app.before_request
def protect_post():
    if request.method == "POST":
        token = request.form.get("_csrf", "")
        if not token or token != session.get("_csrf"):
            abort(400, "Token de seguridad inválido. Recarga la página e inténtalo de nuevo.")


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT id,name,email FROM users WHERE id=?", (uid,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*a, **kw):
        if not session.get("user_id"):
            flash("Inicia sesión para continuar.", "info")
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def cart_items():
    cart = session.get("cart", {})
    if not cart:
        return [], 0
    db = get_db()
    items, subtotal = [], 0
    for pid, qty in cart.items():
        p = db.execute("SELECT * FROM products WHERE id=?", (int(pid),)).fetchone()
        if p:
            line = p["price_cents"] * qty
            subtotal += line
            items.append({"p": p, "qty": qty, "line": line})
    return items, subtotal


def shipping_for(subtotal):
    return 0 if subtotal == 0 or subtotal >= FREE_SHIPPING_FROM else SHIPPING_COST


def money(cents):
    return f"${cents / 100:,.2f}"


app.jinja_env.filters["money"] = money


@app.context_processor
def inject_globals():
    count = sum(session.get("cart", {}).values())
    wa_msg = quote(f"Hola {STORE_NAME}, me gustaría recibir asesoría sobre sus suplementos.")
    return dict(store_name=STORE_NAME, csrf_token=csrf_token, user=current_user(),
                cart_count=count, wa_link=f"https://wa.me/{WHATSAPP}?text={wa_msg}",
                free_from=FREE_SHIPPING_FROM)


# --------------------------------------------------------------------------
# Tienda
# --------------------------------------------------------------------------
@app.route("/")
def index():
    db = get_db()
    featured = db.execute("SELECT * FROM products WHERE featured=1").fetchall()
    return render_template("index.html", featured=featured)


@app.route("/tienda")
def tienda():
    db = get_db()
    cat = request.args.get("cat", "")
    cats = [r[0] for r in db.execute("SELECT DISTINCT category FROM products ORDER BY category")]
    if cat in cats:
        products = db.execute("SELECT * FROM products WHERE category=? ORDER BY name", (cat,)).fetchall()
    else:
        cat, products = "", db.execute("SELECT * FROM products ORDER BY name").fetchall()
    return render_template("tienda.html", products=products, cats=cats, active=cat)


@app.route("/producto/<slug>")
def producto(slug):
    db = get_db()
    p = db.execute("SELECT * FROM products WHERE slug=?", (slug,)).fetchone()
    if not p:
        abort(404)
    wa_msg = quote(f"Hola, tengo una duda sobre {p['name']}.")
    return render_template("producto.html", p=p, wa_product=f"https://wa.me/{WHATSAPP}?text={wa_msg}")


# --------------------------------------------------------------------------
# Carrito
# --------------------------------------------------------------------------
@app.route("/carrito")
def carrito():
    items, subtotal = cart_items()
    ship = shipping_for(subtotal)
    return render_template("carrito.html", items=items, subtotal=subtotal,
                           ship=ship, total=subtotal + ship,
                           stripe_ready=bool(stripe and STRIPE_SECRET))


@app.post("/carrito/agregar")
def carrito_agregar():
    pid = request.form.get("product_id", type=int)
    qty = max(1, min(request.form.get("qty", 1, type=int) or 1, 10))
    p = get_db().execute("SELECT id,stock FROM products WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    cart = session.get("cart", {})
    cart[str(pid)] = min(cart.get(str(pid), 0) + qty, min(p["stock"], 10))
    session["cart"] = cart
    flash("Producto agregado al carrito.", "ok")
    return redirect(request.form.get("next") or url_for("carrito"))


@app.post("/carrito/actualizar")
def carrito_actualizar():
    pid = request.form.get("product_id", "")
    qty = request.form.get("qty", 0, type=int)
    cart = session.get("cart", {})
    if pid in cart:
        if qty <= 0:
            cart.pop(pid)
        else:
            cart[pid] = min(qty, 10)
    session["cart"] = cart
    return redirect(url_for("carrito"))


# --------------------------------------------------------------------------
# Cuentas
# --------------------------------------------------------------------------
def safe_next(target):
    return target if target and target.startswith("/") and not target.startswith("//") else url_for("cuenta")


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        if not name or "@" not in email or len(pw) < 8:
            flash("Revisa tus datos: nombre, correo válido y contraseña de al menos 8 caracteres.", "error")
        else:
            db = get_db()
            try:
                cur = db.execute("INSERT INTO users (name,email,password_hash) VALUES (?,?,?)",
                                 (name, email, generate_password_hash(pw)))
                db.commit()
                cart = session.get("cart", {})
                session.clear()
                session["user_id"] = cur.lastrowid
                session["cart"] = cart
                flash(f"¡Bienvenido a {STORE_NAME}, {name}!", "ok")
                return redirect(safe_next(request.args.get("next")))
            except sqlite3.IntegrityError:
                flash("Ya existe una cuenta con ese correo.", "error")
    return render_template("auth.html", mode="registro")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw = request.form.get("password", "")
        u = get_db().execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if u and check_password_hash(u["password_hash"], pw):
            cart = session.get("cart", {})
            session.clear()
            session["user_id"] = u["id"]
            session["cart"] = cart
            return redirect(safe_next(request.args.get("next")))
        flash("Correo o contraseña incorrectos.", "error")
    return render_template("auth.html", mode="login")


@app.post("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada.", "info")
    return redirect(url_for("index"))


@app.route("/cuenta")
@login_required
def cuenta():
    db = get_db()
    orders = db.execute("SELECT * FROM orders WHERE user_id=? ORDER BY id DESC", (session["user_id"],)).fetchall()
    detail = {o["id"]: db.execute("SELECT * FROM order_items WHERE order_id=?", (o["id"],)).fetchall()
              for o in orders}
    return render_template("cuenta.html", orders=orders, detail=detail)


# --------------------------------------------------------------------------
# Checkout con tarjeta (Stripe)
# --------------------------------------------------------------------------
@app.post("/checkout")
@login_required
def checkout():
    items, subtotal = cart_items()
    if not items:
        flash("Tu carrito está vacío.", "info")
        return redirect(url_for("tienda"))
    if not (stripe and STRIPE_SECRET):
        flash("El pago con tarjeta aún no está activado: falta configurar STRIPE_SECRET_KEY.", "error")
        return redirect(url_for("carrito"))

    ship = shipping_for(subtotal)
    db = get_db()
    cur = db.execute("INSERT INTO orders (user_id,total_cents,shipping_cents) VALUES (?,?,?)",
                     (session["user_id"], subtotal + ship, ship))
    order_id = cur.lastrowid
    for it in items:
        db.execute("INSERT INTO order_items (order_id,product_id,name,price_cents,qty) VALUES (?,?,?,?,?)",
                   (order_id, it["p"]["id"], it["p"]["name"], it["p"]["price_cents"], it["qty"]))

    line_items = [{
        "quantity": it["qty"],
        "price_data": {"currency": CURRENCY, "unit_amount": it["p"]["price_cents"],
                       "product_data": {"name": it["p"]["name"]}},
    } for it in items]
    if ship:
        line_items.append({"quantity": 1, "price_data": {
            "currency": CURRENCY, "unit_amount": ship, "product_data": {"name": "Envío"}}})

    try:
        cs = stripe.checkout.Session.create(
            mode="payment",
            payment_method_types=["card"],
            line_items=line_items,
            customer_email=current_user()["email"],
            client_reference_id=str(order_id),
            success_url=url_for("pago_exito", _external=True) + "?session_id={CHECKOUT_SESSION_ID}",
            cancel_url=url_for("carrito", _external=True),
            shipping_address_collection={"allowed_countries": ["MX"]},
        )
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        app.logger.exception("Stripe error: %s", exc)
        flash("No pudimos iniciar el pago. Inténtalo de nuevo o escríbenos por WhatsApp.", "error")
        return redirect(url_for("carrito"))

    db.execute("UPDATE orders SET stripe_session_id=? WHERE id=?", (cs.id, order_id))
    db.commit()
    return redirect(cs.url, code=303)


@app.route("/pago/exito")
@login_required
def pago_exito():
    sid = request.args.get("session_id", "")
    db = get_db()
    order = db.execute("SELECT * FROM orders WHERE stripe_session_id=? AND user_id=?",
                       (sid, session["user_id"])).fetchone()
    if not order:
        abort(404)
    paid = False
    if stripe and STRIPE_SECRET:
        try:
            cs = stripe.checkout.Session.retrieve(sid)
            paid = cs.payment_status == "paid"
        except Exception:  # noqa: BLE001
            paid = False
    if paid and order["status"] != "pagado":
        db.execute("UPDATE orders SET status='pagado' WHERE id=?", (order["id"],))
        for it in db.execute("SELECT * FROM order_items WHERE order_id=?", (order["id"],)):
            db.execute("UPDATE products SET stock = MAX(stock - ?, 0) WHERE id=?", (it["qty"], it["product_id"]))
        db.commit()
        session.pop("cart", None)
    wa_msg = quote(f"Hola, acabo de hacer el pedido #{order['id']}.")
    return render_template("pago_exito.html", order=order, paid=paid,
                           wa_order=f"https://wa.me/{WHATSAPP}?text={wa_msg}")


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", code=404, msg="Esta página no existe."), 404


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", code=400, msg=getattr(e, "description", "Solicitud inválida.")), 400


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", port=int(os.environ.get("PORT", 5000)))
