from flask import Flask, render_template, jsonify, request, redirect, url_for, session, make_response, send_from_directory
from flask_session import Session
from sqlalchemy import create_engine, MetaData, Table, select, text
from flask import request, jsonify, redirect, url_for, flash
from redis import Redis
from werkzeug.security import generate_password_hash, check_password_hash
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from dotenv import load_dotenv
import os
from datetime import timedelta, datetime
from email.mime.text import MIMEText
import smtplib
import secrets
import stripe
from flask_login import current_user, LoginManager, login_user, UserMixin, logout_user, login_required
import json
from flask_seasurf import SeaSurf
import re
import logging
from functools import wraps
import pickle
import hashlib
import uuid
from flask_socketio import SocketIO, emit, join_room, leave_room

# Redis-konfiguration för både sessioner och cache
redis_client = Redis(
    host='localhost',  # ändra till din Redis-host om behövs
    port=6379,         # standard Redis-port
    db=0,              # använd db 0 för både sessioner och cache
    decode_responses=False  # viktigt för att hantera binärdata
)

app = Flask(__name__)

# Viktiga säkerhetsinställningar
app.secret_key = os.getenv("SECRET_KEY", "en_mycket_säker_hemlig_nyckel_som_bör_ändras")

# Konfigurera Flask-Session med Redis
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = redis_client
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_PERMANENT_LIFETIME'] = timedelta(days=7)
app.config['SESSION_USE_SIGNER'] = True            # Signera cookie-data
app.config['SESSION_KEY_PREFIX'] = 'flask-session:' # Prefix för Redis-nycklar
app.config['SESSION_COOKIE_SECURE'] = False        # Ändra till True i produktion med HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True       # Förhindra åtkomst via JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'      # Cookie-säkerhet för CSRF-skydd
Session(app)  # Initialisera sessioner med Redis

# Konfigurera Flask-SocketIO
socketio = SocketIO(app, cors_allowed_origins="*", manage_session=False)

# Decorator för att cacha databasfrågor med Redis
def cached_query(cache_key=None, ttl_seconds=300):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Generera cache-nyckel baserad på funktionsnamn och argument om inte explicit angiven
            if cache_key is None:
                # Skapa en nyckel baserad på funktionsnamn och parametrar
                key_parts = [func.__name__]
                # Lägg till positionsargument
                key_parts.extend([str(arg) for arg in args])
                # Lägg till nyckelord-argument
                key_parts.extend([f"{k}:{v}" for k, v in sorted(kwargs.items())])
                # Skapa en hash av delarna
                redis_key = f"cache:{hashlib.md5('|'.join(key_parts).encode()).hexdigest()}"
            else:
                redis_key = f"cache:{cache_key}"
                
            # Kontrollera om data finns i cachen
            cached_data = redis_client.get(redis_key)
            if cached_data:
                try:
                    return pickle.loads(cached_data)
                except (pickle.PickleError, TypeError):
                    # Om något går fel vid deserialiseringen, fortsätt med att köra funktionen
                    app.logger.warning(f"Kunde inte avseriliasera cache-data för {redis_key}")
                    pass
                    
            # Om inte i cache, kör funktionen
            result = func(*args, **kwargs)
            
            # Använd default TTL om inget anges
            ttl = ttl_seconds or 300
            
            # Lagra resultatet i Redis med TTL
            try:
                redis_client.setex(
                    redis_key,
                    ttl,
                    pickle.dumps(result)
                )
            except (pickle.PickleError, TypeError):
                app.logger.warning(f"Kunde inte serialisera resultat för {redis_key}")
                pass
            
            return result
        return wrapper
    return decorator

# Funktion för att invalidera specifik cache
def invalidate_cache(cache_key):
    redis_key = f"cache:{cache_key}"
    redis_client.delete(redis_key)

# Funktion för att rensa all cache
def clear_all_cache():
    for key in redis_client.keys("cache:*"):
        redis_client.delete(key)

# Funktioner för hantering av misslyckade inloggningsförsök
def increment_failed_login(email):
    """Ökar antalet misslyckade inloggningsförsök för en e-postadress"""
    key = f"login_attempts:{email.lower()}"
    attempts = redis_client.get(key)
    
    if attempts:
        count = int(attempts) + 1
        # Sätt 30 minuters time-to-live för att återställa efter viss tid
        redis_client.setex(key, 1800, str(count))
        return count
    else:
        # Första misslyckade försöket
        redis_client.setex(key, 1800, "1")
        return 1

def reset_failed_login(email):
    """Återställer räknaren för misslyckade inloggningsförsök"""
    key = f"login_attempts:{email.lower()}"
    redis_client.delete(key)

def is_account_locked(email):
    """Kontrollerar om kontot är låst på grund av för många misslyckade försök"""
    key = f"login_attempts:{email.lower()}"
    attempts = redis_client.get(key)
    
    # Om fler än 5 misslyckade försök på 30 minuter, lås kontot
    if attempts and int(attempts) >= 5:
        return True
    return False

# Läs in miljövariabler
load_dotenv()

# Sätt loggnivå om det behövs:
app.logger.setLevel(logging.DEBUG)

csrf = SeaSurf()
csrf.init_app(app)

# Konfigurera Stripe
stripe.api_key = os.getenv("STRIPE_SECRET_KEY")
stripe.api_version = "2023-10-16"  # Använd en nyare API-version som stöder Klarna
if not stripe.api_key:
    app.logger.error("STRIPE_SECRET_KEY saknas i miljövariabler. Stripe-betalningar kommer inte att fungera.")
stripe_webhook_secret = os.getenv("STRIPE_WEBHOOK_SECRET")

# Lägg till säkerhetsheaders till alla HTTP-svar
@app.after_request
def add_security_headers(response):
    """Lägger till rekommenderade säkerhetsheaders till alla svar"""
    # Content Security Policy - anpassa utifrån dina behov
    csp = (
        "default-src 'self'; "
        "script-src 'self' https://js.stripe.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com 'unsafe-inline'; "
        "img-src 'self' data: https:; "
        "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "connect-src 'self' https://api.stripe.com; "
        "frame-src 'self' https://js.stripe.com https://hooks.stripe.com; "
        "object-src 'none';"
    )
    
    # Kommentera bort för att helt inaktivera CSP under utveckling
    # response.headers['Content-Security-Policy'] = csp
    
    # Förhindra att webbläsaren tolkar filen på ett annat sätt än vad som är deklarerat
    response.headers['X-Content-Type-Options'] = 'nosniff'
    
    # Hindra att sidan används i iframe (skydd mot clickjacking)
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    
    # Strikta transportssäkerhet (HSTS) - bara i produktion med HTTPS
    if not app.debug and not app.testing:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    # Skydd mot XSS-attacker för webbläsare som stöder det
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    # Referrer Policy - mer restriktiv
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    # Feature Policy - begränsa åtkomst till känsliga funktioner
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    
    return response

# Databas
DATABASE_URL = os.getenv("DATABASE_URL")
engine = create_engine(
    DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_recycle=3600,  # Återanvända anslutningar efter 1 timme
    pool_timeout=30     # Timeout efter 30 sekunder
)
metadata = MetaData()

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    storage_uri=os.getenv("RATE_LIMIT_STORAGE_URI", "memory://"),
    default_limits=[os.getenv("RATE_LIMIT_DEFAULT", "100 per minute")]
)

def get_db_connection():
    """
    Returnerar en SQLAlchemy-transaktion (connection) med hjälp av engine.begin().
    Använder connection pool för bättre prestanda och hanterar fel korrekt.
    """
    try:
        return engine.begin()  # Hanterar commit/rollback automatiskt
    except Exception as e:
        app.logger.error(f"⚠️ Fel vid anslutning till databasen: {e}")
        try:
            # Prova med fallback-anslutning endast vid faktiskt fel
            user = os.getenv("DB_USER", "postgres")
            password = os.getenv("DB_PASSWORD", "mysecretpassword")
            host = os.getenv("DB_HOST", "localhost")
            port = os.getenv("DB_PORT", "5432")
            dbname = os.getenv("DB_NAME", "loggain")
            fallback_url = f"postgresql://{user}:{password}@{host}:{port}/{dbname}"
            fallback_engine = create_engine(fallback_url)
            return fallback_engine.begin()
        except Exception as e:
            app.logger.error(f"❌ Databasanslutning misslyckades helt: {e}")
            raise e

users = Table('users', metadata, autoload_with=engine)

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(hours=1)
    # Förbättra CSRF-skydd för sessioner
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)
    
    # Kontrollera om användaren är inloggad
    if current_user.is_authenticated:
        # Kontrollera om sessionen har en unik session_id
        if 'unique_session_id' not in session:
            session['unique_session_id'] = str(uuid.uuid4())
        
        # Kontrollera om sessionen har blivit ogiltigförklarad (någon annan har loggat in)
        if is_session_invalid(session['unique_session_id']):
            # Logga ut användaren
            logout_user()
            session.clear()
            # Sätt ett meddelande som visas efter omdirigering
            session['logout_message'] = "Du har loggats ut eftersom någon annan loggade in på ditt konto."
            # Omdirigera till inloggningssidan
            if request.endpoint != 'loggain' and not request.path.startswith('/static/'):
                return redirect(url_for('loggain'))
    
    # Sätt cookie-säkerhet (kan justeras för utveckling)
    session.modified = True

# Variabel för att spåra om databasen har konfigurerats
_database_setup_done = False

@app.before_request
def setup_database_if_needed():
    """Kontrollerar och lägger till saknade kolumner i databasen vid första förfrågan."""
    global _database_setup_done
    if _database_setup_done:
        return
    
    _database_setup_done = True
    try:
        with get_db_connection() as conn:
            # Kontrollera om kolumnerna publisher, pages och category finns i tabellen
            check_columns_query = text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'books' 
                AND column_name IN ('publisher', 'pages', 'category')
            """)
            existing_columns = [row[0] for row in conn.execute(check_columns_query).fetchall()]
            
            # Lägg till saknade kolumner
            if 'publisher' not in existing_columns:
                app.logger.info("Lägger till kolumnen 'publisher' i books-tabellen")
                conn.execute(text("ALTER TABLE books ADD COLUMN publisher TEXT"))
                
            if 'pages' not in existing_columns:
                app.logger.info("Lägger till kolumnen 'pages' i books-tabellen")
                conn.execute(text("ALTER TABLE books ADD COLUMN pages INTEGER"))
                
            if 'category' not in existing_columns:
                app.logger.info("Lägger till kolumnen 'category' i books-tabellen")
                conn.execute(text("ALTER TABLE books ADD COLUMN category TEXT"))
                
            conn.commit()
            app.logger.info("Databaskontroll slutförd")
    except Exception as e:
        app.logger.error(f"Fel vid kontroll/uppdatering av databas: {e}")

# ROUTES
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/registrera')
def registrera():
    return render_template('registreradig.html')

@app.route('/omoss')
def omoss():
    return render_template('omoss.html')

@app.route('/hallbarhet')
def hallbarhet():
    return render_template('hallbarhet.html')

@app.route('/kontaktaoss', methods=['GET'])
def kontaktaoss():
    return render_template('kontaktaoss.html')

@app.route('/loggain')
def loggain():
    # Kontrollera om det finns ett utloggningsmeddelande
    logout_message = session.pop('logout_message', None)
    return render_template('loggain.html', error_message=logout_message)

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/anvandarvilkor')
def anvandarvilkor():
    return render_template('anvandarvilkor.html')

@app.route('/Integritetspolicy')
def Integritetspolicy():
    return render_template('Integritetspolicy.html')

@app.route('/karriar')
def karriar():
    return render_template('karriar.html')

@app.route('/glomtlosenord')
def glomtlosenord():
    return render_template('glomtlosenord.html')

@app.route('/kontakt')
def kontakt():
    return render_template('kontakt.html')

@app.route('/support')
def support():
    return render_template('support.html')

@app.route('/blipartner')
def blipartner():
    return render_template('blipartner.html')

@app.route('/forlagsvilkor')
def forlagsvilkor():
    return render_template('forlagsvilkor.html')

@app.route('/fel')
def fel():
    message = request.args.get('message', 'Ett fel har inträffat.')
    return render_template('fel.html', message=message)

@app.route('/register', methods=['POST'])
@limiter.limit("10 per hour")
def register():
    # Hämta formulärdata
    email = request.form.get('email', '').strip().lower()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    # Validera indata
    validation_errors = []
    
    # E-postvalidering
    if not email:
        validation_errors.append("E-postadress är obligatorisk.")
    elif not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email):
        validation_errors.append("Ogiltig e-postadress.")
        
    # Användarnamnsvalidering 
    if not username:
        validation_errors.append("Användarnamn är obligatoriskt.")
    elif len(username) < 3:
        validation_errors.append("Användarnamnet måste innehålla minst 3 tecken.")
    elif len(username) > 30:
        validation_errors.append("Användarnamnet får inte överstiga 30 tecken.")
    elif not re.match(r'^[a-zA-Z0-9_\-]+$', username):
        validation_errors.append("Användarnamnet får bara innehålla bokstäver, siffror, bindestreck och understreck.")
    
    # Lösenordsvalidering
    if not password:
        validation_errors.append("Lösenord är obligatoriskt.")
    elif len(password) < 8:
        validation_errors.append("Lösenordet måste innehålla minst 8 tecken.")
    elif not re.search(r'[A-Z]', password):
        validation_errors.append("Lösenordet måste innehålla minst en stor bokstav.")
    elif not re.search(r'[a-z]', password):
        validation_errors.append("Lösenordet måste innehålla minst en liten bokstav.")
    elif not re.search(r'[0-9]', password):
        validation_errors.append("Lösenordet måste innehålla minst en siffra.")
    
    # Bekräfta lösenord
    if password != confirm_password:
        validation_errors.append("Lösenorden matchar inte.")
    
    # Om valideringsfel finns, returnera dem
    if validation_errors:
        return jsonify({"success": False, "errors": validation_errors}), 400
    
    try:
        with get_db_connection() as conn:
            # Kontrollera om e-postadressen redan finns
            check_query = text("SELECT id FROM users WHERE email = :email")
            existing_email = conn.execute(check_query, {"email": email}).fetchone()
            if existing_email:
                return jsonify({"success": False, "errors": ["E-postadressen är redan registrerad."]}), 409
            
            # Kontrollera om användarnamnet redan finns
            check_query = text("SELECT id FROM users WHERE username = :username")
            existing_username = conn.execute(check_query, {"username": username}).fetchone()
            if existing_username:
                return jsonify({"success": False, "errors": ["Användarnamnet är redan taget."]}), 409
            
            # Skapa ny användare med säker lösenordshashning
            hashed_password = generate_password_hash(password)
            insert_query = text("""
                INSERT INTO users (email, username, password, created_at, membership_active)
                VALUES (:email, :username, :password, :created_at, false)
                RETURNING id
            """)
            result = conn.execute(
                insert_query, 
                {
                    "email": email, 
                    "username": username, 
                    "password": hashed_password,
                    "created_at": datetime.now()
                }
            ).fetchone()
            
            user_id = result[0]
            
            app.logger.info(f"Ny användare registrerad: {user_id} ({username}, {email})")
            
            # Skapa en ny User-objekt
            user = User(id=user_id, username=username, membership_active=False)
            
            # Skapa en unik session-ID för denna inloggning
            unique_session_id = str(uuid.uuid4())
            session['unique_session_id'] = unique_session_id
            
            # Kontrollera om användaren redan är inloggad någon annanstans
            # och invalidera den tidigare sessionen
            invalidate_session(user_id, unique_session_id)
            
            # Spara den nya aktiva sessionen
            save_active_session(user_id, unique_session_id)
            
            # Logga in användaren
            login_user(user)
            
            return jsonify({"success": True, "redirect": "/inloggad"}), 201
            
    except Exception as e:
        app.logger.error(f"Registreringsfel: {e}")
        return jsonify({"success": False, "errors": ["Ett fel uppstod vid registrering. Vänligen försök igen."]}), 500

@app.route('/check_email')
@limiter.limit("20 per minute")
def check_email():
    email_to_check = request.args.get('email', '').strip().lower()
    if not email_to_check:
        return jsonify({"used": False})
    with get_db_connection() as conn:
        query = text("SELECT id FROM users WHERE LOWER(email) = :email LIMIT 1")
        result = conn.execute(query, {"email": email_to_check}).fetchone()
    return jsonify({"used": True}) if result else jsonify({"used": False})

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if current_user.is_authenticated:
        # Ta bort den aktiva sessionen från Redis
        if 'unique_session_id' in session:
            key = f"active_session:{current_user.id}"
            redis_client.delete(key)
    
    logout_user()
    session.clear()
    return redirect(url_for('loggain'))

@app.route('/loggain/submit', methods=['POST'])
@limiter.limit("5 per minute")
def loggain_submit():
    # Hämta e-post och lösenord från formuläret
    email = request.form.get('email')
    password = request.form.get('password')
    remember_me = 'remember_me' in request.form
    
    # Kontrollera om det är en AJAX-förfrågan
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    # Kontrollera om kontot är låst
    if is_account_locked(email):
        error_message = 'Kontot är tillfälligt låst på grund av för många misslyckade inloggningsförsök. Vänligen försök igen om 30 minuter.'
        app.logger.warning(f"Inloggningsförsök på låst konto: {email}")
        
        if is_ajax:
            return jsonify({"error": error_message}), 403
        else:
            flash(error_message, 'danger')
            return redirect(url_for('loggain'))

    try:
        with get_db_connection() as conn:
            query = text("SELECT * FROM users WHERE email = :email")
            user = conn.execute(query, {"email": email}).fetchone()
            
            # Kontrollera om användarobjektet finns och om inloggning är rätt
            if user and check_password_hash(user.password, password):
                # Lyckad inloggning - återställ räknaren
                reset_failed_login(email)
                
                # Skapa User-objekt och logga in användaren
                user_obj = User(
                    id=user.id, 
                    username=user.username, 
                    membership_active=user.membership_active,
                    program_id=user.subscription_id if hasattr(user, 'subscription_id') else None,
                    start_date=user.start_date if hasattr(user, 'start_date') else None
                )
                
                # Skapa en unik session-ID för denna inloggning
                unique_session_id = str(uuid.uuid4())
                session['unique_session_id'] = unique_session_id
                
                # Kontrollera om användaren redan är inloggad någon annanstans
                # och invalidera den tidigare sessionen
                invalidate_session(user.id, unique_session_id)
                
                # Spara den nya aktiva sessionen
                save_active_session(user.id, unique_session_id)
                
                # Logga in användaren
                login_user(user_obj, remember=remember_me)
                
                # Sätt permanenta sessioner om remember_me
                if remember_me:
                    session.permanent = True
                
                # Logga händelsen 
                success_message = 'Du är nu inloggad!'
                app.logger.info(f"Användare {user.id} ({user.username}) loggade in")
                
                if is_ajax:
                    return jsonify({"redirect": url_for('inloggad'), "message": success_message}), 200
                else:
                    flash(success_message, 'success')
                    return redirect(url_for('inloggad'))
            else:
                # Misslyckad inloggning - öka räknaren
                attempts = increment_failed_login(email)
                remaining_attempts = 5 - attempts
                
                if remaining_attempts <= 0:
                    error_message = 'För många misslyckade inloggningsförsök. Kontot är tillfälligt låst i 30 minuter.'
                    app.logger.warning(f"Konto låst efter för många misslyckade försök: {email}")
                else:
                    error_message = f'Felaktigt användarnamn eller lösenord. Du har {remaining_attempts} försök kvar innan kontot låses tillfälligt.'
                
                if is_ajax:
                    return jsonify({"error": error_message}), 401
                else:
                    flash(error_message, 'danger')
                    return redirect(url_for('loggain'))
    except Exception as e:
        error_message = 'Ett fel uppstod vid inloggning. Vänligen försök igen.'
        app.logger.error(f"Fel vid inloggning: {e}")
        
        if is_ajax:
            return jsonify({"error": error_message}), 500
        else:
            flash(error_message, 'danger')
            return redirect(url_for('loggain'))

@app.errorhandler(RateLimitExceeded)
def handle_rate_limit_exceeded(e):
    app.logger.warning(f"Rate limit exceeded: {e.description}")
    
    # Kontrollera om det är en API-ändpunkt (förväntar JSON)
    if request.path.startswith('/api/') or request.headers.get('Accept') == 'application/json':
        return jsonify({
            "error": "För många förfrågningar. Vänta några minuter och försök igen.",
            "retry_after": e.retry_after
        }), 429
    
    # Vanlig webbförfrågan - omdirigera till en felmeddelande-sida
    flash("För många förfrågningar. Vänta några minuter och försök igen.", "warning")
    return redirect(url_for('fel', message="För många förfrågningar. Vänta några minuter och försök igen.")), 429

@cached_query(ttl_seconds=60)  # 1 minut TTL - kort för att vara aktuell
def get_latest_purchase_for_user(user_id):
    """
    Hämtar senaste köpet för en användare.
    Cachelagras i 1 minut för att balansera prestanda och aktualitet.
    """
    try:
        with get_db_connection() as conn:
            query = text("""
                SELECT ub.purchase_date, ub.book_id, b.title, b.author, b.cover_image 
                FROM user_books ub
                JOIN books b ON ub.book_id = b.id
                WHERE ub.user_id = :user_id
                ORDER BY ub.purchase_date DESC
                LIMIT 1
            """)
            
            result = conn.execute(query, {"user_id": user_id}).fetchone()
            
            if not result:
                return None
                
            return {
                'purchase_date': result.purchase_date,
                'book_id': result.book_id,
                'title': result.title,
                'author': result.author,
                'cover_image': result.cover_image
            }
    except Exception as e:
        app.logger.error(f"Fel vid hämtning av senaste köp: {e}")
        return None

@app.route('/inloggad')
@login_required
def inloggad():
    app.logger.debug(f"Användare {current_user.id} besöker inloggad-sidan")
    
    if not current_user.is_authenticated:
        app.logger.warning("Användare ej autentiserad trots @login_required")
        return redirect(url_for('loggain'))
        
    app.logger.debug(f"Användare autentiserad: {current_user.username}")
    
    latest_purchase = get_latest_purchase_for_user(current_user.id)
    
    # Hämta antal köpta böcker och medlemskapsinformation
    with get_db_connection() as conn:
        # Hämta antal köpta böcker
        books_query = text("SELECT COUNT(*) FROM user_books WHERE user_id = :user_id")
        books_row = conn.execute(books_query, {"user_id": current_user.id}).fetchone()
        books_count = books_row[0] if books_row else 0
        
        # Hämta registreringsdatum och medlemskapsinfo
        user_query = text("""
            SELECT created_at, subscription_id 
            FROM users 
            WHERE id = :user_id
        """)
        user_row = conn.execute(user_query, {"user_id": current_user.id}).fetchone()
        
        start_date = user_row[0] if user_row else datetime.now()
        subscription_id = user_row[1] if user_row else None
        
        app.logger.debug(f"DB-data: start_date={start_date}, subscription_id={subscription_id}")
    
    # Beräkna förfallodatum för medlemskapet
    membership_expiry = None
    days_until_expiry = None
    
    # Om användaren har ett subscription_id (Stripe-prenumeration)
    if subscription_id and current_user.membership_active:
        app.logger.debug(f"Försöker hämta Stripe-prenumeration för ID: {subscription_id}")
        app.logger.debug(f"Stripe API-nyckel finns: {'Ja' if stripe.api_key else 'Nej'}")
        
        try:
            # Hämta information från Stripe om prenumerationen
            subscription = stripe.Subscription.retrieve(subscription_id)
            app.logger.debug(f"Stripe-prenumeration hämtad: {subscription.id}")
            app.logger.debug(f"Prenumerationsdata: status={subscription.status}, current_period_end={subscription.current_period_end}")
            
            # Få nästa faktureringsdatum (i Unix timestamp format)
            next_billing_timestamp = subscription.current_period_end
            
            # Konvertera till datetime
            membership_expiry = datetime.fromtimestamp(next_billing_timestamp)
            
            # Beräkna dagar tills förnyelse
            days_until_expiry = (membership_expiry.date() - datetime.now().date()).days
            
            app.logger.debug(f"Stripe-beräkning: Förnyelse {membership_expiry}, {days_until_expiry} dagar kvar")
        except Exception as e:
            app.logger.error(f"Fel vid hämtning av Stripe-prenumeration: {e}", exc_info=True)
            # Sätt membership_expiry till None om Stripe-anrop misslyckas
            app.logger.debug("Kunde inte hämta förnyelsedatum från Stripe")
            membership_expiry = None
            days_until_expiry = None
            app.logger.debug("Medlemskapsförnyelse kunde ej hämtas")
    # Fallback för användare utan prenumeration eller inaktivt medlemskap
    elif start_date:
        app.logger.debug("Ingen aktiv Stripe-prenumeration hittad, använder standardberäkning")
        # Använd registreringsdatum + 365 dagar som standard
        membership_expiry = start_date + timedelta(days=365)
        if isinstance(membership_expiry, datetime):
            days_until_expiry = (membership_expiry.date() - datetime.now().date()).days
        else:
            days_until_expiry = (membership_expiry - datetime.now().date()).days
    
    # Lägg till cache-kontrollhuvuden
    response = make_response(render_template('inloggad.html',
                           username=current_user.username,
                           membership_active=current_user.membership_active,
                           latest_purchase=latest_purchase,
                           books_count=books_count,
                           membership_expiry=membership_expiry,
                           days_until_expiry=days_until_expiry))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

@app.route('/send-email', methods=['POST'])
@limiter.limit("5 per minute")
def send_email():
    data = request.get_json()
    user_type = data.get("userType")
    email = data.get("email")
    subject = data.get("subject")
    message = data.get("message")
    if not user_type or not email or not subject or not message:
        return jsonify({"error": "All fields are required"}), 400
    if user_type == "student":
        recipient_email = "student@kunskapslitteratur.se"
    elif user_type == "forlag":
        recipient_email = "forlag@kunskapslitteratur.se"
    else:
        recipient_email = "info@kunskapslitteratur.se"
    try:
        msg = MIMEText(message, "plain", "utf-8")
        msg["Subject"] = f"New contact form submission: {subject}"
        msg["From"] = "info@kunskapslitteratur.se"
        msg["To"] = recipient_email
        msg["Reply-To"] = email
        with smtplib.SMTP_SSL(os.getenv("SMTP_SERVER"), int(os.getenv("SMTP_PORT", 465))) as server:
            server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))
            server.sendmail("info@kunskapslitteratur.se", [recipient_email], msg.as_string())
        return jsonify({"message": "Meddelandet har skickats"}), 200
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return jsonify({"error": f"Failed to send email: {str(e)}"}), 500

@app.route("/send-reset-link", methods=["POST"])
def send_reset_link():
    """
    En klassisk POST-route, som tar emot email från ett <form> i HTML.
    """
    try:
        email = request.form.get("email", "").strip().lower()
        if not email:
            flash("E-postadress saknas!", "error")
            return redirect(url_for("glomtlosenord"))

        # 1) Kolla om email finns i DB
        with get_db_connection() as conn:
            query = text("SELECT id FROM users WHERE LOWER(email) = :email LIMIT 1")
            result = conn.execute(query, {"email": email}).fetchone()
            if not result:
                flash("E-postadressen finns inte!", "error")
                return redirect(url_for("glomtlosenord"))

            user_id = result[0]

            # 2) Skapa reset-token
            token = create_reset_token(user_id, conn)  # Du har redan en create_reset_token-funktion
            reset_link = f"https://living-oddly-tortoise.ngrok-free.app/reset-password?token={token}"

            # 3) Skicka mejlet
            msg = MIMEText(
                f"Klicka på länken för att återställa ditt lösenord:\n{reset_link}",
                "plain",
                "utf-8"
            )
            msg["Subject"] = "Återställ lösenord"
            msg["From"] = os.getenv("SMTP_USER")
            msg["To"] = email

            with smtplib.SMTP_SSL(os.getenv("SMTP_SERVER"), int(os.getenv("SMTP_PORT", 465))) as server:
                server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))
                server.sendmail(os.getenv("SMTP_USER"), [email], msg.as_string())

        flash("Återställningslänk skickad! Kolla din e-post.", "success")
        return redirect(url_for("glomtlosenord"))

    except Exception as e:
        app.logger.error(f"Fel i /send-reset-link: {e}")
        flash("Något gick fel. Försök igen.", "error")
        return redirect(url_for("glomtlosenord"))


def create_reset_token(user_id, conn):
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now() + timedelta(hours=1)
    query = text("""
        INSERT INTO password_resets (user_id, token, expires_at)
        VALUES (:user_id, :token, :expires_at)
    """)
    conn.execute(query, {"user_id": user_id, "token": token, "expires_at": expires_at})
    return token


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    """
    Hanterar både GET (visar formulär för återställning) och POST (uppdaterar lösenordet).
    """

    if request.method == "GET":
        # 1) Läs token från URL:en
        token = request.args.get("token")
        if not token:
            return "Ogiltig token!", 400

        # 2) Kolla om token finns i databasen och ej är utgången
        with get_db_connection() as conn:
            query = text("SELECT user_id, expires_at FROM password_resets WHERE token = :token")
            row = conn.execute(query, {"token": token}).fetchone()

            # row blir en tuple, t.ex. (123, datetime(...)) om hittad
            if not row:
                return "Ogiltig token!", 400

            user_id = row[0]
            expires_at = row[1]

            if expires_at < datetime.now():
                return "Token har gått ut.", 400

        return render_template("aterstalllosen.html", token=token)

    # -------------------------------------------------------------------
    # Om det är en POST-förfrågan (formuläret skickas)
    # -------------------------------------------------------------------
    if request.method == "POST":
        # 1) Läs CSRF-token från formuläret
        csrf_token_form = request.form.get("csrf_token")

        # 2) Hämta token och nya lösenord
        token = request.form.get("token")
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirmPassword")

        if not token:
            return "Ogiltig token!", 400
        if not new_password or new_password != confirm_password:
            return "Lösenorden matchar inte!", 400

        # 3) Kolla token i databasen, uppdatera lösenordet
        with get_db_connection() as conn:
            query = text("SELECT user_id, expires_at FROM password_resets WHERE token = :token")
            row = conn.execute(query, {"token": token}).fetchone()

            if not row:
                return "Ogiltig token!", 400

            user_id = row[0]
            expires_at = row[1]

            if expires_at < datetime.now():
                return "Token har gått ut.", 400

            # Kryptera lösenordet
            hashed_password = generate_password_hash(new_password)

            # Uppdatera lösenord
            update_query = text("UPDATE users SET password = :password WHERE id = :user_id")
            conn.execute(update_query, {"password": hashed_password, "user_id": user_id})

            # Ta bort token efter lyckad uppdatering
            delete_query = text("DELETE FROM password_resets WHERE token = :token")
            conn.execute(delete_query, {"token": token})

        # 4) Visa en sida som bekräftar att lösenordet uppdaterats
        return render_template('losenuppdaterad.html')


@app.route('/my_books')
@login_required
def my_books():
    if not current_user.is_authenticated:
        return redirect(url_for('loggain'))
    query = text("""
        SELECT b.id, b.title, b.author, b.description, b.pdf_path, ub.purchase_date
        FROM books b
        INNER JOIN user_books ub ON b.id = ub.book_id
        WHERE ub.user_id = :user_id
    """)
    with get_db_connection() as conn:
        rows = conn.execute(query, {"user_id": current_user.id}).fetchall()
    books = []
    for row in rows:
        expires_on = row.purchase_date + timedelta(days=365)
        days_left = (expires_on - datetime.now()).days
        books.append({
            "id": row.id,
            "title": row.title,
            "author": row.author,
            "description": row.description,
            "pdf_path": row.pdf_path,
            "purchase_date": row.purchase_date,
            "expires_on": expires_on,
            "days_left": days_left,
        })
    return render_template('minbok.html', books=books, membership_active=current_user.membership_active)

@app.route('/utforskabocker')
@login_required
def utforskabocker():
    try:
        query = text("""
            SELECT id, title, author, price, cover_image, isbn, publication_year, description 
            FROM books
        """)
        with get_db_connection() as conn:
            result = conn.execute(query).fetchall()
            books = [dict(row._mapping) for row in result]
        cart = session.get('cart', {})
        return render_template('utforskabocker.html', books=books, cart_items=cart)
    except Exception as e:
        app.logger.error(f"Fel vid hämtning av böcker: {e}")
        return render_template('utforskabocker.html', books=[], cart_items=session.get('cart', {}))

@app.route('/add-to-cart', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def add_to_cart():
    try:
        data = request.get_json()
        book_id = data.get('book_id')
        if not book_id:
            return jsonify({'success': False, 'message': 'Ingen bok-id skickades.'}), 400
        cart = session.get('cart', {})
        cart[book_id] = cart.get(book_id, 0) + 1
        session['cart'] = cart
        return jsonify({'success': True, 'message': 'Boken har lagts till i varukorgen!'})
    except Exception as e:
        return jsonify({'success': False, 'message': 'Ett fel inträffade.'}), 500

@app.route('/update-cart', methods=['POST'])
@login_required
@limiter.limit("30 per minute")
def update_cart():
    data = request.get_json()
    book_id = data.get('book_id')
    action = data.get('action')  # 'add' eller 'remove'
    if not book_id or not action:
        return jsonify({'success': False, 'message': 'Ogiltig förfrågan'}), 400
    cart = session.get('cart', {})
    if action == 'add':
        cart[book_id] = cart.get(book_id, 0) + 1
    elif action == 'remove':
        if book_id in cart:
            del cart[book_id]
    else:
        return jsonify({'success': False, 'message': 'Ogiltig åtgärd'}), 400
    session['cart'] = cart
    return jsonify({'success': True, 'cart': cart})

@cached_query(cache_key="book_filter_options", ttl_seconds=3600)
def get_book_filter_options(conn):
    """Hämtar filteralternativ för booksökning. Cachelagrad i 1 timme."""
    try:
        # Hämta unika kategorier
        categories_query = text("SELECT DISTINCT category FROM books WHERE category IS NOT NULL")
        categories = [row[0] for row in conn.execute(categories_query).fetchall()]
        
        # Hämta unika förlag
        publishers_query = text("SELECT DISTINCT publisher FROM books WHERE publisher IS NOT NULL")
        publishers = [row[0] for row in conn.execute(publishers_query).fetchall()]
        
        # Hämta unika publiceringsår
        years_query = text("SELECT DISTINCT publication_year FROM books WHERE publication_year IS NOT NULL")
        years = [row[0] for row in conn.execute(years_query).fetchall()]
        
        # Hämta pris-range
        price_query = text("SELECT MIN(price), MAX(price) FROM books")
        price_result = conn.execute(price_query).fetchone()
        min_price = float(price_result[0]) if price_result[0] else 0
        max_price = float(price_result[1]) if price_result[1] else 0
        
        return {
            'categories': categories,
            'publishers': publishers,
            'years': years,
            'price_range': {
                'min': min_price,
                'max': max_price
            }
        }
    except Exception as e:
        app.logger.error(f"SQL-fel vid hämtning av filter-alternativ: {e}")
        return {
            'categories': [],
            'publishers': [],
            'years': [],
            'price_range': {'min': 0, 'max': 0}
        }

@app.route('/get-books', methods=['GET'])
@login_required
def get_books():
    """Hämtar böcker baserat på filter, sökning och sidnummer."""
    try:
        # Få sökning och filtrering från request
        category = request.args.get('category')
        publisher = request.args.get('publisher')
        min_price = request.args.get('min_price')
        max_price = request.args.get('max_price')
        search_query = request.args.get('search')
        year = request.args.get('year')
        
        # Pagination-parametrar
        limit = int(request.args.get('limit', 20))
        offset = int(request.args.get('offset', 0))
        
        # Bygga SQL-filter
        try:
            # Hämta filter-parametrar
            category = request.args.get('category')
            publisher = request.args.get('publisher')
            min_price = request.args.get('min_price')
            max_price = request.args.get('max_price')
            search_query = request.args.get('search')
            year = request.args.get('year')
            
            # Pagination-parametrar
            limit = int(request.args.get('limit', 20))
            offset = int(request.args.get('offset', 0))
            
            # Bygga SQL-filter
            filter_conditions = []
            params = {"limit": limit, "offset": offset}
            
            if category:
                filter_conditions.append("category = :category")
                params["category"] = category
                
            if publisher:
                filter_conditions.append("publisher = :publisher")
                params["publisher"] = publisher
                
            if year:
                filter_conditions.append("publication_year = :year")
                params["year"] = year
                
            if min_price:
                filter_conditions.append("price >= :min_price")
                params["min_price"] = float(min_price)
                
            if max_price:
                filter_conditions.append("price <= :max_price")
                params["max_price"] = float(max_price)
                
            if search_query:
                filter_conditions.append("(title ILIKE :search OR author ILIKE :search OR description ILIKE :search)")
                params["search"] = f"%{search_query}%"
            
            with get_db_connection() as conn:
                # Hämta användarens böcker för att markera ägda böcker
                owned_query = text("SELECT book_id FROM user_books WHERE user_id = :user_id")
                owned_book_ids = conn.execute(owned_query, {"user_id": current_user.id}).fetchall()
                owned_book_ids_set = {row[0] for row in owned_book_ids}
                    
                # Kombinera filter-villkor till en WHERE-sats
                where_clause = " AND ".join(filter_conditions) if filter_conditions else "1=1"
                
                # Hämta böcker med filter
                try:
                    query = text(f"""
                        SELECT id, title, author, price, cover_image, description, 
                               publication_year, publisher, isbn, category, pages, language
                        FROM books
                        WHERE {where_clause}
                        ORDER BY id
                        LIMIT :limit OFFSET :offset
                    """)
                    
                    result = conn.execute(query, params)
                    books = []
                    for row in result:
                        book_dict = dict(row._mapping)
                        book_dict['owned'] = (book_dict['id'] in owned_book_ids_set)
                        # Om språk saknas, använd engelska som standardspråk
                        if 'language' not in book_dict or book_dict['language'] is None:
                            book_dict['language'] = 'Engelska'
                        books.append(book_dict)
                except Exception as e:
                    app.logger.error(f"SQL-fel vid filtrering av böcker: {e}")
                    return jsonify({'error': 'Ett fel inträffade vid filtrering av böcker.'}), 500
                    
                # Hämta filter-alternativ från vår cachade funktion    
                filter_options = get_book_filter_options(conn)
                
            return jsonify({
                'books': books, 
                'filter_options': filter_options
            })
        except Exception as e:
            app.logger.error(f"Fel vid hämtning av böcker: {e}")
            return jsonify({'error': 'Ett fel inträffade vid hämtning av böcker.'}), 500

        # Om det är en uppdatering av bokdata, rensa filter-cache
        if request.args.get('refresh_cache') == 'true':
            invalidate_cache("book_filter_options")
            app.logger.debug("Book filter options cache rensad efter användaruppdatering")

    except Exception as e:
        app.logger.error(f"Fel vid hämtning av böcker: {e}")
        return jsonify({'error': 'Ett fel inträffade vid hämtning av böcker.'}), 500

@app.route('/get-book-cover', methods=['GET'])
@login_required
def get_book_cover():
    try:
        title = request.args.get('title', '').strip()
        if not title:
            return jsonify({'error': 'Boktitel saknas'}), 400
            
        with get_db_connection() as conn:
            # Kontrollera om kolumnerna finns i tabellen
            check_columns_query = text("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_name = 'books' 
                AND column_name IN ('publisher', 'pages', 'category', 'language')
            """)
            existing_columns = [row[0] for row in conn.execute(check_columns_query).fetchall()]
            
            # Hämta alla tillgängliga bokdetaljer
            query = text("""
                SELECT cover_image, isbn, publication_year, 
                       COALESCE(description, 'Ingen beskrivning tillgänglig.') as description
                       -- Lägg till publisher, pages och category om de finns
                       {publisher_col}
                       {pages_col}
                       {category_col}
                       {language_col}
                FROM books
                WHERE title = :title
                LIMIT 1
            """.format(
                publisher_col=", publisher" if 'publisher' in existing_columns else "",
                pages_col=", pages" if 'pages' in existing_columns else "",
                category_col=", category" if 'category' in existing_columns else "",
                language_col=", language" if 'language' in existing_columns else ""
            ))
            
            result = conn.execute(query, {"title": title}).fetchone()
            
            if result:
                book_details = dict(result._mapping)
                
                # Lägg till standardvärden för kolumner som kanske inte finns
                if 'publisher' not in book_details and 'publisher' not in existing_columns:
                    book_details['publisher'] = 'Okänd'
                if 'pages' not in book_details and 'pages' not in existing_columns:
                    book_details['pages'] = '-'
                if 'category' not in book_details and 'category' not in existing_columns:
                    book_details['category'] = 'Okategoriserad'
                if 'language' not in book_details and 'language' not in existing_columns:
                    book_details['language'] = 'Engelska'
                # Om language är null, använd Engelska som standard
                if book_details.get('language') is None:
                    book_details['language'] = 'Engelska'
                
                return jsonify(book_details)
            else:
                return jsonify({
                    'cover_image': 'bilder/default_book_cover.jpg',
                    'description': 'Ingen beskrivning tillgänglig.',
                    'publisher': 'Okänd',
                    'isbn': '-',
                    'publication_year': '-',
                    'pages': '-',
                    'category': 'Okategoriserad',
                    'language': 'Engelska'
                })
    except Exception as e:
        print(f"Fel vid hämtning av bokomslag: {e}")
        return jsonify({'error': 'Tekniskt fel vid hämtning av bokomslag'}), 500

@app.route('/checkout', methods=['GET', 'POST'])
@login_required
def checkout():
    if request.method == 'POST':
        cart_data = request.json  
        return jsonify({"success": True, "message": "Köp slutfört!"})
    return render_template('checkout.html')

@app.route('/create-checkout-session-membership', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def create_checkout_session_membership():
    try:
        app.logger.info(f"Användare {current_user.id} försöker teckna medlemskap")
        
        if current_user.membership_active:
            app.logger.warning(f"Användare {current_user.id} försökte teckna medlemskap men har redan aktivt medlemskap")
            return jsonify({'error': 'Du har redan medlemskap!'}), 400
            
        app.logger.debug(f"Skapar Stripe checkout session för medlemskap för användare {current_user.id}")
        app.logger.debug(f"Stripe API-nyckel finns: {'Ja' if stripe.api_key else 'Nej'}")
        
        # Säkerställ korrekt URL-formatering och använder HTTPS för ngrok
        host_url = request.host_url.rstrip('/')
        # Konvertera till HTTPS om det är en ngrok-URL
        if 'ngrok-free.app' in host_url:
            base_url = host_url.replace('http://', 'https://')
        else:
            base_url = host_url
            
        success_url = f"{base_url}/checkout-success?type=membership"
        cancel_url = f"{base_url}/checkout-cancel"
        
        app.logger.debug(f"Success URL: {success_url}")
        app.logger.debug(f"Cancel URL: {cancel_url}")
        
        session_stripe = stripe.checkout.Session.create(
            payment_method_types=['card'],  # Ta bort Klarna för prenumerationer
            mode='subscription',
            line_items=[{
                'price': 'price_1Qsn1WAQlWNEJwj3bIH4z9Fa',
                'quantity': 1
            }],
            success_url=success_url,
            cancel_url=cancel_url,
            client_reference_id=current_user.id,
            metadata={'type': 'membership'}
        )
        
        app.logger.info(f"Stripe checkout session skapad för användare {current_user.id}: {session_stripe.id}")
        return jsonify({'sessionId': session_stripe.id})
    except Exception as e:
        app.logger.error(f"Fel vid skapande av medlemskaps-session för användare {current_user.id}: {e}", exc_info=True)
        return jsonify({'error': f'Ett fel inträffade vid betalning: {str(e)}'}), 500


@app.route('/create-checkout-session-books', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def create_checkout_session_books():
    try:
        app.logger.debug("Startar skapande av checkout-session för böcker")
        data = request.get_json()
        books = data.get('books', [])
        if not books:
            return jsonify({'error': 'Varukorgen är tom!'}), 400
        
        app.logger.debug(f"Böcker i varukorgen: {books}")
        
        # Säkerställ att URL:erna är korrekt formaterade och använder HTTPS för ngrok
        image_base_url = request.url_root
        if 'ngrok-free.app' in image_base_url:
            image_base_url = image_base_url.replace('http://', 'https://')
        
        line_items = []
        for item in books:
            price_float = float(item['price'])
            # Ersätt backslash med framåtlutande snedstreck i bildfilnamnet
            cover_image = item.get('cover_image', '').replace('\\', '/')
            
            line_items.append({
                'price_data': {
                    'currency': 'sek',  # SEK är en av valutorna som stöds av Klarna
                    'product_data': {
                        'name': item['title'],
                        'images': [f"{image_base_url}static/{cover_image}"]
                    },
                    'unit_amount': int(price_float * 100),
                },
                'quantity': 1,
            })
        
        if not current_user.membership_active:
            return jsonify({'error': 'Du saknar medlemskap. Köp medlemskap först!'}), 400
        
        # Hämta användarinformation för Klarna
        with get_db_connection() as conn:
            user_query = text("SELECT email FROM users WHERE id = :user_id")
            user_row = conn.execute(user_query, {"user_id": current_user.id}).fetchone()
            user_email = user_row[0] if user_row else None
        
        app.logger.debug("Skapar Stripe Checkout Session med Klarna")
        
        # Säkerställ att URL:erna är korrekt formaterade och använder HTTPS för ngrok
        host_url = request.host_url.rstrip('/')
        # Konvertera till HTTPS om det är en ngrok-URL
        if 'ngrok-free.app' in host_url:
            base_url = host_url.replace('http://', 'https://')
        else:
            base_url = host_url
            
        success_url = f"{base_url}/checkout-success?type=books"
        cancel_url = f"{base_url}/checkout-cancel"
        
        app.logger.debug(f"Success URL: {success_url}")
        app.logger.debug(f"Cancel URL: {cancel_url}")
        
        checkout_session_params = {
            'payment_method_types': ['card', 'klarna'],
            'mode': 'payment',
            'line_items': line_items,
            'success_url': success_url,
            'cancel_url': cancel_url,
            'client_reference_id': current_user.id,
            'payment_intent_data': {
                'capture_method': 'automatic',
            },
            'metadata': {
                'type': 'books',
                'cart': json.dumps(books)
            }
        }
        
        # Lägg till kundinformation om tillgänglig
        if user_email:
            checkout_session_params['customer_email'] = user_email
            
        # Skapa Stripe Checkout Session
        session_stripe = stripe.checkout.Session.create(**checkout_session_params)
        
        app.logger.debug(f"Stripe session skapad: {session_stripe.id}")
        return jsonify({'sessionId': session_stripe.id})
    except Exception as e:
        app.logger.error(f"Fel vid skapande av bok-köp-session: {e}", exc_info=True)
        return jsonify({'error': f'Ett fel inträffade vid betalning: {str(e)}'}), 500


@app.route('/checkout-success')
@login_required
def checkout_success():
    session['cart'] = {}
    purchase_type = request.args.get('type', 'books')  # Standard till "books" om inget anges
    return render_template('checkout_success.html', purchase_type=purchase_type)


@app.route('/checkout-membership')
@login_required
@limiter.limit("5 per minute")
def checkout_membership():
    try:
        if current_user.membership_active:
            flash("Du har redan ett aktivt medlemskap.", "warning")
            return redirect(url_for('inloggad'))
            
        # Lägg till medlemskap i localStorage och dirigera till checkout-sidan
        # Checkout-sidan kommer automatiskt visa medlemskap i varukorgen
        return redirect(url_for('checkout'))
    except Exception as e:
        app.logger.error(f"Fel vid omdirigering till kassan: {e}")
        flash("Ett fel inträffade vid försök att gå till kassan.", "danger")
        return redirect(url_for('inloggad'))

@app.route('/checkout-cancel')
@login_required
def checkout_cancel():
    return render_template('checkout_cancel.html')

@app.route('/webhook', methods=['POST'])
@csrf.exempt
def stripe_webhook():
    payload = request.get_data(as_text=True)
    sig_header = request.headers.get('Stripe-Signature')
    
    app.logger.debug(f"Stripe webhook mottagen: {request.headers.get('Stripe-Event-Type', 'okänd event-typ')}")
    
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, stripe_webhook_secret)
        app.logger.info(f"Stripe webhook verifierad: {event['type']}")
    except ValueError as e:
        app.logger.error(f"Ogiltig webhook payload: {e}")
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        app.logger.error(f"Ogiltig webhook signatur: {e}")
        return jsonify({'error': 'Invalid signature'}), 400

    if event['type'] == 'checkout.session.completed':
        session_data = event['data']['object']
        mode = session_data.get('mode')
        session_type = session_data.get('metadata', {}).get('type')
        user_id = session_data.get('client_reference_id')
        
        app.logger.info(f"Checkout session completed: mode={mode}, type={session_type}, user_id={user_id}")
        
        if mode == 'subscription' and session_type == 'membership':
            subscription_id = session_data.get('subscription')
            app.logger.info(f"Medlemskap tecknat: user_id={user_id}, subscription_id={subscription_id}")
            
            try:
                with get_db_connection() as conn:
                    update_query = text("""
                        UPDATE users
                        SET subscription_id = :sub_id,
                            membership_active = true
                        WHERE id = :user_id
                    """)
                    result = conn.execute(update_query, {"sub_id": subscription_id, "user_id": user_id})
                    app.logger.info(f"Användare {user_id} medlemskap uppdaterat i databasen, påverkade rader: {result.rowcount}")
            except Exception as db_error:
                app.logger.error(f"Databasfel vid uppdatering av medlemskap för användare {user_id}: {db_error}", exc_info=True)
                
            # Hämta användarens e-post och skicka medlemskapskvittot
            try:
                with get_db_connection() as conn:
                    user_query = text("SELECT email FROM users WHERE id = :user_id")
                    user_row = conn.execute(user_query, {"user_id": user_id}).fetchone()
                
                if user_row:
                    user_email = user_row[0]
                    app.logger.info(f"Skickar medlemskapskvitto till {user_email}")
                    send_membership_receipt_email(user_email, subscription_id, datetime.now())
                else:
                    app.logger.warning(f"Kunde inte hitta e-post för användare {user_id}")
            except Exception as email_error:
                app.logger.error(f"Fel vid sändning av medlemskapskvitto: {email_error}", exc_info=True)

        elif mode == 'payment' and session_type == 'books':
            cart_json = session_data.get('metadata', {}).get('cart', '[]')
            books = json.loads(cart_json)
            purchased_books = []
            total_amount = 0.0
            purchase_date = datetime.now()
            with get_db_connection() as conn:
                for item in books:
                    book_id = item.get('id')
                    purchased_books.append(item.get('title', 'Okänd titel'))
                    total_amount += float(item.get('price', 0))
                    query = text("""
                        INSERT INTO user_books (user_id, book_id, purchase_date)
                        VALUES (:user_id, :book_id, NOW())
                        ON CONFLICT DO NOTHING
                    """)
                    conn.execute(query, {"user_id": user_id, "book_id": book_id})
                transaction_query = text("""
                    INSERT INTO transactions (user_id, total_amount, purchase_date, items, stripe_charge_id)
                    VALUES (:user_id, :total_amount, :purchase_date, :items, :charge_id)
                    RETURNING id
                """)
                items_json = json.dumps(books)
                stripe_charge_id = session_data.get('payment_intent', None)
                conn.execute(transaction_query, {
                    "user_id": user_id,
                    "total_amount": total_amount,
                    "purchase_date": purchase_date,
                    "items": items_json,
                    "charge_id": stripe_charge_id
                })
            print(f"Användare {user_id} köpte böcker: {cart_json}")
            with get_db_connection() as conn:
                user_query = text("SELECT email FROM users WHERE id = :user_id")
                user_row = conn.execute(user_query, {"user_id": user_id}).fetchone()
            if user_row:
                user_email = user_row[0]
                send_receipt_email(user_email, purchased_books, total_amount, purchase_date)
    return jsonify({'status': 'success'}), 200

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'loggain'

@login_manager.user_loader
def load_user(user_id):
    query = text("SELECT id, username, membership_active, created_at FROM users WHERE id = :user_id")
    with get_db_connection() as conn:
        row = conn.execute(query, {"user_id": user_id}).fetchone()
    if row:
        return User(id=row[0], username=row[1], membership_active=row[2], start_date=row[3])
    return None

class User(UserMixin):
    def __init__(self, id, username, membership_active, program_id=None, start_date=None):
        self.id = id
        self.username = username
        self.membership_active = membership_active
        self.start_date = start_date
        # Vi tar fortsatt emot program_id som parameter men använder det inte aktivt
        # för bakåtkompatibilitet (så vi inte behöver uppdatera alla platser som skapar User-objekt)

@app.route('/api/check-membership', methods=['GET'])
@login_required
def check_membership():
    membership_active = current_user.membership_active if current_user.is_authenticated else False
    return jsonify({'membership_active': membership_active})

def send_membership_receipt_email(user_email, subscription_id, purchase_date):
    subject = "Kvitto för ditt medlemskap hos Kunskapslitteratur"
    body = f"""
Hej,

Tack för att du tecknat medlemskap hos Kunskapslitteratur!

Medlemskaps-ID: {subscription_id}
Teckningsdatum: {purchase_date.strftime('%Y-%m-%d %H:%M:%S')}

Du har nu full tillgång till att köpa och använda kurslitteratur.

Med vänlig hälsning,
Kunskapslitteratur
"""
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = os.getenv("SMTP_USER")
        msg["To"] = user_email
        with smtplib.SMTP_SSL(os.getenv("SMTP_SERVER"), int(os.getenv("SMTP_PORT", 465))) as server:
            server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))
            server.sendmail(os.getenv("SMTP_USER"), [user_email], msg.as_string())
        app.logger.info(f"Medlemskaps-kvitto skickat till {user_email}")
    except Exception as e:
        app.logger.error(f"Fel vid sändning av medlemskaps-kvitto: {e}", exc_info=True)

def send_receipt_email(user_email, purchased_books, total_amount, purchase_date):
    subject = "Kvitto för ditt bokköp hos Kunskapslitteratur"
    body = f"""
Hej,

Tack för ditt köp hos Kunskapslitteratur!

Köpdatum: {purchase_date.strftime('%Y-%m-%d %H:%M:%S')}
Inköpta böcker:
{chr(10).join(purchased_books)}

Totalbelopp: {total_amount:.2f} kr

Vi hoppas att du blir nöjd med ditt köp!

Med vänlig hälsning,
Kunskapslitteratur
"""
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = os.getenv("SMTP_USER")
        msg["To"] = user_email
        with smtplib.SMTP_SSL(os.getenv("SMTP_SERVER"), int(os.getenv("SMTP_PORT", 465))) as server:
            server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))
            server.sendmail(os.getenv("SMTP_USER"), [user_email], msg.as_string())
        print(f"Kvitto skickat till {user_email}")
    except Exception as e:
        print(f"Fel vid sändning av kvitto: {e}")

@app.route('/betalningsstatus')
@login_required
def betalningsstatus():
    user_id = current_user.id
    
    with get_db_connection() as conn:
        # Hämta användarens transaktioner med sekventiell numrering
        transactions_query = text("""
            WITH numbered_transactions AS (
                SELECT 
                    t.id,
                    t.user_id,
                    t.purchase_date,
                    t.total_amount,
                    t.items,
                    ROW_NUMBER() OVER (PARTITION BY t.user_id ORDER BY t.purchase_date DESC) as transaction_number
                FROM transactions t
                WHERE t.user_id = :user_id
            )
            SELECT 
                id,
                user_id,
                purchase_date,
                total_amount,
                items,
                CONCAT('Transaktion ', transaction_number) as display_id
            FROM numbered_transactions
            ORDER BY purchase_date DESC
        """)
        transactions = conn.execute(transactions_query, {"user_id": user_id}).fetchall()
        
        # Konvertera transaktioner till dictionary format för template
        transactions_list = []
        for tx in transactions:
            tx_dict = dict(tx._mapping)
            
            # Hantera items beroende på dess typ
            items = tx_dict.get('items')
            if isinstance(items, str):
                try:
                    parsed_items = json.loads(items)
                    # Säkerställ att items är en lista
                    tx_dict['purchased_books'] = parsed_items if isinstance(parsed_items, list) else [parsed_items]
                except json.JSONDecodeError:
                    tx_dict['purchased_books'] = []
            elif isinstance(items, dict):
                # Om items är ett enskilt objekt, lägg det i en lista
                tx_dict['purchased_books'] = [items]
            elif isinstance(items, list):
                tx_dict['purchased_books'] = items
            else:
                tx_dict['purchased_books'] = []
                
            transactions_list.append(tx_dict)
    
    return render_template('betalningsstatus.html', transactions=transactions_list)

@app.route('/mittkonto')
@login_required
def mittkonto():
    user_id = current_user.id
    
    with get_db_connection() as conn:
        # Hämta användarinformation med membership_active från users-tabellen
        user_query = text("""
            SELECT u.id, u.username, u.email, u.first_name, u.last_name, 
                   u.phone, u.address, u.postal_code, u.city,
                   u.membership_active, u.subscription_id, u.created_at
            FROM users u
            WHERE u.id = :user_id
        """)
        user = conn.execute(user_query, {"user_id": user_id}).fetchone()
        
        # Kontrollera att användaren hittades
        if user is None:
            flash("Kunde inte hitta användarinformation.", "danger")
            return redirect(url_for('inloggad'))
        
        # Kontrollera medlemskapsstatus
        membership_active = user.membership_active if user.membership_active is not None else False
        subscription_id = user.subscription_id
        
        # Standardvärden
        membership_expiry = None
        is_cancelling = False
        
        # Om användaren har ett subscription_id (Stripe-prenumeration)
        if subscription_id and membership_active:
            app.logger.debug(f"Försöker hämta Stripe-prenumeration för ID: {subscription_id}")
            
            try:
                # Hämta information från Stripe om prenumerationen
                subscription = stripe.Subscription.retrieve(subscription_id)
                
                # Få nästa faktureringsdatum (i Unix timestamp format)
                next_billing_timestamp = subscription.current_period_end
                
                # Konvertera till datetime
                membership_expiry = datetime.fromtimestamp(next_billing_timestamp)
                
                # Kontrollera om prenumerationen är inställd på att avslutas
                is_cancelling = subscription.cancel_at_period_end
                
                app.logger.debug(f"Stripe-prenumeration status: {subscription.status}, " + 
                                f"avslutad vid periodens slut: {is_cancelling}, " + 
                                f"förnyelsedatum: {membership_expiry}")
                
            except Exception as e:
                app.logger.error(f"Fel vid hämtning av Stripe-prenumeration: {e}", exc_info=True)
                # Fallback om Stripe-anrop misslyckas
                membership_expiry = user.created_at + timedelta(days=30) if user.created_at else datetime.now() + timedelta(days=30)
                app.logger.debug(f"Använder fallback-förnyelsedatum: {membership_expiry}")
        elif membership_active:
            # Fallback för användare med aktivt medlemskap men utan subscription_id
            membership_expiry = user.created_at + timedelta(days=30) if user.created_at else datetime.now() + timedelta(days=30)
    
    return render_template('mittkonto.html', 
                          user=user, 
                          membership_active=membership_active,
                          membership_expiry=membership_expiry,
                          is_cancelling=is_cancelling)


@app.route('/secure-pdf/<path:pdf_path>')
@login_required
def secure_pdf(pdf_path):
    """
    Skyddad åtkomst till PDF-filer.
    Verifierar att användaren äger boken innan den serveras.
    """
    # Kontrollera om användaren har köpt boken med denna pdf_path
    query = text("""
        SELECT 1 FROM user_books ub
        JOIN books b ON b.id = ub.book_id
        WHERE ub.user_id = :user_id 
        AND b.pdf_path = :pdf_path
    """)
    
    with get_db_connection() as conn:
        result = conn.execute(query, {"user_id": current_user.id, "pdf_path": pdf_path}).fetchone()
    
    # Om användaren inte äger boken, returnera ett felmeddelande
    if not result:
        flash("Du har inte tillgång till denna bok. Köp den först för att få åtkomst.", "danger")
        return redirect(url_for('utforskabocker'))
    
    # Kontrollera att användaren har aktivt medlemskap
    if not current_user.membership_active:
        flash("Du behöver ett aktivt medlemskap för att öppna böcker.", "warning")
        return redirect(url_for('inloggad'))
        
    # Användaren äger boken och har aktivt medlemskap, leverera filen
    try:
        # Enkel filöverföring utan extra headers som kan orsaka problem
        app.logger.debug(f"Levererar PDF-fil: {pdf_path}")
        return send_from_directory('static', pdf_path, mimetype='application/pdf')
    except FileNotFoundError:
        app.logger.error(f"PDF-fil hittades inte: {pdf_path}")
        flash("Filen kunde inte hittas. Kontakta support.", "danger")
        return redirect(url_for('my_books'))

@app.route('/view-pdf/<path:pdf_path>')
@login_required
def view_pdf(pdf_path):
    """
    Visa PDF med PDF.js Express Viewer.
    Verifierar att användaren äger boken innan den visas.
    """
    # Kontrollera om användaren har köpt boken med denna pdf_path
    query = text("""
        SELECT b.id, b.title FROM user_books ub
        JOIN books b ON b.id = ub.book_id
        WHERE ub.user_id = :user_id 
        AND b.pdf_path = :pdf_path
    """)
    
    with get_db_connection() as conn:
        result = conn.execute(query, {"user_id": current_user.id, "pdf_path": pdf_path}).fetchone()
    
    # Om användaren inte äger boken, returnera ett felmeddelande
    if not result:
        flash("Du har inte tillgång till denna bok. Köp den först för att få åtkomst.", "danger")
        return redirect(url_for('utforskabocker'))
    
    # Kontrollera att användaren har aktivt medlemskap
    if not current_user.membership_active:
        flash("Du behöver ett aktivt medlemskap för att öppna böcker.", "warning")
        return redirect(url_for('inloggad'))
    
    # Användaren äger boken och har aktivt medlemskap, visa PDF-visaren
    book_id = result[0]
    book_title = result[1]
    pdf_url = url_for('secure_pdf', pdf_path=pdf_path)
    
    # Hämta användarens läsposition för denna bok
    page_position = get_book_position(current_user.id, book_id)
    
    return render_template('pdf_viewer.html', 
                          pdf_url=pdf_url, 
                          book_title=book_title, 
                          book_id=book_id,
                          user_id=current_user.id,
                          page_position=page_position)

@app.route('/update-profile', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def update_profile():
    user_id = current_user.id
    
    # Hämta formulärdata
    first_name = request.form.get('firstName', '').strip()
    last_name = request.form.get('lastName', '').strip()
    phone = request.form.get('phone', '').strip()
    address = request.form.get('address', '').strip()
    postal_code = request.form.get('postalCode', '').strip()
    city = request.form.get('city', '').strip()
    
    # Förbättrad validering av indata
    validation_errors = []
    
    # Validera namn (max 50 tecken, inga siffror eller specialtecken)
    if first_name and (len(first_name) > 50 or not first_name.replace(" ", "").replace("-", "").isalpha()):
        validation_errors.append("Förnamn får endast innehålla bokstäver och bindestreck (max 50 tecken).")
        
    if last_name and (len(last_name) > 50 or not last_name.replace(" ", "").replace("-", "").isalpha()):
        validation_errors.append("Efternamn får endast innehålla bokstäver och bindestreck (max 50 tecken).")
    
    # Validera telefonnummer (endast siffror, +, -, och mellanslag)
    import re
    if phone and not re.match(r'^[0-9+\-\s]{5,20}$', phone):
        validation_errors.append("Ogiltigt telefonnummer. Använd endast siffror, +, - och mellanslag.")
    
    # Validera adress (max 100 tecken)
    if address and len(address) > 100:
        validation_errors.append("Adressen får inte överstiga 100 tecken.")
    
    # Validera postnummer (endast siffror och mellanslag)
    if postal_code and not re.match(r'^[0-9\s]{5,10}$', postal_code):
        validation_errors.append("Ogiltigt postnummer. Använd formatet 123 45.")
    
    # Validera stad (max 50 tecken, inga siffror eller specialtecken)
    if city and (len(city) > 50 or not city.replace(" ", "").replace("-", "").isalpha()):
        validation_errors.append("Stad får endast innehålla bokstäver och bindestreck (max 50 tecken).")
    
    # Kontrollera om det är en AJAX-förfrågan
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    # Om det finns valideringsfel, returnera dem
    if validation_errors:
        app.logger.warning(f"Valideringsfel för användare {user_id}: {', '.join(validation_errors)}")
        error_message = "Formuläret innehåller felaktiga värden. Kontrollera och försök igen."
        
        if is_ajax:
            return jsonify({
                "success": False,
                "message": error_message,
                "validation_errors": validation_errors
            })
        else:
            for error in validation_errors:
                flash(error, "danger")
            return redirect(url_for('mittkonto'))
    
    # Loggning för att diagnostisera problemet
    app.logger.info(f"Uppdateringsförsök för användare {user_id}: {first_name} {last_name}, {phone}, {address}, {postal_code}, {city}")
    
    try:
        with get_db_connection() as conn:
            # Uppdatera användarinformation
            update_query = text("""
                UPDATE users 
                SET first_name = :first_name, 
                    last_name = :last_name, 
                    phone = :phone, 
                    address = :address, 
                    postal_code = :postal_code, 
                    city = :city
                WHERE id = :user_id
            """)
            
            result = conn.execute(update_query, {
                "first_name": first_name,
                "last_name": last_name,
                "phone": phone,
                "address": address,
                "postal_code": postal_code,
                "city": city,
                "user_id": user_id
            })
            
            # Loggning för att bekräfta uppdateringen
            app.logger.info(f"SQL UPDATE resultat: {result.rowcount} rader påverkade")
            
            # Explicit commit för att säkerställa att ändringarna sparas i databasen
            conn.commit()
            app.logger.info("Commit genomförd")
            
            # Skapa framgångsmeddelande
            success_message = "Din profilinformation har uppdaterats!"
            
            if is_ajax:
                return jsonify({
                    "success": True,
                    "message": success_message
                })
            else:
                flash(success_message, "success")
                
    except Exception as e:
        app.logger.error(f"Fel vid uppdatering av profil: {e}")
        # Mer detaljerad felloggning
        import traceback
        app.logger.error(f"Detaljerad felbeskrivning: {traceback.format_exc()}")
        
        error_message = "Ett fel uppstod vid uppdatering av din profil. Försök igen."
        
        if is_ajax:
            return jsonify({
                "success": False,
                "message": error_message
            })
        else:
            flash(error_message, "danger")
    
    if is_ajax:
        # Detta bör aldrig nås om allt går som det ska, men för säkerhets skull
        return jsonify({
            "success": False,
            "message": "Ett oväntat fel uppstod."
        })
    else:
        return redirect(url_for('mittkonto'))

@app.route('/check_username')
@limiter.limit("20 per minute")
def check_username():
    username_to_check = request.args.get('username', '').strip().lower()
    if not username_to_check:
        return jsonify({"used": False})
    with get_db_connection() as conn:
        query = text("SELECT id FROM users WHERE LOWER(username) = :username LIMIT 1")
        result = conn.execute(query, {"username": username_to_check}).fetchone()
    return jsonify({"used": True}) if result else jsonify({"used": False})

@app.route('/cancel-membership', methods=['POST'])
@login_required
@limiter.limit("3 per minute")
@csrf.exempt
def cancel_membership():
    app.logger.info(f"Användare {current_user.id} försöker avsluta medlemskap")
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    try:
        # Hämta användarens subscription_id från databasen
        with get_db_connection() as conn:
            query = text("SELECT subscription_id FROM users WHERE id = :user_id")
            result = conn.execute(query, {"user_id": current_user.id}).fetchone()
            
            if not result or not result[0]:
                app.logger.warning(f"Inget subscription_id hittat för användare {current_user.id}")
                if is_ajax:
                    return jsonify({
                        'success': False,
                        'message': 'Inget aktivt medlemskap hittades.'
                    }), 400
                else:
                    flash('Inget aktivt medlemskap hittades.', 'danger')
                    return redirect(url_for('mittkonto'))
            
            subscription_id = result[0]
        
        app.logger.debug(f"Försöker avsluta Stripe-prenumeration {subscription_id} för användare {current_user.id}")
        
        # Hämta prenumerationen från Stripe för att få current_period_end
        subscription = stripe.Subscription.retrieve(subscription_id)
        
        # Avsluta prenumerationen vid periodens slut (cancel_at_period_end=True)
        stripe.Subscription.modify(
            subscription_id,
            cancel_at_period_end=True
        )
        
        # Hämta slutdatum för den aktuella perioden 
        current_period_end = subscription.current_period_end
        active_until_date = datetime.fromtimestamp(current_period_end)
        formatted_date = active_until_date.strftime('%Y-%m-%d')
        
        app.logger.info(f"Medlemskap för användare {current_user.id} avslutat, aktivt till {formatted_date}")
        
        # Skicka bekräftelsemail
        try:
            with get_db_connection() as conn:
                user_query = text("SELECT email FROM users WHERE id = :user_id")
                user_row = conn.execute(user_query, {"user_id": current_user.id}).fetchone()
                
                if user_row:
                    user_email = user_row[0]
                    app.logger.info(f"Skickar bekräftelse på avslutat medlemskap till {user_email}")
                    send_membership_cancellation_email(user_email, formatted_date)
        except Exception as email_error:
            app.logger.error(f"Fel vid sändning av bekräftelse på avslutat medlemskap: {email_error}", exc_info=True)
        
        if is_ajax:
            return jsonify({
                'success': True,
                'message': f'Ditt medlemskap har avslutats och kommer att vara aktivt till {formatted_date}.',
                'active_until': formatted_date
            })
        else:
            flash(f'Ditt medlemskap har avslutats och kommer att vara aktivt till {formatted_date}.', 'success')
            return redirect(url_for('mittkonto'))
            
    except Exception as e:
        app.logger.error(f"Fel vid avslutning av medlemskap för användare {current_user.id}: {e}", exc_info=True)
        
        if is_ajax:
            return jsonify({
                'success': False,
                'message': 'Ett fel uppstod vid avslutning av medlemskapet. Vänligen försök igen senare.'
            }), 500
        else:
            flash('Ett fel uppstod vid avslutning av medlemskapet. Vänligen försök igen senare.', 'danger')
            return redirect(url_for('mittkonto'))

def send_membership_cancellation_email(user_email, end_date):
    subject = "Bekräftelse på avslutat medlemskap hos Kunskapslitteratur"
    body = f"""
Hej,

Vi bekräftar att ditt medlemskap hos Kunskapslitteratur har avslutats.

Ditt medlemskap förblir aktivt till och med {end_date}. Efter detta datum kommer du inte längre ha tillgång till dina köpta böcker.

Om du ångrar dig och vill återaktivera ditt medlemskap kan du göra det när som helst genom att logga in på ditt konto.

Med vänlig hälsning,
Kunskapslitteratur
"""
    try:
        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = os.getenv("SMTP_USER")
        msg["To"] = user_email
        with smtplib.SMTP_SSL(os.getenv("SMTP_SERVER"), int(os.getenv("SMTP_PORT", 465))) as server:
            server.login(os.getenv("SMTP_USER"), os.getenv("SMTP_PASSWORD"))
            server.sendmail(os.getenv("SMTP_USER"), [user_email], msg.as_string())
        app.logger.info(f"Bekräftelse på avslutat medlemskap skickat till {user_email}")
    except Exception as e:
        app.logger.error(f"Fel vid sändning av bekräftelse på avslutat medlemskap: {e}", exc_info=True)

@app.route('/update-password', methods=['POST'])
@login_required
@limiter.limit("5 per minute")
def update_password():
    user_id = current_user.id
    
    # Hämta formulärdata
    current_password = request.form.get('currentPassword', '').strip()
    new_password = request.form.get('newPassword', '').strip()
    confirm_password = request.form.get('confirmPassword', '').strip()
    
    # Kontrollera om det är en AJAX-förfrågan
    is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'
    
    # Validering av indata
    validation_errors = []
    
    if not current_password:
        validation_errors.append("Ange ditt nuvarande lösenord")
    
    if not new_password:
        validation_errors.append("Ange ett nytt lösenord")
    
    if not confirm_password:
        validation_errors.append("Bekräfta ditt nya lösenord")
    
    if new_password and confirm_password and new_password != confirm_password:
        validation_errors.append("Lösenorden matchar inte")
    
    # Kontrollera lösenordskrav (minst 8 tecken, minst 1 stor bokstav, minst 1 siffra)
    if new_password and not re.match(r'^(?=.*[A-Z])(?=.*\d).{8,}$', new_password):
        validation_errors.append("Lösenordet måste vara minst 8 tecken långt, innehålla minst en stor bokstav och en siffra")
    
    # Om det finns valideringsfel, returnera dem
    if validation_errors:
        app.logger.warning(f"Valideringsfel för lösenordsuppdatering (användare {user_id}): {', '.join(validation_errors)}")
        error_message = "Formuläret innehåller felaktiga värden. Kontrollera och försök igen."
        
        if is_ajax:
            return jsonify({
                "success": False,
                "message": error_message,
                "validation_errors": validation_errors
            })
        else:
            for error in validation_errors:
                flash(error, "danger")
            return redirect(url_for('mittkonto'))
    
    try:
        # Hämta användarens nuvarande lösenordshash
        with get_db_connection() as conn:
            query = text("SELECT password FROM users WHERE id = :user_id")
            result = conn.execute(query, {"user_id": user_id}).fetchone()
            
            if not result:
                app.logger.error(f"Kunde inte hitta användare {user_id} i databasen vid lösenordsuppdatering")
                error_message = "Ett fel uppstod vid uppdatering av lösenordet. Användaren kunde inte hittas."
                
                if is_ajax:
                    return jsonify({
                        "success": False,
                        "message": error_message
                    })
                else:
                    flash(error_message, "danger")
                    return redirect(url_for('mittkonto'))
            
            current_password_hash = result[0]
            
            # Verifiera nuvarande lösenord
            if not check_password_hash(current_password_hash, current_password):
                app.logger.warning(f"Felaktigt nuvarande lösenord angivet för användare {user_id}")
                error_message = "Det nuvarande lösenordet är felaktigt"
                
                if is_ajax:
                    return jsonify({
                        "success": False,
                        "message": error_message,
                        "validation_errors": ["Det nuvarande lösenordet är felaktigt"]
                    })
                else:
                    flash(error_message, "danger")
                    return redirect(url_for('mittkonto'))
            
            # Kontrollera att nya lösenordet inte är samma som det nuvarande
            if check_password_hash(current_password_hash, new_password):
                app.logger.warning(f"Användare {user_id} försökte sätta samma lösenord som tidigare")
                error_message = "Det nya lösenordet måste vara annorlunda från ditt nuvarande lösenord"
                
                if is_ajax:
                    return jsonify({
                        "success": False,
                        "message": error_message,
                        "validation_errors": ["Det nya lösenordet måste vara annorlunda från ditt nuvarande lösenord"]
                    })
                else:
                    flash(error_message, "danger")
                    return redirect(url_for('mittkonto'))
            
            # Generera nytt lösenordshash
            new_password_hash = generate_password_hash(new_password)
            
            # Uppdatera lösenordet
            update_query = text("UPDATE users SET password = :password WHERE id = :user_id")
            conn.execute(update_query, {"password": new_password_hash, "user_id": user_id})
            conn.commit()
            
            app.logger.info(f"Lösenord uppdaterat för användare {user_id}")
            success_message = "Ditt lösenord har uppdaterats!"
            
            if is_ajax:
                return jsonify({
                    "success": True,
                    "message": success_message
                })
            else:
                flash(success_message, "success")
                return redirect(url_for('mittkonto'))
            
    except Exception as e:
        app.logger.error(f"Fel vid uppdatering av lösenord för användare {user_id}: {e}")
        import traceback
        app.logger.error(f"Detaljerad felbeskrivning: {traceback.format_exc()}")
        
        error_message = "Ett fel uppstod vid uppdatering av lösenordet. Försök igen senare."
        
        if is_ajax:
            return jsonify({
                "success": False,
                "message": error_message
            })
        else:
            flash(error_message, "danger")
            return redirect(url_for('mittkonto'))

# Funktioner för att hantera unika sessioner per användare
def save_active_session(user_id, session_id):
    """Sparar den aktiva sessionen för en användare i Redis"""
    key = f"active_session:{user_id}"
    # Hämta tidigare session om den finns
    previous_session = redis_client.get(key)
    if previous_session:
        previous_session = previous_session.decode('utf-8')
        if previous_session != session_id:
            # Skicka en utloggningssignal till den tidigare sessionen via WebSocket
            socketio.emit('force_logout', {'message': 'Du har loggats ut eftersom någon annan loggade in på ditt konto.'}, room=previous_session)
    
    # Spara den nya sessionen
    redis_client.set(key, session_id)

def get_active_session(user_id):
    """Hämtar den aktiva sessionen för en användare från Redis"""
    key = f"active_session:{user_id}"
    session_id = redis_client.get(key)
    if session_id:
        return session_id.decode('utf-8')
    return None

def invalidate_session(user_id, current_session_id=None):
    """Markerar en session som ogiltig i Redis"""
    key = f"active_session:{user_id}"
    active_session = redis_client.get(key)
    
    # Om det finns en aktiv session och den inte är den nuvarande
    if active_session:
        active_session = active_session.decode('utf-8')
        if current_session_id is None or active_session != current_session_id:
            # Markera den tidigare sessionen som ogiltig
            invalid_key = f"invalid_session:{active_session}"
            redis_client.set(invalid_key, "1")
            redis_client.expire(invalid_key, 3600)  # Sätt en TTL på 1 timme
            
            # Skicka en utloggningssignal till den tidigare sessionen via WebSocket
            socketio.emit('force_logout', {'message': 'Du har loggats ut eftersom någon annan loggade in på ditt konto.'}, room=active_session)
            
            return True
    return False

def is_session_invalid(session_id):
    """Kontrollerar om en session har markerats som ogiltig"""
    key = f"invalid_session:{session_id}"
    return redis_client.exists(key)

# Funktioner för att hantera läsposition för böcker
def save_book_position(user_id, book_id, page):
    """Sparar läspositionen för en bok i Redis"""
    key = f"book_position:{user_id}:{book_id}"
    redis_client.set(key, str(page))
    # Sätt en TTL på 1 år (samma som bokens giltighetstid)
    redis_client.expire(key, 31536000)  # 60*60*24*365 sekunder = 1 år

def get_book_position(user_id, book_id):
    """Hämtar läspositionen för en bok från Redis"""
    key = f"book_position:{user_id}:{book_id}"
    position = redis_client.get(key)
    if position:
        return int(position.decode('utf-8'))
    return 1  # Standardvärde: första sidan

# API-endpoints för att spara och hämta läsposition
@app.route('/api/save-book-position', methods=['POST'])
@login_required
def save_book_position_api():
    """API för att spara läsposition för en bok"""
    if not request.is_json:
        return jsonify({"error": "Förfrågan måste vara i JSON-format"}), 400
    
    data = request.get_json()
    book_id = data.get('book_id')
    page = data.get('page')
    
    if not book_id or not page:
        return jsonify({"error": "book_id och page krävs"}), 400
    
    try:
        page = int(page)
        book_id = int(book_id)
    except ValueError:
        return jsonify({"error": "book_id och page måste vara heltal"}), 400
    
    # Kontrollera att användaren äger boken
    query = text("""
        SELECT 1 FROM user_books
        WHERE user_id = :user_id AND book_id = :book_id
    """)
    
    with get_db_connection() as conn:
        result = conn.execute(query, {"user_id": current_user.id, "book_id": book_id}).fetchone()
    
    if not result:
        return jsonify({"error": "Du har inte tillgång till denna bok"}), 403
    
    # Spara läspositionen
    save_book_position(current_user.id, book_id, page)
    
    return jsonify({"success": True}), 200

@app.route('/api/get-book-position/<int:book_id>', methods=['GET'])
@login_required
def get_book_position_api(book_id):
    """API för att hämta läsposition för en bok"""
    # Kontrollera att användaren äger boken
    query = text("""
        SELECT 1 FROM user_books
        WHERE user_id = :user_id AND book_id = :book_id
    """)
    
    with get_db_connection() as conn:
        result = conn.execute(query, {"user_id": current_user.id, "book_id": book_id}).fetchone()
    
    if not result:
        return jsonify({"error": "Du har inte tillgång till denna bok"}), 403
    
    # Hämta läspositionen
    position = get_book_position(current_user.id, book_id)
    
    return jsonify({"page": position}), 200

# WebSocket-hanterare
@socketio.on('connect')
def handle_connect():
    """Hantera WebSocket-anslutning"""
    if current_user.is_authenticated and 'unique_session_id' in session:
        # Anslut användaren till en rum med deras unika session-ID
        join_room(session['unique_session_id'])
        app.logger.debug(f"WebSocket ansluten för användare {current_user.id}, session {session['unique_session_id']}")

@socketio.on('disconnect')
def handle_disconnect():
    """Hantera WebSocket-frånkoppling"""
    if current_user.is_authenticated and 'unique_session_id' in session:
        # Lämna rummet när användaren kopplar från
        leave_room(session['unique_session_id'])
        app.logger.debug(f"WebSocket frånkopplad för användare {current_user.id}, session {session['unique_session_id']}")

if __name__ == '__main__':
    socketio.run(app, debug=True)
