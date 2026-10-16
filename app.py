import os, re, json, secrets, hashlib, smtplib, mimetypes
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from uuid import uuid4
from functools import wraps
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, abort, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text as sql_text
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / 'static' / 'uploads'
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
app = Flask(__name__, template_folder=str(BASE_DIR))
# A stable development fallback keeps sessions consistent across local worker processes.
# Production deployments must set SECRET_KEY in the hosting dashboard.
APP_ENV = os.getenv('APP_ENV', 'development').strip().lower()
_secret_key = os.getenv('SECRET_KEY', '').strip()
if not _secret_key and APP_ENV in ('production', 'prod'):
    raise RuntimeError('SECRET_KEY must be configured in production environment variables.')
app.config['SECRET_KEY'] = _secret_key or 'nexora-local-development-only-change-before-deploy'
if not _secret_key:
    app.logger.warning('Using development SECRET_KEY. Set a long random SECRET_KEY before deployment.')
app.config['MAX_CONTENT_LENGTH'] = 45 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.getenv('COOKIE_SECURE', 'true' if APP_ENV in ('production', 'prod') else 'false').lower() == 'true'
app.permanent_session_lifetime = timedelta(days=14)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
url = os.getenv('DATABASE_URL', 'sqlite:///' + str(BASE_DIR / 'nexora.db'))
if url.startswith('postgres://'):
    url = 'postgresql://' + url[len('postgres://'):]
if url.startswith('postgresql://') and '+psycopg' not in url:
    url = url.replace('postgresql://', 'postgresql+psycopg://', 1)
app.config['SQLALCHEMY_DATABASE_URI'] = url

db = SQLAlchemy(app)


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    username = db.Column(db.String(24), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    verification_hash = db.Column(db.String(64))
    verification_expires = db.Column(db.DateTime)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    verified_badge = db.Column(db.Boolean, default=False, nullable=False)
    premium_until = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    profile = db.relationship('Profile', backref='user', uselist=False, cascade='all, delete-orphan')

class Profile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True, nullable=False)
    data = db.Column(db.Text, default='{}', nullable=False)
    views = db.Column(db.Integer, default=0, nullable=False)
    clicks = db.Column(db.Integer, default=0, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

class Theme(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(60), nullable=False)
    description = db.Column(db.String(300), default='')
    visual = db.Column(db.Text, default='{}')
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    author = db.relationship('User')

class PromoCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(48), unique=True, nullable=False, index=True)
    reward_days = db.Column(db.Integer, default=30, nullable=False)
    max_uses = db.Column(db.Integer, default=1, nullable=False)
    uses = db.Column(db.Integer, default=0, nullable=False)
    expires_at = db.Column(db.DateTime)
    active = db.Column(db.Boolean, default=True, nullable=False)

class PromoUse(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    promo_id = db.Column(db.Integer, db.ForeignKey('promo_code.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    __table_args__ = (db.UniqueConstraint('promo_id', 'user_id', name='unique_promo_per_user'),)

with app.app_context():
    db.create_all()
    owner_email = os.getenv('OWNER_EMAIL', '').strip().lower()
    if owner_email:
        owner = User.query.filter_by(email=owner_email).first()
        if owner and not owner.is_admin:
            owner.is_admin = True
            db.session.commit()


def error(message, status=400):
    return jsonify({'error': message}), status

def current_user():
    uid = session.get('user_id')
    return db.session.get(User, uid) if uid else None

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user(): return error('Сначала войди в аккаунт.', 401)
        return fn(*args, **kwargs)
    return wrapper

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        u = current_user()
        if not u or not u.is_admin: return error('Доступ только владельцу NEXORA.', 403)
        return fn(*args, **kwargs)
    return wrapper

def premium_active(u):
    return bool(u.premium_until and u.premium_until > utcnow())

def public_user(u):
    return {'id': u.id, 'username': u.username, 'email': u.email, 'email_verified': u.email_verified,
            'is_admin': u.is_admin, 'verified_badge': u.verified_badge, 'premium': premium_active(u),
            'premium_until': u.premium_until.isoformat() if u.premium_until else None}

def get_profile(u):
    if not u.profile:
        p = Profile(user_id=u.id, data='{}'); db.session.add(p); db.session.commit(); return {}
    try: return json.loads(u.profile.data or '{}')
    except (ValueError, TypeError): return {}

def save_profile(u, data):
    if not isinstance(data, dict): raise ValueError('Неверный формат профиля.')
    data = dict(data)
    # Server owns these entitlements. Client-provided badge IDs are never trusted.
    requested = data.get('selectedBadges', [])
    if not isinstance(requested, list): requested = []
    allowed = {'creator'} if u.is_admin else set()
    if u.verified_badge: allowed.add('verified')
    if premium_active(u): allowed.update({'silver', 'diamond', 'star', 'orbit'})
    data['selectedBadges'] = [x for x in requested if x in allowed]
    data['name'] = str(data.get('name', ''))[:40]
    data['nick'] = str(data.get('nick', '')).lstrip('@')[:24]
    data['bio'] = str(data.get('bio', ''))[:240]
    data['trackName'] = str(data.get('trackName', ''))[:70]
    allowed_fonts = {'', 'font-serif', 'font-mono', 'font-italic', 'font-wide'}
    data['font'] = data.get('font', '') if data.get('font', '') in allowed_fonts else ''
    data['lang'] = data.get('lang', 'ru') if data.get('lang') in {'ru','en','uk'} else 'ru'
    effects = data.get('effectState', {})
    if not isinstance(effects, dict): effects = {}
    data['effectState'] = {k: bool(effects.get(k, False)) for k in ('snow','glow','rainbow','blink')}
    allowed_types = {'telegram','tiktok','discord','instagram','youtube','twitch','github','website','x','custom'}
    clean_links = []
    for item in data.get('links', [])[:20] if isinstance(data.get('links'), list) else []:
        if not isinstance(item, dict): continue
        kind = item.get('type', 'custom')
        clean_links.append({'id': str(item.get('id',''))[:64], 'type': kind if kind in allowed_types else 'custom', 'url': str(item.get('url','')).strip()[:300]})
    data['links'] = clean_links
    import re as _re
    for field in ('avatarData','coverData'):
        value = data.get(field, '')
        if not isinstance(value, str) or (value and (len(value) > 7_000_000 or not _re.fullmatch(r'data:image/(?:png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+', value))):
            data[field] = ''
    for field in ('avatarVideoUrl','backgroundVideoUrl','musicUrl'):
        value = data.get(field, '')
        if not isinstance(value, str) or (value and not _re.fullmatch(r'/uploads/[A-Za-z0-9_.-]{1,180}', value)):
            data[field] = ''
    if not u.profile:
        u.profile = Profile(data=json.dumps(data, ensure_ascii=False))
        db.session.add(u.profile)
    else: u.profile.data = json.dumps(data, ensure_ascii=False)
    db.session.commit()
    return data


def send_verification(email, code):
    import os
    import json
    import urllib.request
    import urllib.error

    api_key = os.getenv("RESEND_API_KEY")
    sender = os.getenv("RESEND_FROM", "onboarding@resend.dev")

    if not api_key:
        app.logger.error("RESEND_API_KEY is not configured")
        return False

    payload = {
        "from": sender,
        "to": [email],
        "subject": "Your NEXORA verification code",
        "text": (
            f"Your NEXORA verification code is: {code}\n\n"
            "It expires in 15 minutes. "
            "If you did not request it, ignore this email."
         ),
    }

    request = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "NEXORA/1.0",
        },
        method="POST",
    )

    try:
        
        with urllib.request.urlopen(request, timeout=20) as response:
            app.logger.info("Resend accepted verification email")
            return 200 <= response.status < 300
    except urllib.error.HTTPError as error:
        details = error.read().decode("utf-8", errors="replace")
        app.logger.error(
            "Resend email failed: HTTP %s: %s",
            error.code, details
        )
        return False
    except Exception:
        app.logger.exception("Resend email request failed")
        return False
        
@app.get('/')
def index():
    return render_template('index.html')

@app.get('/health')
def health():
    try: db.session.execute(sql_text('SELECT 1'))
    except Exception: return jsonify({'status':'error','database':'unavailable'}), 503
    return jsonify({'status':'ok','database':'connected'})

@app.post('/api/auth/register')
def register():
    d = request.get_json(silent=True) or {}
    email = str(d.get('email','')).strip().lower(); username = str(d.get('username','')).strip().lstrip('@'); password = str(d.get('password',''))
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) or len(email)>254: return error('Укажи корректный email.')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,24}', username): return error('Никнейм: 3–24 символа, латиница, цифры, точка, дефис или _.')
    if len(password)<10 or len(password)>128: return error('Пароль должен быть длиной от 10 до 128 символов.')
    if User.query.filter_by(email=email).first(): return error('Этот email уже зарегистрирован.')
    if User.query.filter(db.func.lower(User.username)==username.lower()).first(): return error('Этот никнейм уже занят.')
    code = f'{secrets.randbelow(1000000):06d}'
    u = User(email=email, username=username, password_hash=generate_password_hash(password), verification_hash=hashlib.sha256(code.encode()).hexdigest(), verification_expires=utcnow()+timedelta(minutes=15))
    u.profile = Profile(data='{}')
    owner_email = os.getenv('OWNER_EMAIL','').strip().lower()
    if owner_email and email == owner_email: u.is_admin = True
    db.session.add(u); db.session.commit()
    if not send_verification(email, code):
        db.session.delete(u); db.session.commit()
        return error('Не удалось отправить письмо. Проверь SMTP-настройки сервера и попробуй снова.', 503)
    return jsonify({'ok':True,'message':'Код отправлен на email. Введи его и нажми «Подтвердить email».'}), 201

@app.post('/api/auth/verify')
def verify():
    d=request.get_json(silent=True) or {}; email=str(d.get('email','')).strip().lower(); code=str(d.get('code','')).strip()
    u=User.query.filter_by(email=email).first()
    if not u or not u.verification_hash or not u.verification_expires or u.verification_expires < utcnow(): return error('Код неверный или срок его действия истёк.')
    if not secrets.compare_digest(u.verification_hash, hashlib.sha256(code.encode()).hexdigest()): return error('Неверный код подтверждения.')
    u.email_verified=True; u.verification_hash=None; u.verification_expires=None; db.session.commit()
    return jsonify({'ok':True,'message':'Email подтверждён. Теперь войди в аккаунт.'})

@app.post('/api/auth/login')
def login():
    d=request.get_json(silent=True) or {}; email=str(d.get('email','')).strip().lower(); password=str(d.get('password',''))
    u=User.query.filter_by(email=email).first()
    if not u or not check_password_hash(u.password_hash,password): return error('Неверный email или пароль.', 401)
    if not u.email_verified: return error('Сначала подтверди email кодом из письма.', 403)
    session.clear(); session['user_id']=u.id; session.permanent=True
    app.permanent_session_lifetime=timedelta(days=14)
    return jsonify({'ok':True,'user':public_user(u)})

@app.post('/api/auth/logout')
def logout(): session.clear(); return jsonify({'ok':True})
@app.get('/api/auth/me')
def me():
    u=current_user(); return jsonify({'user':public_user(u) if u else None})

@app.route('/api/profile', methods=['GET','PUT'])
@login_required
def profile_api():
    u=current_user()
    if request.method=='GET': return jsonify({'profile':get_profile(u),'public_url':url_for('public_profile', username=u.username, _external=True)})
    d=request.get_json(silent=True) or {}
    try: data=save_profile(u,d.get('profile',{}))
    except ValueError as e: return error(str(e))
    return jsonify({'ok':True,'profile':data,'public_url':url_for('public_profile', username=u.username, _external=True)})

@app.post('/api/media')
@login_required
def upload_media():
    f=request.files.get('file'); kind=request.form.get('kind','')
    if not f: return error('Файл не получен.')
    if kind not in ('avatar_video','background_video','audio'): return error('Неизвестный тип файла.')
    ext=Path(secure_filename(f.filename or '')).suffix.lower()
    allowed={'.mp4','.webm','.mov'} if kind != 'audio' else {'.mp3','.m4a','.aac','.ogg','.wav','.flac'}
    if ext not in allowed: return error('Недопустимый формат файла.')
    data=f.read()
    limit=25*1024*1024 if kind=='audio' else 28*1024*1024
    if len(data)>limit: return error('Файл превышает лимит размера.')
    name=f'{current_user().id}_{uuid4().hex}{ext}'
    (UPLOAD_DIR/name).write_bytes(data)
    return jsonify({'ok':True,'url':url_for('uploaded_media', filename=name)})

@app.get('/uploads/<path:filename>')
def uploaded_media(filename):
    # Only files created by the app are served from the fixed upload directory.
    return send_from_directory(UPLOAD_DIR, filename, conditional=True)

@app.get('/api/analytics')
@login_required
def analytics():
    u=current_user(); p=u.profile
    return jsonify({'views':p.views if p else 0,'clicks':p.clicks if p else 0})

@app.route('/api/themes', methods=['GET','POST'])
def themes_api():
    if request.method=='GET':
        items=Theme.query.order_by(Theme.created_at.desc()).limit(100).all()
        return jsonify({'themes':[{'id':t.id,'name':t.name,'description':t.description,'author':t.author.username,'visual':json.loads(t.visual or '{}')} for t in items]})
    u=current_user()
    if not u: return error('Войди, чтобы публиковать темы.',401)
    d=request.get_json(silent=True) or {}; name=str(d.get('name','')).strip(); desc=str(d.get('description','')).strip()
    if not name or len(name)>60 or len(desc)>300: return error('Проверь название и описание темы.')
    visual=d.get('visual',{})
    if not isinstance(visual,dict): visual={}
    t=Theme(user_id=u.id,name=name,description=desc,visual=json.dumps(visual,ensure_ascii=False)); db.session.add(t); db.session.commit()
    return jsonify({'ok':True,'id':t.id}),201

@app.post('/api/promo/redeem')
@login_required
def redeem_promo():
    u=current_user(); d=request.get_json(silent=True) or {}; code=str(d.get('code','')).strip().upper()
    p=PromoCode.query.filter_by(code=code,active=True).first()
    if not p: return error('Промокод не найден или отключён.')
    if p.expires_at and p.expires_at < utcnow(): return error('Срок действия промокода истёк.')
    if p.uses>=p.max_uses: return error('Лимит активаций промокода исчерпан.')
    if PromoUse.query.filter_by(promo_id=p.id,user_id=u.id).first(): return error('Ты уже активировал этот промокод.')
    base=u.premium_until if u.premium_until and u.premium_until>utcnow() else utcnow()
    u.premium_until=base+timedelta(days=p.reward_days); p.uses+=1; db.session.add(PromoUse(promo_id=p.id,user_id=u.id)); db.session.commit()
    return jsonify({'ok':True,'premium_until':u.premium_until.isoformat(),'message':f'Premium активирован на {p.reward_days} дней.'})

@app.get('/u/<username>')
def public_profile(username):
    u=User.query.filter(db.func.lower(User.username)==username.lower(), User.email_verified.is_(True)).first_or_404()
    p=u.profile
    if p: p.views+=1; db.session.commit()
    try: data=json.loads(p.data or '{}') if p else {}
    except ValueError: data={}
    data['selectedBadges'] = [b for b in data.get('selectedBadges',[]) if b not in ('verified','creator','silver','diamond','star','orbit')]
    if u.verified_badge: data['selectedBadges'].append('verified')
    if u.is_admin: data['selectedBadges'].append('creator')
    if premium_active(u): data['selectedBadges'] += [b for b in json.loads(p.data or '{}').get('selectedBadges',[]) if b in ('silver','diamond','star','orbit')] if p else []
    data['selectedBadges']=list(dict.fromkeys(data['selectedBadges']))
    return render_template('public_profile.html', user=u, profile=data)

@app.get('/go/<username>/<int:index>')
def track_link(username,index):
    u=User.query.filter(db.func.lower(User.username)==username.lower(),User.email_verified.is_(True)).first_or_404()
    data=get_profile(u); links=data.get('links',[])
    valid=[x for x in links if isinstance(x,dict) and str(x.get('url','')).strip()]
    if index<0 or index>=len(valid): abort(404)
    item=valid[index]; raw=str(item.get('url','')).strip(); typ=str(item.get('type','custom'))
    prefixes={'telegram':'https://t.me/','tiktok':'https://tiktok.com/@','discord':'https://discord.com/users/','instagram':'https://instagram.com/','youtube':'https://youtube.com/','twitch':'https://twitch.tv/','github':'https://github.com/','website':'https://','x':'https://x.com/','custom':'https://'}
    target=raw if raw.startswith(('https://','http://')) else prefixes.get(typ,'https://')+raw.lstrip('@')
    if not target.startswith(('https://','http://')): abort(400)
    if u.profile: u.profile.clicks+=1; db.session.commit()
    return redirect(target, code=302)

@app.get('/admin')
def admin_page():
    u=current_user()
    if not u: return redirect(url_for('index')+'?admin=login')
    if not u.is_admin: abort(403)
    users=User.query.order_by(User.created_at.desc()).limit(200).all()
    promos=PromoCode.query.order_by(PromoCode.id.desc()).all()
    return render_template('admin.html', user=u, users=users, promos=promos)

@app.post('/admin/promo')
def admin_create_promo():
    u=current_user()
    if not u or not u.is_admin: abort(403)
    code=re.sub(r'[^A-Z0-9_-]','',str(request.form.get('code','')).upper())[:48]
    try: days=int(request.form.get('days','30')); max_uses=int(request.form.get('max_uses','1'))
    except ValueError: abort(400)
    if not code or not 1<=days<=3650 or not 1<=max_uses<=100000: abort(400)
    if PromoCode.query.filter_by(code=code).first(): abort(400, 'Промокод уже существует')
    expires_raw=request.form.get('expires','').strip(); expires=None
    if expires_raw:
        try: expires=datetime.fromisoformat(expires_raw)
        except ValueError: abort(400)
    db.session.add(PromoCode(code=code,reward_days=days,max_uses=max_uses,expires_at=expires)); db.session.commit()
    return redirect(url_for('admin_page'))

@app.post('/admin/user/<int:user_id>')
def admin_update_user(user_id):
    owner=current_user()
    if not owner or not owner.is_admin: abort(403)
    u=db.session.get(User,user_id)
    if not u: abort(404)
    action=request.form.get('action')
    if action=='verify': u.verified_badge=True
    elif action=='unverify': u.verified_badge=False
    elif action=='premium30':
        base=u.premium_until if u.premium_until and u.premium_until>utcnow() else utcnow(); u.premium_until=base+timedelta(days=30)
    elif action=='premium365':
        base=u.premium_until if u.premium_until and u.premium_until>utcnow() else utcnow(); u.premium_until=base+timedelta(days=365)
    elif action=='remove_premium': u.premium_until=None
    elif action=='toggle_admin' and u.id!=owner.id: u.is_admin=not u.is_admin
    db.session.commit(); return redirect(url_for('admin_page'))

@app.errorhandler(413)
def too_large(_): return error('Файл слишком большой. Максимум 45 МБ на запрос.',413)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.getenv('PORT','8000')))
