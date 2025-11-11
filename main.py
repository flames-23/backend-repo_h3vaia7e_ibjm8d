import os
from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import secrets
from bson import ObjectId

from database import db, create_document, get_documents

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- Utility functions ----------

def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256', password.encode('utf-8'), salt.encode('utf-8'), 100000
    ).hex()
    return pwd_hash, salt

# Simple token store in DB (collection: session)
# token docs: { token, user_id, expires_at }

def create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(days=3)
    db['session'].insert_one({
        'token': token,
        'user_id': user_id,
        'expires_at': expires_at
    })
    return token


def get_user_by_email(email: str) -> Optional[dict]:
    return db['user'].find_one({'email': email})


def auth_dependency(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith('Bearer '):
        raise HTTPException(status_code=401, detail='Unauthorized')
    token = authorization.split(' ', 1)[1]
    session = db['session'].find_one({'token': token})
    if not session or session.get('expires_at') < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail='Session expired')
    user = db['user'].find_one({'_id': ObjectId(session['user_id'])})
    if not user:
        raise HTTPException(status_code=401, detail='User not found')
    return {'user_id': str(user['_id']), 'email': user['email']}


# ---------- Models ----------

class SignupRequest(BaseModel):
    name: str
    email: EmailStr
    password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ProductCreate(BaseModel):
    title: str
    description: Optional[str] = None
    price: float
    category: str
    image: Optional[str] = None

class AddToCartRequest(BaseModel):
    product_id: str
    quantity: int = 1


# ---------- Routes ----------

@app.get("/")
def read_root():
    return {"message": "Electronics Shop API"}

@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    try:
        if db is not None:
            response["database"] = "✅ Connected & Working"
            response["database_url"] = "✅ Set"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            collections = db.list_collection_names()
            response["collections"] = collections[:10]
        else:
            response["database"] = "⚠️ Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    import os
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response

# Auth
@app.post('/api/signup')
def signup(payload: SignupRequest):
    if get_user_by_email(payload.email):
        raise HTTPException(status_code=400, detail='Email already registered')
    pwd_hash, salt = hash_password(payload.password)
    user_doc = {
        'name': payload.name,
        'email': payload.email,
        'password_hash': pwd_hash,
        'salt': salt,
        'is_active': True,
        'created_at': datetime.now(timezone.utc),
        'updated_at': datetime.now(timezone.utc),
    }
    result = db['user'].insert_one(user_doc)
    token = create_session(str(result.inserted_id))
    return {'token': token, 'user': {'id': str(result.inserted_id), 'name': payload.name, 'email': payload.email}}

@app.post('/api/login')
def login(payload: LoginRequest):
    user = get_user_by_email(payload.email)
    if not user:
        raise HTTPException(status_code=401, detail='Invalid credentials')
    pwd_hash, _ = hash_password(payload.password, user['salt'])
    if not hmac.compare_digest(pwd_hash, user['password_hash']):
        raise HTTPException(status_code=401, detail='Invalid credentials')
    token = create_session(str(user['_id']))
    return {'token': token, 'user': {'id': str(user['_id']), 'name': user['name'], 'email': user['email']}}

@app.post('/api/logout')
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.startswith('Bearer '):
        token = authorization.split(' ', 1)[1]
        db['session'].delete_one({'token': token})
    return {'message': 'Logged out'}

# Products
@app.get('/api/products')
def list_products() -> List[dict]:
    count = db['product'].count_documents({})
    if count == 0:
        demo = [
            {
                'title': 'Noise-Cancelling Headphones',
                'description': 'Immersive sound with active noise cancellation.',
                'price': 199.99,
                'category': 'Audio',
                'image': 'https://images.unsplash.com/photo-1518441902113-c1d3b87b73dc?q=80&w=1200&auto=format&fit=crop',
                'rating': 4.8,
                'in_stock': True,
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc),
            },
            {
                'title': 'Smartwatch Pro',
                'description': 'Fitness tracking, notifications, and more.',
                'price': 149.99,
                'category': 'Wearables',
                'image': 'https://images.unsplash.com/photo-1517341720795-cf33c0b59877?q=80&w=1200&auto=format&fit=crop',
                'rating': 4.6,
                'in_stock': True,
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc),
            },
            {
                'title': '4K Action Camera',
                'description': 'Capture adventures in stunning 4K.',
                'price': 229.0,
                'category': 'Cameras',
                'image': 'https://images.unsplash.com/photo-1519181245277-cffeb31da2fb?q=80&w=1200&auto=format&fit=crop',
                'rating': 4.4,
                'in_stock': True,
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc),
            },
            {
                'title': 'Portable Bluetooth Speaker',
                'description': 'Rich bass and 12-hour battery.',
                'price': 59.99,
                'category': 'Audio',
                'image': 'https://images.unsplash.com/photo-1585386959984-a4155223168f?q=80&w=1200&auto=format&fit=crop',
                'rating': 4.5,
                'in_stock': True,
                'created_at': datetime.now(timezone.utc),
                'updated_at': datetime.now(timezone.utc),
            }
        ]
        db['product'].insert_many(demo)
    products = list(db['product'].find())
    for p in products:
        p['id'] = str(p['_id'])
        del p['_id']
    return products

@app.post('/api/products')
def create_product(payload: ProductCreate):
    doc = {
        'title': payload.title,
        'description': payload.description,
        'price': payload.price,
        'category': payload.category,
        'image': payload.image,
        'rating': 4.5,
        'in_stock': True,
        'created_at': datetime.now(timezone.utc),
        'updated_at': datetime.now(timezone.utc),
    }
    res = db['product'].insert_one(doc)
    return {"id": str(res.inserted_id), **doc}

# Cart
@app.get('/api/cart')
def get_cart(user=Depends(auth_dependency)):
    items = list(db['cartitem'].find({'user_id': user['user_id']}))
    # Map product details
    product_ids = [ObjectId(i['product_id']) for i in items]
    products_map = {str(p['_id']): p for p in db['product'].find({'_id': {'$in': product_ids}})} if product_ids else {}
    result = []
    for item in items:
        prod = products_map.get(item['product_id']) or db['product'].find_one({'_id': ObjectId(item['product_id'])})
        if prod:
            result.append({
                'id': str(item['_id']),
                'product': {
                    'id': str(prod['_id']),
                    'title': prod.get('title'),
                    'price': prod.get('price'),
                    'image': prod.get('image'),
                    'category': prod.get('category')
                },
                'quantity': item.get('quantity', 1)
            })
    return result

@app.post('/api/cart')
def add_to_cart(payload: AddToCartRequest, user=Depends(auth_dependency)):
    # Check product exists
    prod = db['product'].find_one({'_id': ObjectId(payload.product_id)})
    if not prod:
        raise HTTPException(status_code=404, detail='Product not found')
    existing = db['cartitem'].find_one({'user_id': user['user_id'], 'product_id': payload.product_id})
    if existing:
        db['cartitem'].update_one({'_id': existing['_id']}, {'$inc': {'quantity': payload.quantity}})
        return {'message': 'Quantity updated'}
    db['cartitem'].insert_one({
        'user_id': user['user_id'],
        'product_id': payload.product_id,
        'quantity': payload.quantity,
        'created_at': datetime.now(timezone.utc),
        'updated_at': datetime.now(timezone.utc),
    })
    return {'message': 'Added to cart'}

@app.delete('/api/cart/{item_id}')
def remove_cart_item(item_id: str, user=Depends(auth_dependency)):
    db['cartitem'].delete_one({'_id': ObjectId(item_id), 'user_id': user['user_id']})
    return {'message': 'Removed'}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
