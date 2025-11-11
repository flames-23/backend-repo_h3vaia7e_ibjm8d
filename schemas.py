"""
Database Schemas

Define your MongoDB collection schemas here using Pydantic models.
These schemas are used for data validation in your application.

Each Pydantic model represents a collection in your database.
Model name is converted to lowercase for the collection name:
- User -> "user" collection
- Product -> "product" collection
- BlogPost -> "blogs" collection
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional

class User(BaseModel):
    """
    Users collection schema
    Collection name: "user" (lowercase of class name)
    """
    name: str = Field(..., description="Full name")
    email: EmailStr = Field(..., description="Email address")
    password_hash: str = Field(..., description="Password hash (internal)")
    salt: str = Field(..., description="Password salt (internal)")
    is_active: bool = Field(True, description="Whether user is active")

class Product(BaseModel):
    """
    Products collection schema
    Collection name: "product" (lowercase of class name)
    """
    title: str = Field(..., description="Product title")
    description: Optional[str] = Field(None, description="Product description")
    price: float = Field(..., ge=0, description="Price in dollars")
    category: str = Field(..., description="Product category")
    image: Optional[str] = Field(None, description="Image URL")
    rating: Optional[float] = Field(4.5, ge=0, le=5, description="Average rating")
    in_stock: bool = Field(True, description="Whether product is in stock")

class CartItem(BaseModel):
    """
    Cart items collection schema
    Collection name: "cartitem" (lowercase of class name)
    """
    user_id: str = Field(..., description="User ID")
    product_id: str = Field(..., description="Product ID")
    quantity: int = Field(1, ge=1, description="Quantity")
