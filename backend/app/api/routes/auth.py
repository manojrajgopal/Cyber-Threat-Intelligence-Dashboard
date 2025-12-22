from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from ...db.session import get_db
from ...models.models import User, Role
from ...schemas.schemas import UserRegister, UserLogin, Token
from ...security.auth import authenticate_user, create_access_token, get_password_hash
from ...config import settings

router = APIRouter()

@router.post("/login", response_model=Token)
async def login(
    user_data: UserLogin,
    db: Session = Depends(get_db)
):
    """Login endpoint."""
    user = authenticate_user(db, user_data.username, user_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/register", response_model=Token)
async def register(
    user_data: UserRegister,
    db: Session = Depends(get_db)
):
    """Register new user endpoint."""
    # Check if user already exists
    db_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    # Ensure all roles exist
    admin_role = db.query(Role).filter(Role.name == "admin").first()
    if not admin_role:
        admin_role = Role(name="admin", permissions={"permissions": ["admin", "analyst", "read"]})
        db.add(admin_role)
        db.commit()
        db.refresh(admin_role)

    analyst_role = db.query(Role).filter(Role.name == "analyst").first()
    if not analyst_role:
        analyst_role = Role(name="analyst", permissions={"permissions": ["analyst", "read"]})
        db.add(analyst_role)
        db.commit()
        db.refresh(analyst_role)

    user_role = db.query(Role).filter(Role.name == "user").first()
    if not user_role:
        user_role = Role(name="user", permissions={"permissions": ["read"]})
        db.add(user_role)
        db.commit()
        db.refresh(user_role)

    # Check if this is the first user
    first_user = db.query(User).first() is None

    if first_user:
        default_role = admin_role
    else:
        default_role = user_role
    
    # Create new user
    hashed_password = get_password_hash(user_data.password)
    db_user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hashed_password,
        role_id=default_role.id
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    # Create access token
    access_token = create_access_token(data={"sub": db_user.username})
    return {"access_token": access_token, "token_type": "bearer"}