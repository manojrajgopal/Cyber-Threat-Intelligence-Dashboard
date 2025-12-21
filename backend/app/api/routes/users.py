from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from ...db.session import get_db
from ...models.models import User, Role
from ...schemas.schemas import User as UserSchema, UserCreate, Role as RoleSchema
from ...security.auth import get_current_active_user, ADMIN_ONLY

router = APIRouter()

@router.get("/roles", response_model=List[RoleSchema])
async def get_roles(
    db: Session = Depends(get_db),
    current_user: User = Depends(ADMIN_ONLY)
):
    """Get all roles (admin only)."""
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

    roles = db.query(Role).all()
    return roles

@router.get("/", response_model=List[UserSchema])
async def get_users(
    skip: int = 0,
    limit: int = 100,
    db: Session = Depends(get_db),
    current_user: User = Depends(ADMIN_ONLY)
):
    """Get all users (admin only)."""
    users = db.query(User).offset(skip).limit(limit).all()
    return users

@router.get("/me", response_model=UserSchema)
async def get_current_user_info(current_user: User = Depends(get_current_active_user)):
    """Get current user information."""
    return current_user

@router.post("/", response_model=UserSchema)
async def create_user(
    user: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(ADMIN_ONLY)
):
    """Create a new user (admin only)."""
    # Check if user already exists
    db_user = db.query(User).filter(
        (User.username == user.username) | (User.email == user.email)
    ).first()
    if db_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already registered"
        )
    
    from ...security.auth import get_password_hash
    hashed_password = get_password_hash(user.password)

    role_id = user.role_id or 1  # Default to 1 if not provided

    db_user = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password,
        role_id=role_id
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@router.put("/{user_id}", response_model=UserSchema)
async def update_user(
    user_id: int,
    user_update: UserCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(ADMIN_ONLY)
):
    """Update user (admin only)."""
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Update fields
    if user_update.username:
        db_user.username = user_update.username
    if user_update.email:
        db_user.email = user_update.email
    if user_update.password:
        from ...security.auth import get_password_hash
        db_user.hashed_password = get_password_hash(user_update.password)
    if user_update.role_id is not None:
        db_user.role_id = user_update.role_id

    db.commit()
    db.refresh(db_user)
    return db_user

@router.delete("/{user_id}")
async def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(ADMIN_ONLY)
):
    """Delete user (admin only)."""
    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(db_user)
    db.commit()
    return {"message": "User deleted"}

@router.get("/{user_id}", response_model=UserSchema)
async def get_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_active_user)
):
    """Get user by ID."""
    # Users can view their own info, admins can view any
    if current_user.id != user_id and not any(p in ["admin"] for p in current_user.role.permissions.get("permissions", [])):
        raise HTTPException(status_code=403, detail="Not enough permissions")

    db_user = db.query(User).filter(User.id == user_id).first()
    if db_user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return db_user