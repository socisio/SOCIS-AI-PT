"""
SOCIS-AI-PT — User Initialization
Creates default users and roles on startup.
"""

import logging
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.user import User, Role
from app.core.security import hash_password

logger = logging.getLogger(__name__)


async def init_default_admin(db: AsyncSession):
    """Create default admin user if it doesn't exist."""
    from app.config import settings
    
    password = settings.ADMIN_PASSWORD
    is_production = settings.DEPLOYMENT_MODE == 'production'
    
    if not password and is_production:
        logger.error("[-] ADMIN_PASSWORD must be set in production mode!")
        return
    
    if not password:
        password = "Admin123!"  # Dev only
    
    try:
        result = await db.execute(select(User).where(User.username == "admin"))
        admin = result.scalar_one_or_none()
        
        result = await db.execute(select(Role).where(Role.name == "admin"))
        admin_role = result.scalar_one_or_none()
        
        if not admin_role:
            logger.error("[-] Admin role not found. Run init_roles first.")
            return
        
        if admin:
            admin.password_hash = hash_password(password)
            await db.commit()
            logger.info("[+] Admin password updated")
            return
        
        admin_user = User(
            email="admin@socis.local",
            username="admin",
            password_hash=hash_password(password),
            full_name="Administrator",
            is_active=True,
            is_superuser=True,
        )
        admin_user.roles.append(admin_role)
        
        db.add(admin_user)
        await db.flush()
        await db.commit()
        
        mode = "PRODUCTION" if is_production else "DEVELOPMENT"
        logger.info(f"[+] Default admin user created ({mode} mode)")
        logger.info("    Username: admin")
        if is_production:
            logger.warning("    ⚠️  CHANGE PASSWORD IMMEDIATELY AFTER FIRST LOGIN!")
        else:
            logger.info("    Password: Admin123! (dev only)")
        
    except Exception as e:
        logger.error(f"[-] Failed to initialize default admin: {e}")
        await db.rollback()


async def init_roles(db: AsyncSession):
    """Create default roles if they don't exist."""
    try:
        roles_to_create = [
            {"name": "admin", "description": "Administrator with full access"},
            {"name": "analyst", "description": "Security analyst with project access"},
            {"name": "viewer", "description": "Read-only access to reports and scans"},
            {"name": "api_user", "description": "API-only user for integrations"},
        ]
        
        for role_data in roles_to_create:
            result = await db.execute(
                select(Role).where(Role.name == role_data["name"])
            )
            if not result.scalar_one_or_none():
                role = Role(
                    name=role_data["name"],
                    description=role_data["description"],
                )
                db.add(role)
        
        await db.commit()
        logger.info("[+] Default roles verified/created")
        
    except Exception as e:
        logger.error(f"[-] Failed to initialize roles: {e}")
        await db.rollback()
