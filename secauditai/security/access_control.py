#!/usr/bin/env python3
"""
Role-Based Access Control System
"""

import logging
from typing import Dict, List, Set, Optional
from datetime import datetime, timedelta
import jwt
from functools import wraps

class AccessControl:
    def __init__(
        self,
        roles: List[str],
        permissions: Dict[str, List[str]],
        jwt_secret: str,
        jwt_algorithm: str = "HS256",
        session_timeout: str = "1h"
    ):
        """
        Initialize access control system
        
        Args:
            roles: List of available roles
            permissions: Dictionary mapping roles to allowed permissions
            jwt_secret: Secret key for JWT token generation
            jwt_algorithm: JWT signing algorithm
            session_timeout: Session timeout duration
        """
        self.roles = set(roles)
        self.permissions = permissions
        self.jwt_secret = jwt_secret
        self.jwt_algorithm = jwt_algorithm
        self.session_timeout = self._parse_timeout(session_timeout)
        self.logger = logging.getLogger(__name__)
        
        # Validate permissions
        self._validate_permissions()
    
    def _parse_timeout(self, timeout: str) -> timedelta:
        """Parse timeout string into timedelta"""
        value = int(timeout[:-1])
        unit = timeout[-1]
        
        if unit == 'h':
            return timedelta(hours=value)
        elif unit == 'd':
            return timedelta(days=value)
        elif unit == 'm':
            return timedelta(minutes=value)
        else:
            raise ValueError(f"Invalid timeout unit: {unit}")
    
    def _validate_permissions(self) -> None:
        """Validate that all roles have defined permissions"""
        for role in self.roles:
            if role not in self.permissions:
                raise ValueError(f"Permissions not defined for role: {role}")
    
    def create_token(
        self,
        user_id: str,
        roles: List[str],
        additional_claims: Optional[Dict] = None
    ) -> str:
        """
        Create JWT token for user
        
        Args:
            user_id: User identifier
            roles: List of user roles
            additional_claims: Optional additional JWT claims
            
        Returns:
            JWT token string
        """
        # Validate roles
        for role in roles:
            if role not in self.roles:
                raise ValueError(f"Invalid role: {role}")
        
        # Prepare claims
        claims = {
            "sub": user_id,
            "roles": roles,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + self.session_timeout
        }
        
        # Add additional claims if provided
        if additional_claims:
            claims.update(additional_claims)
        
        # Generate token
        return jwt.encode(
            claims,
            self.jwt_secret,
            algorithm=self.jwt_algorithm
        )
    
    def verify_token(self, token: str) -> Dict:
        """
        Verify JWT token
        
        Args:
            token: JWT token string
            
        Returns:
            Decoded token claims
        """
        try:
            return jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[self.jwt_algorithm]
            )
        except jwt.ExpiredSignatureError:
            self.logger.warning("Token has expired")
            raise
        except jwt.InvalidTokenError:
            self.logger.warning("Invalid token")
            raise
    
    def check_permission(self, role: str, permission: str) -> bool:
        """
        Check if role has permission
        
        Args:
            role: Role to check
            permission: Permission to check
            
        Returns:
            True if role has permission, False otherwise
        """
        if role not in self.roles:
            return False
        
        return permission in self.permissions.get(role, [])
    
    def get_user_permissions(self, roles: List[str]) -> Set[str]:
        """
        Get all permissions for user roles
        
        Args:
            roles: List of user roles
            
        Returns:
            Set of permissions
        """
        permissions = set()
        for role in roles:
            if role in self.permissions:
                permissions.update(self.permissions[role])
        return permissions
    
    def require_permission(self, permission: str):
        """
        Decorator to require specific permission
        
        Args:
            permission: Required permission
        """
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                # Get token from request
                token = kwargs.get('token')
                if not token:
                    raise PermissionError("No token provided")
                
                # Verify token
                claims = self.verify_token(token)
                
                # Check permissions
                for role in claims['roles']:
                    if self.check_permission(role, permission):
                        return func(*args, **kwargs)
                
                raise PermissionError(f"Permission denied: {permission}")
            return wrapper
        return decorator
    
    def audit_log(self, user_id: str, action: str, resource: str, status: str) -> None:
        """
        Log access control events
        
        Args:
            user_id: User identifier
            action: Action performed
            resource: Resource accessed
            status: Action status (success/failure)
        """
        self.logger.info(
            f"Access Control Audit - User: {user_id}, Action: {action}, "
            f"Resource: {resource}, Status: {status}"
        )
    
    def rotate_secret(self, new_secret: str) -> None:
        """
        Rotate JWT secret key
        
        Args:
            new_secret: New secret key
        """
        self.jwt_secret = new_secret
        self.logger.info("JWT secret key rotated")
    
    def update_permissions(self, role: str, permissions: List[str]) -> None:
        """
        Update permissions for a role
        
        Args:
            role: Role to update
            permissions: New permissions list
        """
        if role not in self.roles:
            raise ValueError(f"Invalid role: {role}")
        
        self.permissions[role] = permissions
        self.logger.info(f"Permissions updated for role: {role}")
    
    def add_role(self, role: str, permissions: List[str]) -> None:
        """
        Add new role
        
        Args:
            role: New role name
            permissions: Role permissions
        """
        if role in self.roles:
            raise ValueError(f"Role already exists: {role}")
        
        self.roles.add(role)
        self.permissions[role] = permissions
        self.logger.info(f"New role added: {role}")
    
    def remove_role(self, role: str) -> None:
        """
        Remove role
        
        Args:
            role: Role to remove
        """
        if role not in self.roles:
            raise ValueError(f"Role not found: {role}")
        
        self.roles.remove(role)
        del self.permissions[role]
        self.logger.info(f"Role removed: {role}") 