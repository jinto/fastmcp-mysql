"""MySQL query execution tool for FastMCP."""

import re
import logging
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from fastmcp import Context

from ..connection import ConnectionManager
from ..security import SecurityManager, SecurityContext, SecuritySettings
from ..security.config import FilterMode, RateLimitAlgorithm
from ..security.injection import SQLInjectionDetector
from ..security.filtering import BlacklistFilter, WhitelistFilter, CombinedFilter
from ..security.rate_limiting import create_rate_limiter
from ..security.exceptions import SecurityError

logger = logging.getLogger(__name__)

# Global connection manager instance
_connection_manager: Optional[ConnectionManager] = None

# Global security manager instance
_security_manager: Optional[SecurityManager] = None


def set_connection_manager(manager: ConnectionManager) -> None:
    """Set the global connection manager instance."""
    global _connection_manager
    _connection_manager = manager


def get_connection_manager() -> Optional[ConnectionManager]:
    """Get the global connection manager instance."""
    return _connection_manager


def set_security_manager(manager: SecurityManager) -> None:
    """Set the global security manager instance."""
    global _security_manager
    _security_manager = manager


def get_security_manager() -> Optional[SecurityManager]:
    """Get the global security manager instance."""
    return _security_manager


class QueryType(Enum):
    """Types of SQL queries."""
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    DDL = "DDL"
    OTHER = "OTHER"


class QueryValidator:
    """Validates SQL queries for safety and permissions."""
    
    def __init__(
        self,
        allow_insert: bool = False,
        allow_update: bool = False,
        allow_delete: bool = False,
    ):
        """Initialize query validator.
        
        Args:
            allow_insert: Whether INSERT operations are allowed
            allow_update: Whether UPDATE operations are allowed
            allow_delete: Whether DELETE operations are allowed
        """
        self.allow_insert = allow_insert
        self.allow_update = allow_update
        self.allow_delete = allow_delete
        
        # Patterns for detecting query types
        self.patterns = {
            QueryType.SELECT: re.compile(r'^\s*(WITH\s+.*?\s+)?SELECT\s+', re.IGNORECASE),
            QueryType.INSERT: re.compile(r'^\s*INSERT\s+', re.IGNORECASE),
            QueryType.UPDATE: re.compile(r'^\s*UPDATE\s+', re.IGNORECASE),
            QueryType.DELETE: re.compile(r'^\s*DELETE\s+', re.IGNORECASE),
            QueryType.DDL: re.compile(
                r'^\s*(CREATE|DROP|ALTER|TRUNCATE|RENAME)\s+', 
                re.IGNORECASE
            ),
        }
        
        # Pattern for detecting multiple statements
        self.multi_statement_pattern = re.compile(r';\s*\S', re.MULTILINE)
    
    def get_query_type(self, query: str) -> QueryType:
        """Determine the type of SQL query.
        
        Args:
            query: SQL query string
            
        Returns:
            QueryType enum value
        """
        query = query.strip()
        
        for query_type, pattern in self.patterns.items():
            if pattern.match(query):
                return query_type
        
        return QueryType.OTHER
    
    def validate_query(self, query: str, allow_write: bool = True) -> None:
        """Validate a SQL query.
        
        Args:
            query: SQL query to validate
            allow_write: Whether write operations are allowed for this request
            
        Raises:
            ValueError: If query is not allowed
        """
        # Check for multiple statements
        if self.multi_statement_pattern.search(query):
            raise ValueError("Multiple statements detected in query")
        
        query_type = self.get_query_type(query)
        
        # DDL is never allowed
        if query_type == QueryType.DDL:
            raise ValueError("DDL operations are not allowed")
        
        # SELECT and OTHER queries are always allowed
        if query_type in (QueryType.SELECT, QueryType.OTHER):
            return
        
        # Check write permissions
        if not allow_write:
            raise ValueError(f"{query_type.value} operations require write permission")
        
        # Check specific write permissions
        if query_type == QueryType.INSERT and not self.allow_insert:
            raise ValueError("INSERT operations are not allowed")
        elif query_type == QueryType.UPDATE and not self.allow_update:
            raise ValueError("UPDATE operations are not allowed")
        elif query_type == QueryType.DELETE and not self.allow_delete:
            raise ValueError("DELETE operations are not allowed")


class QueryExecutor:
    """Executes SQL queries with proper validation and error handling."""
    
    def __init__(
        self,
        connection_manager: ConnectionManager,
        validator: QueryValidator
    ):
        """Initialize query executor.
        
        Args:
            connection_manager: Database connection manager
            validator: Query validator instance
        """
        self.connection_manager = connection_manager
        self.validator = validator
    
    async def execute(
        self,
        query: str,
        params: Optional[Union[tuple, List[Any]]] = None,
        database: Optional[str] = None,
        context: Optional[SecurityContext] = None
    ) -> Dict[str, Any]:
        """Execute a SQL query.
        
        Args:
            query: SQL query to execute
            params: Query parameters for prepared statement
            database: Optional database name to prefix tables with
            context: Security context for the request
            
        Returns:
            Dictionary with execution results
        """
        try:
            # Security validation first (if security manager is available)
            security_manager = get_security_manager()
            if security_manager and context:
                # Convert params to tuple for security check
                security_params = tuple(params) if params else None
                await security_manager.validate_query(query, security_params, context)
            
            # Then validate query type
            self.validator.validate_query(query)
            
            # Convert params to tuple if it's a list
            if isinstance(params, list):
                params = tuple(params)
            
            # Add database prefix if specified
            if database:
                # Simple implementation - in production, use proper SQL parser
                query = self._add_database_prefix(query, database)
            
            # Execute query
            result = await self.connection_manager.execute(query, params)
            
            # Format response based on query type
            query_type = self.validator.get_query_type(query)
            
            if query_type == QueryType.SELECT:
                return {
                    "success": True,
                    "data": result,
                    "rows_affected": None
                }
            else:
                return {
                    "success": True,
                    "data": None,
                    "rows_affected": result
                }
        
        except SecurityError as e:
            # Security errors should be logged differently
            logger.warning(f"Security validation failed: {e}", extra={"query": query[:100]})
            return {
                "success": False,
                "error": str(e),
                "data": None,
                "rows_affected": None
            }
        except Exception as e:
            logger.error(f"Query execution failed: {e}", extra={"query": query})
            return {
                "success": False,
                "error": str(e),
                "data": None,
                "rows_affected": None
            }
    
    def _add_database_prefix(self, query: str, database: str) -> str:
        """Add database prefix to table names in query.
        
        This is a simple implementation. In production, use a proper SQL parser.
        
        Args:
            query: Original SQL query
            database: Database name to prefix
            
        Returns:
            Modified query with database prefixes
        """
        # For now, just return the original query
        # In a real implementation, we would parse and modify the SQL
        return query


def format_query_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Format query result for output.
    
    Args:
        result: Raw query result
        
    Returns:
        Formatted result dictionary
    """
    if result["success"]:
        formatted = {
            "success": True,
            "message": "Query executed successfully",
        }
        
        if result["data"] is not None:
            # SELECT query result
            formatted["data"] = result["data"]
            formatted["metadata"] = {
                "row_count": len(result["data"]) if isinstance(result["data"], list) else 0,
                "query_type": "SELECT"
            }
        else:
            # Write query result
            formatted["data"] = None
            formatted["metadata"] = {
                "rows_affected": result["rows_affected"],
                "query_type": "WRITE"
            }
    else:
        formatted = {
            "success": False,
            "error": result["error"],
            "message": "Query execution failed"
        }
    
    return formatted


async def mysql_query(
    query: str,
    params: Optional[List[Any]] = None,
    database: Optional[str] = None,
    context: Optional[Context] = None
) -> Dict[str, Any]:
    """Execute a MySQL query.
    
    This is the main tool function exposed to FastMCP.
    
    Args:
        query: SQL query to execute
        params: Optional query parameters for prepared statements
        database: Optional database name for multi-database mode
        context: FastMCP context (optional)
        
    Returns:
        Dictionary containing query results or error information
    """
    try:
        # Get connection manager
        conn_manager = get_connection_manager()
        if not conn_manager:
            return {
                "success": False,
                "error": "Connection not initialized",
                "message": "Query execution failed"
            }
        
        # Get validator from settings (in a real implementation)
        # For now, use defaults from environment
        import os
        validator = QueryValidator(
            allow_insert=os.getenv("MYSQL_ALLOW_INSERT", "false").lower() == "true",
            allow_update=os.getenv("MYSQL_ALLOW_UPDATE", "false").lower() == "true",
            allow_delete=os.getenv("MYSQL_ALLOW_DELETE", "false").lower() == "true",
        )
        
        # Create executor
        executor = QueryExecutor(conn_manager, validator)
        
        # Create security context from FastMCP context
        security_context = None
        if get_security_manager():
            # Extract user information from context if available
            user_id = None
            if context and hasattr(context, 'user_id'):
                user_id = context.user_id
            elif context and hasattr(context, 'session_id'):
                user_id = context.session_id
            
            security_context = SecurityContext(
                user_id=user_id or "anonymous",
                ip_address=getattr(context, 'ip_address', None) if context else None,
                session_id=getattr(context, 'session_id', None) if context else None
            )
        
        # Execute query
        result = await executor.execute(query, params, database, security_context)
        
        # Format and return result
        return format_query_result(result)
    
    except Exception as e:
        logger.error(f"Unexpected error in mysql_query: {e}")
        return {
            "success": False,
            "error": str(e),
            "message": "Query execution failed"
        }