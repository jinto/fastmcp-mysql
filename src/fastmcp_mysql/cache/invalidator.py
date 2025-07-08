"""Cache invalidation logic for query operations."""
import re
from enum import Enum
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field

from .interfaces import CacheInterface, CacheKeyGenerator


class QueryType(Enum):
    """SQL query types."""
    SELECT = "SELECT"
    INSERT = "INSERT"
    UPDATE = "UPDATE"
    DELETE = "DELETE"
    DDL = "DDL"
    OTHER = "OTHER"


class InvalidationStrategy(Enum):
    """Cache invalidation strategies."""
    AGGRESSIVE = "aggressive"  # Invalidate table and all dependencies
    CONSERVATIVE = "conservative"  # Invalidate only affected table
    TARGETED = "targeted"  # Invalidate based on WHERE clause analysis


@dataclass
class TableDependency:
    """Represents dependencies between tables."""
    table: str
    depends_on: List[str] = field(default_factory=list)


class CacheInvalidator:
    """Manages cache invalidation for database operations."""
    
    def __init__(self, strategy: InvalidationStrategy = InvalidationStrategy.AGGRESSIVE):
        """Initialize cache invalidator.
        
        Args:
            strategy: Invalidation strategy to use
        """
        self.strategy = strategy
        self.key_generator = CacheKeyGenerator()
        self._dependencies: Dict[str, List[str]] = {}
    
    def get_query_type(self, query: str) -> QueryType:
        """Determine the type of SQL query.
        
        Args:
            query: SQL query string
            
        Returns:
            QueryType enum value
        """
        query_upper = query.strip().upper()
        
        if query_upper.startswith("SELECT"):
            return QueryType.SELECT
        elif query_upper.startswith("INSERT"):
            return QueryType.INSERT
        elif query_upper.startswith("UPDATE"):
            return QueryType.UPDATE
        elif query_upper.startswith("DELETE"):
            return QueryType.DELETE
        elif any(query_upper.startswith(ddl) for ddl in ["CREATE", "ALTER", "DROP", "TRUNCATE"]):
            return QueryType.DDL
        else:
            return QueryType.OTHER
    
    def extract_tables(self, query: str) -> List[str]:
        """Extract table names from a query.
        
        Args:
            query: SQL query string
            
        Returns:
            List of table names found in the query
        """
        tables = []
        normalized = self.key_generator.normalize_query(query)
        
        # Patterns for different SQL clauses
        patterns = [
            # FROM clause
            r'\bfrom\s+([a-z_][a-z0-9_]*)',
            # JOIN clauses
            r'\bjoin\s+([a-z_][a-z0-9_]*)',
            # INTO clause (for INSERT)
            r'\binto\s+([a-z_][a-z0-9_]*)',
            # UPDATE clause
            r'\bupdate\s+([a-z_][a-z0-9_]*)',
            # DELETE FROM clause
            r'\bdelete\s+from\s+([a-z_][a-z0-9_]*)',
            # Subqueries (basic support)
            r'\(\s*select\s+.*?\s+from\s+([a-z_][a-z0-9_]*)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, normalized, re.IGNORECASE)
            tables.extend(matches)
        
        # Remove duplicates while preserving order
        seen = set()
        unique_tables = []
        for table in tables:
            if table not in seen:
                seen.add(table)
                unique_tables.append(table)
        
        return unique_tables
    
    def add_dependency(self, table: str, depends_on: List[str]) -> None:
        """Add table dependencies.
        
        Args:
            table: Table name
            depends_on: List of tables this table depends on
        """
        if table not in self._dependencies:
            self._dependencies[table] = []
        
        for dep in depends_on:
            if dep not in self._dependencies[table]:
                self._dependencies[table].append(dep)
    
    def remove_dependency(self, table: str, dependency: str) -> None:
        """Remove a specific dependency.
        
        Args:
            table: Table name
            dependency: Dependency to remove
        """
        if table in self._dependencies and dependency in self._dependencies[table]:
            self._dependencies[table].remove(dependency)
    
    def get_dependencies(self, table: str) -> List[str]:
        """Get direct dependencies for a table.
        
        Args:
            table: Table name
            
        Returns:
            List of direct dependencies
        """
        return self._dependencies.get(table, [])
    
    def get_all_dependencies(self, table: str, visited: Optional[Set[str]] = None) -> List[str]:
        """Get all dependencies (including transitive) for a table.
        
        Args:
            table: Table name
            visited: Set of already visited tables (for cycle detection)
            
        Returns:
            List of all dependencies
        """
        if visited is None:
            visited = set()
        
        if table in visited:
            return []
        
        visited.add(table)
        all_deps = []
        
        # Get direct dependencies
        direct_deps = self.get_dependencies(table)
        all_deps.extend(direct_deps)
        
        # Get transitive dependencies
        for dep in direct_deps:
            transitive_deps = self.get_all_dependencies(dep, visited)
            for t_dep in transitive_deps:
                if t_dep not in all_deps:
                    all_deps.append(t_dep)
        
        return all_deps
    
    def generate_pattern(self, table: str, prefix: Optional[str] = None) -> str:
        """Generate cache key pattern for a table.
        
        Args:
            table: Table name
            prefix: Optional prefix (e.g., database name)
            
        Returns:
            Cache key pattern
        """
        if prefix:
            return f"{prefix}:*:{table}:*"
        return f"*:{table}:*"
    
    def generate_patterns(self, tables: List[str], prefix: Optional[str] = None) -> List[str]:
        """Generate cache key patterns for multiple tables.
        
        Args:
            tables: List of table names
            prefix: Optional prefix
            
        Returns:
            List of cache key patterns
        """
        return [self.generate_pattern(table, prefix) for table in tables]
    
    async def invalidate_on_write(
        self,
        query: str,
        cache: CacheInterface,
        database: Optional[str] = None,
        targeted: bool = False
    ) -> None:
        """Invalidate cache entries based on a write operation.
        
        Args:
            query: SQL query that modifies data
            cache: Cache instance to invalidate
            database: Optional database context
            targeted: Whether to use targeted invalidation
        """
        query_type = self.get_query_type(query)
        
        # SELECT queries don't invalidate cache
        if query_type == QueryType.SELECT:
            return
        
        # DDL operations clear entire cache
        if query_type == QueryType.DDL:
            await cache.clear()
            return
        
        # Extract affected tables
        tables = self.extract_tables(query)
        
        # Add dependencies based on strategy
        if self.strategy == InvalidationStrategy.AGGRESSIVE:
            # Add all dependencies
            additional_tables = []
            for table in tables:
                deps = self.get_all_dependencies(table)
                additional_tables.extend(deps)
            
            # Add unique dependencies
            for dep in additional_tables:
                if dep not in tables:
                    tables.append(dep)
        
        # Generate patterns and invalidate
        patterns = self.generate_patterns(tables, database)
        
        for pattern in patterns:
            await cache.delete_pattern(pattern)
    
    async def invalidate_batch(
        self,
        queries: List[str],
        cache: CacheInterface,
        database: Optional[str] = None
    ) -> None:
        """Invalidate cache for a batch of queries.
        
        Args:
            queries: List of SQL queries
            cache: Cache instance
            database: Optional database context
        """
        # Collect all affected tables
        all_tables = set()
        has_ddl = False
        
        for query in queries:
            query_type = self.get_query_type(query)
            
            if query_type == QueryType.DDL:
                has_ddl = True
                break
            
            if query_type != QueryType.SELECT:
                tables = self.extract_tables(query)
                all_tables.update(tables)
        
        # If any DDL, clear entire cache
        if has_ddl:
            await cache.clear()
            return
        
        # Invalidate all affected tables
        if all_tables:
            # Process each table separately to ensure proper pattern generation
            for table in all_tables:
                tables_to_invalidate = [table]
                
                # Add dependencies if using aggressive strategy
                if self.strategy == InvalidationStrategy.AGGRESSIVE:
                    deps = self.get_all_dependencies(table)
                    tables_to_invalidate.extend(deps)
                
                # Generate patterns and invalidate
                patterns = self.generate_patterns(tables_to_invalidate, database)
                for pattern in patterns:
                    await cache.delete_pattern(pattern)
    
    def analyze_where_clause(self, query: str) -> Optional[Dict[str, any]]:
        """Analyze WHERE clause for targeted invalidation.
        
        Args:
            query: SQL query
            
        Returns:
            Dictionary with WHERE clause analysis or None
        """
        # This is a placeholder for more sophisticated WHERE clause analysis
        # In a real implementation, this would parse the WHERE clause
        # and extract specific conditions for targeted invalidation
        
        # Simple regex to find id = value patterns
        pattern = r'where\s+.*?(\w+)\s*=\s*[\'"]?(\w+)[\'"]?'
        match = re.search(pattern, query, re.IGNORECASE)
        
        if match:
            return {
                "column": match.group(1),
                "value": match.group(2)
            }
        
        return None