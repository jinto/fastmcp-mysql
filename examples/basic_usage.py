"""Basic usage examples for FastMCP MySQL Server."""

import asyncio
import os
from typing import Dict, Any, List

# Set up environment variables for testing
os.environ.update({
    "MYSQL_HOST": "localhost",
    "MYSQL_PORT": "3306",
    "MYSQL_USER": "root",
    "MYSQL_PASSWORD": "password",
    "MYSQL_DB": "test",
    "MYSQL_LOG_LEVEL": "INFO"
})


async def basic_queries_example():
    """Demonstrate basic query operations."""
    from fastmcp_mysql.server import create_server
    
    print("=== Basic Query Examples ===\n")
    
    # Create server instance
    server = await create_server()
    
    # 1. Simple SELECT query
    print("1. Simple SELECT query:")
    result = await server.mysql_query(
        "SELECT VERSION() as version, NOW() as current_time"
    )
    if result["success"]:
        data = result["data"][0]
        print(f"   MySQL Version: {data['version']}")
        print(f"   Current Time: {data['current_time']}\n")
    
    # 2. SELECT with WHERE clause
    print("2. SELECT with parameters:")
    result = await server.mysql_query(
        "SELECT * FROM information_schema.tables WHERE table_schema = %s LIMIT 5",
        params=["mysql"]
    )
    if result["success"]:
        print(f"   Found {len(result['data'])} tables in 'mysql' schema\n")
    
    # 3. Aggregate queries
    print("3. Aggregate query:")
    result = await server.mysql_query(
        """
        SELECT 
            table_schema,
            COUNT(*) as table_count,
            SUM(data_length + index_length) as total_size
        FROM information_schema.tables
        WHERE table_schema NOT IN ('information_schema', 'performance_schema')
        GROUP BY table_schema
        """
    )
    if result["success"]:
        print("   Database sizes:")
        for db in result["data"]:
            size_mb = (db['total_size'] or 0) / 1024 / 1024
            print(f"   - {db['table_schema']}: {db['table_count']} tables, {size_mb:.2f} MB")


async def parameterized_queries_example():
    """Demonstrate safe parameterized queries."""
    from fastmcp_mysql.server import create_server
    
    print("\n=== Parameterized Query Examples ===\n")
    
    server = await create_server()
    
    # Create a test table for demonstration
    await server.mysql_query("""
        CREATE TABLE IF NOT EXISTS test_users (
            id INT PRIMARY KEY AUTO_INCREMENT,
            name VARCHAR(100),
            email VARCHAR(100),
            age INT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # 1. Safe INSERT with parameters (requires MYSQL_ALLOW_INSERT=true)
    print("1. INSERT with parameters (will fail without write permission):")
    result = await server.mysql_query(
        "INSERT INTO test_users (name, email, age) VALUES (%s, %s, %s)",
        params=["Alice Smith", "alice@example.com", 25]
    )
    if not result["success"]:
        print(f"   Expected error: {result['error']}")
        print("   Set MYSQL_ALLOW_INSERT=true to enable INSERT operations\n")
    
    # 2. Safe SELECT with multiple parameters
    print("2. SELECT with multiple parameters:")
    result = await server.mysql_query(
        """
        SELECT table_name, table_rows, data_length
        FROM information_schema.tables
        WHERE table_schema = %s 
          AND table_type = %s
          AND table_rows > %s
        ORDER BY table_rows DESC
        LIMIT %s
        """,
        params=["mysql", "BASE TABLE", 0, 5]
    )
    if result["success"]:
        print(f"   Found {len(result['data'])} tables matching criteria\n")
    
    # 3. Demonstrate SQL injection prevention
    print("3. SQL injection prevention:")
    malicious_input = "'; DROP TABLE users; --"
    result = await server.mysql_query(
        "SELECT * FROM information_schema.tables WHERE table_name = %s",
        params=[malicious_input]
    )
    print(f"   Malicious input safely handled: {result['success']}")
    print("   The query is executed safely with prepared statements\n")


async def error_handling_example():
    """Demonstrate proper error handling."""
    from fastmcp_mysql.server import create_server
    
    print("\n=== Error Handling Examples ===\n")
    
    server = await create_server()
    
    # 1. Syntax error
    print("1. Handling syntax errors:")
    result = await server.mysql_query("SELCT * FROM users")  # Typo: SELCT
    if not result["success"]:
        print(f"   Error caught: {result['error']}\n")
    
    # 2. Table doesn't exist
    print("2. Handling missing table:")
    result = await server.mysql_query(
        "SELECT * FROM non_existent_table"
    )
    if not result["success"]:
        print(f"   Error caught: {result['error']}\n")
    
    # 3. Parameter count mismatch
    print("3. Handling parameter mismatch:")
    result = await server.mysql_query(
        "SELECT * FROM information_schema.tables WHERE table_schema = %s AND table_name = %s",
        params=["mysql"]  # Missing second parameter
    )
    if not result["success"]:
        print(f"   Error caught: {result['error']}\n")
    
    # 4. DDL operations (blocked by default)
    print("4. Handling blocked DDL operations:")
    result = await server.mysql_query(
        "DROP TABLE important_data"
    )
    if not result["success"]:
        print(f"   Error caught: {result['error']}")
        print("   DDL operations are blocked for safety\n")


async def health_monitoring_example():
    """Demonstrate health check and monitoring."""
    from fastmcp_mysql.server_enhanced import create_enhanced_server
    
    print("\n=== Health Monitoring Examples ===\n")
    
    # Use enhanced server for monitoring features
    server = await create_enhanced_server()
    
    # 1. Basic health check
    print("1. Health check:")
    health = await server.mysql_health()
    print(f"   Overall status: {health['status']}")
    print(f"   Components:")
    for component in health['components']:
        print(f"   - {component['name']}: {component['status']}")
    
    # 2. Detailed metrics
    print("\n2. Performance metrics:")
    metrics = await server.mysql_metrics()
    
    query_metrics = metrics['query']
    print(f"   Total queries: {query_metrics['total']}")
    print(f"   Success rate: {(query_metrics['successful'] / max(query_metrics['total'], 1) * 100):.1f}%")
    print(f"   Query types: {query_metrics['by_type']}")
    
    if 'duration_percentiles_ms' in query_metrics:
        percentiles = query_metrics['duration_percentiles_ms']
        print(f"   Response times: p50={percentiles['p50']}ms, p95={percentiles['p95']}ms")
    
    # 3. Connection pool status
    print("\n3. Connection pool status:")
    pool_metrics = metrics['connection_pool']
    print(f"   Total connections: {pool_metrics['total_connections']}")
    print(f"   Active: {pool_metrics['active_connections']}")
    print(f"   Utilization: {pool_metrics['utilization_percent']:.1f}%")


async def batch_operations_example():
    """Demonstrate efficient batch operations."""
    from fastmcp_mysql.server import create_server
    import time
    
    print("\n=== Batch Operations Examples ===\n")
    
    server = await create_server()
    
    # 1. Batch SELECT with pagination
    print("1. Paginated data retrieval:")
    page_size = 10
    total_rows = 0
    
    for page in range(3):  # Get 3 pages
        offset = page * page_size
        result = await server.mysql_query(
            """
            SELECT table_name, table_rows
            FROM information_schema.tables
            WHERE table_schema = 'mysql'
            ORDER BY table_name
            LIMIT %s OFFSET %s
            """,
            params=[page_size, offset]
        )
        
        if result["success"] and result["data"]:
            total_rows += len(result["data"])
            print(f"   Page {page + 1}: Retrieved {len(result['data'])} rows")
        else:
            break
    
    print(f"   Total rows retrieved: {total_rows}\n")
    
    # 2. Simulate batch processing with timing
    print("2. Batch query performance:")
    queries = [
        ("SELECT COUNT(*) FROM information_schema.tables", []),
        ("SELECT COUNT(*) FROM information_schema.columns", []),
        ("SELECT COUNT(*) FROM information_schema.routines", []),
    ]
    
    start_time = time.time()
    results = []
    
    for query, params in queries:
        result = await server.mysql_query(query, params=params)
        results.append(result)
    
    elapsed = time.time() - start_time
    print(f"   Executed {len(queries)} queries in {elapsed:.3f} seconds")
    print(f"   Average time per query: {elapsed / len(queries):.3f} seconds\n")


async def main():
    """Run all examples."""
    print("\n" + "="*60)
    print("FastMCP MySQL Server - Basic Usage Examples")
    print("="*60 + "\n")
    
    try:
        # Run examples in sequence
        await basic_queries_example()
        await parameterized_queries_example()
        await error_handling_example()
        await health_monitoring_example()
        await batch_operations_example()
        
    except Exception as e:
        print(f"\nError running examples: {e}")
        print("Make sure MySQL is running and accessible with the configured credentials.")
    
    print("\n" + "="*60)
    print("Examples completed!")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())