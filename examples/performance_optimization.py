"""Performance optimization examples for FastMCP MySQL Server."""

import asyncio
import os
import time
from typing import Dict, Any, List
import statistics


async def connection_pooling_example():
    """Demonstrate connection pooling benefits."""
    from fastmcp_mysql.server import create_server
    
    print("=== Connection Pooling Examples ===\n")
    
    # Configure connection pool
    os.environ.update({
        "MYSQL_HOST": "localhost",
        "MYSQL_USER": "root",
        "MYSQL_PASSWORD": "password",
        "MYSQL_DB": "test",
        "MYSQL_POOL_SIZE": "10",  # Connection pool size
        "MYSQL_QUERY_TIMEOUT": "30000",  # 30 seconds
    })
    
    server = await create_server()
    
    # 1. Sequential queries (reusing connections)
    print("1. Sequential queries with connection pooling:")
    start_time = time.time()
    
    for i in range(20):
        result = await server.mysql_query("SELECT CONNECTION_ID() as conn_id")
        if i == 0 and result["success"]:
            print(f"   First connection ID: {result['data'][0]['conn_id']}")
    
    elapsed = time.time() - start_time
    print(f"   20 queries completed in {elapsed:.3f} seconds")
    print(f"   Average: {elapsed/20:.3f} seconds per query\n")
    
    # 2. Concurrent queries (parallel execution)
    print("2. Concurrent queries with connection pooling:")
    
    async def concurrent_query(query_id: int) -> float:
        """Execute a query and return execution time."""
        start = time.time()
        result = await server.mysql_query(
            "SELECT %s as query_id, CONNECTION_ID() as conn_id, SLEEP(0.1) as delay",
            params=[query_id]
        )
        return time.time() - start
    
    start_time = time.time()
    
    # Run 10 queries concurrently
    tasks = [concurrent_query(i) for i in range(10)]
    execution_times = await asyncio.gather(*tasks)
    
    total_elapsed = time.time() - start_time
    
    print(f"   10 concurrent queries completed in {total_elapsed:.3f} seconds")
    print(f"   Individual query times: min={min(execution_times):.3f}s, max={max(execution_times):.3f}s")
    print(f"   Speedup vs sequential: {(sum(execution_times) / total_elapsed):.1f}x\n")
    
    # 3. Connection pool metrics
    if hasattr(server, 'mysql_metrics'):
        metrics = await server.mysql_metrics()
        pool_metrics = metrics.get('connection_pool', {})
        print("3. Connection pool status:")
        print(f"   Total connections: {pool_metrics.get('total_connections', 'N/A')}")
        print(f"   Active connections: {pool_metrics.get('active_connections', 'N/A')}")
        print(f"   Pool utilization: {pool_metrics.get('utilization_percent', 'N/A')}%")


async def query_caching_example():
    """Demonstrate query result caching."""
    from fastmcp_mysql.server_enhanced import create_enhanced_server
    
    print("\n\n=== Query Caching Examples ===\n")
    
    # Configure caching
    os.environ.update({
        "MYSQL_CACHE_ENABLED": "true",
        "MYSQL_CACHE_MAX_SIZE": "1000",
        "MYSQL_CACHE_TTL": "60000",  # 60 seconds
        "MYSQL_CACHE_EVICTION_POLICY": "lru",
    })
    
    server = await create_enhanced_server()
    
    # 1. Cache hit demonstration
    print("1. Cache hit demonstration:")
    
    # First query (cache miss)
    start = time.time()
    result1 = await server.mysql_query(
        "SELECT COUNT(*) as total FROM information_schema.columns"
    )
    time1 = time.time() - start
    print(f"   First query (cache miss): {time1:.3f} seconds")
    
    # Second identical query (cache hit)
    start = time.time()
    result2 = await server.mysql_query(
        "SELECT COUNT(*) as total FROM information_schema.columns"
    )
    time2 = time.time() - start
    print(f"   Second query (cache hit): {time2:.3f} seconds")
    print(f"   Speedup: {time1/time2:.1f}x\n")
    
    # 2. Cache metrics
    metrics = await server.mysql_metrics()
    cache_metrics = metrics.get('cache', {})
    print("2. Cache metrics:")
    print(f"   Hit rate: {cache_metrics.get('hit_rate_percent', 0):.1f}%")
    print(f"   Total hits: {cache_metrics.get('hits', 0)}")
    print(f"   Total misses: {cache_metrics.get('misses', 0)}")
    print(f"   Cache size: {cache_metrics.get('current_size', 0)}/{cache_metrics.get('max_size', 0)}\n")
    
    # 3. Cache invalidation
    print("3. Cache invalidation modes:")
    print("   - aggressive: Invalidate on any write operation")
    print("   - conservative: Keep cache until TTL expires")
    print("   - targeted: Invalidate only affected tables")


async def query_optimization_example():
    """Demonstrate query optimization techniques."""
    from fastmcp_mysql.server import create_server
    
    print("\n\n=== Query Optimization Examples ===\n")
    
    server = await create_server()
    
    # 1. Index usage
    print("1. Using indexes effectively:")
    
    # Without index (table scan)
    start = time.time()
    result = await server.mysql_query("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_rows > 1000
    """)
    time_no_index = time.time() - start
    
    # With index (using table_schema which is indexed)
    start = time.time()
    result = await server.mysql_query("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'mysql' AND table_rows > 1000
    """)
    time_with_index = time.time() - start
    
    print(f"   Query without index hint: {time_no_index:.3f} seconds")
    print(f"   Query with index hint: {time_with_index:.3f} seconds\n")
    
    # 2. Limiting result sets
    print("2. Limiting result sets:")
    
    queries = [
        ("No limit", "SELECT * FROM information_schema.columns"),
        ("Limit 100", "SELECT * FROM information_schema.columns LIMIT 100"),
        ("Limit 10", "SELECT * FROM information_schema.columns LIMIT 10"),
    ]
    
    for desc, query in queries:
        start = time.time()
        result = await server.mysql_query(query)
        elapsed = time.time() - start
        row_count = len(result['data']) if result['success'] else 0
        print(f"   {desc}: {elapsed:.3f} seconds, {row_count} rows")
    
    # 3. Query complexity
    print("\n3. Query complexity comparison:")
    
    # Simple query
    start = time.time()
    await server.mysql_query("SELECT 1")
    simple_time = time.time() - start
    
    # Complex query with joins
    start = time.time()
    await server.mysql_query("""
        SELECT 
            t.table_name,
            COUNT(c.column_name) as column_count
        FROM information_schema.tables t
        JOIN information_schema.columns c 
            ON t.table_schema = c.table_schema 
            AND t.table_name = c.table_name
        WHERE t.table_schema = 'mysql'
        GROUP BY t.table_name
        ORDER BY column_count DESC
        LIMIT 10
    """)
    complex_time = time.time() - start
    
    print(f"   Simple query: {simple_time:.3f} seconds")
    print(f"   Complex query: {complex_time:.3f} seconds")
    print(f"   Ratio: {complex_time/simple_time:.1f}x slower")


async def batch_processing_example():
    """Demonstrate efficient batch processing."""
    from fastmcp_mysql.server import create_server
    
    print("\n\n=== Batch Processing Examples ===\n")
    
    server = await create_server()
    
    # 1. Individual vs batch operations
    print("1. Individual vs batch operations:")
    
    # Individual queries
    ids = list(range(1, 11))
    start = time.time()
    
    for id_val in ids:
        await server.mysql_query(
            "SELECT %s as id, NOW() as timestamp",
            params=[id_val]
        )
    
    individual_time = time.time() - start
    
    # Batch query using IN clause
    start = time.time()
    placeholders = ','.join(['%s'] * len(ids))
    await server.mysql_query(
        f"SELECT id, NOW() as timestamp FROM (SELECT %s as id UNION ALL " + 
        " UNION ALL ".join([f"SELECT %s"] * (len(ids)-1)) + ") as t",
        params=ids
    )
    batch_time = time.time() - start
    
    print(f"   Individual queries (10): {individual_time:.3f} seconds")
    print(f"   Batch query: {batch_time:.3f} seconds")
    print(f"   Speedup: {individual_time/batch_time:.1f}x\n")
    
    # 2. Pagination for large datasets
    print("2. Efficient pagination:")
    
    page_size = 100
    total_rows = 0
    page_times = []
    
    for page in range(5):
        start = time.time()
        result = await server.mysql_query(
            """
            SELECT table_name, table_type 
            FROM information_schema.tables 
            ORDER BY table_schema, table_name
            LIMIT %s OFFSET %s
            """,
            params=[page_size, page * page_size]
        )
        page_time = time.time() - start
        page_times.append(page_time)
        
        if result['success']:
            row_count = len(result['data'])
            total_rows += row_count
            print(f"   Page {page + 1}: {row_count} rows in {page_time:.3f} seconds")
            
            if row_count < page_size:
                break
    
    print(f"   Total: {total_rows} rows, avg {statistics.mean(page_times):.3f} seconds/page")


async def streaming_example():
    """Demonstrate streaming for large result sets."""
    print("\n\n=== Streaming Examples ===\n")
    
    # Configure streaming
    os.environ.update({
        "MYSQL_STREAMING_CHUNK_SIZE": "1000",
        "MYSQL_PAGINATION_DEFAULT_SIZE": "50",
        "MYSQL_PAGINATION_MAX_SIZE": "1000",
    })
    
    print("1. Streaming configuration:")
    print("   - Chunk size: 1000 rows")
    print("   - Default page size: 50 rows")
    print("   - Max page size: 1000 rows\n")
    
    print("2. Memory-efficient processing:")
    print("   Process large datasets without loading all data into memory")
    print("   Use LIMIT/OFFSET or cursor-based pagination")
    print("   Stream results as they arrive from the database\n")
    
    print("3. Example streaming pattern:")
    print("""
    async def stream_large_dataset():
        offset = 0
        chunk_size = 1000
        
        while True:
            result = await mysql_query(
                "SELECT * FROM large_table LIMIT %s OFFSET %s",
                params=[chunk_size, offset]
            )
            
            if not result['data']:
                break
                
            # Process chunk
            process_chunk(result['data'])
            
            offset += chunk_size
    """)


async def monitoring_performance_example():
    """Monitor and analyze query performance."""
    from fastmcp_mysql.server_enhanced import create_enhanced_server
    
    print("\n\n=== Performance Monitoring Examples ===\n")
    
    server = await create_enhanced_server()
    
    # Execute various queries to generate metrics
    queries = [
        ("SELECT 1", 10),  # Fast query, 10 times
        ("SELECT COUNT(*) FROM information_schema.tables", 5),  # Medium
        ("SELECT * FROM information_schema.columns LIMIT 1000", 2),  # Slow
    ]
    
    print("Executing test queries...\n")
    
    for query, count in queries:
        for _ in range(count):
            await server.mysql_query(query)
            await asyncio.sleep(0.01)
    
    # Get performance metrics
    metrics = await server.mysql_metrics()
    query_metrics = metrics['query']
    
    # 1. Query performance percentiles
    print("1. Query performance percentiles:")
    percentiles = query_metrics.get('duration_percentiles_ms', {})
    print(f"   p50 (median): {percentiles.get('p50', 0):.1f}ms")
    print(f"   p90: {percentiles.get('p90', 0):.1f}ms")
    print(f"   p95: {percentiles.get('p95', 0):.1f}ms")
    print(f"   p99: {percentiles.get('p99', 0):.1f}ms\n")
    
    # 2. Query type distribution
    print("2. Query type distribution:")
    by_type = query_metrics.get('by_type', {})
    total = sum(by_type.values())
    for qtype, count in by_type.items():
        percentage = (count / total * 100) if total > 0 else 0
        print(f"   {qtype}: {count} ({percentage:.1f}%)")
    
    # 3. Slow queries
    print("\n3. Slow queries (if any):")
    slow_queries = query_metrics.get('slow_queries', [])
    if slow_queries:
        for sq in slow_queries[:3]:  # Show top 3
            print(f"   - {sq['duration_ms']:.1f}ms: {sq['query'][:50]}...")
    else:
        print("   No slow queries detected")
    
    # 4. Connection pool efficiency
    pool_metrics = metrics.get('connection_pool', {})
    print("\n4. Connection pool efficiency:")
    print(f"   Pool utilization: {pool_metrics.get('utilization_percent', 0):.1f}%")
    print(f"   Avg wait time: {pool_metrics.get('avg_wait_time_ms', 0):.1f}ms")
    
    # 5. Cache effectiveness
    cache_metrics = metrics.get('cache', {})
    print("\n5. Cache effectiveness:")
    print(f"   Hit rate: {cache_metrics.get('hit_rate_percent', 0):.1f}%")
    print(f"   Cache size: {cache_metrics.get('utilization_percent', 0):.1f}% full")


async def performance_best_practices():
    """Show performance best practices."""
    print("\n\n=== Performance Best Practices ===\n")
    
    practices = [
        ("1. Use Prepared Statements", [
            "- Prevents SQL injection",
            "- Query plan caching",
            "- Better performance for repeated queries"
        ]),
        
        ("2. Optimize Connection Pool", [
            "- Set pool size based on concurrent users",
            "- Monitor pool utilization",
            "- Adjust timeout settings"
        ]),
        
        ("3. Enable Query Caching", [
            "- Cache frequently accessed data",
            "- Set appropriate TTL",
            "- Monitor cache hit rate"
        ]),
        
        ("4. Use Pagination", [
            "- Limit result set size",
            "- Use OFFSET for simple pagination",
            "- Use cursor-based for large datasets"
        ]),
        
        ("5. Monitor Performance", [
            "- Track query percentiles",
            "- Identify slow queries",
            "- Watch for performance degradation"
        ]),
        
        ("6. Query Optimization", [
            "- Use appropriate indexes",
            "- Avoid SELECT *",
            "- Minimize joins when possible"
        ])
    ]
    
    for title, tips in practices:
        print(f"{title}:")
        for tip in tips:
            print(f"  {tip}")
        print()


async def main():
    """Run all performance examples."""
    print("\n" + "="*60)
    print("FastMCP MySQL Server - Performance Optimization Examples")
    print("="*60 + "\n")
    
    try:
        await connection_pooling_example()
        await query_caching_example()
        await query_optimization_example()
        await batch_processing_example()
        await streaming_example()
        await monitoring_performance_example()
        await performance_best_practices()
        
    except Exception as e:
        print(f"\nError running examples: {e}")
    
    print("\n" + "="*60)
    print("Performance examples completed!")
    print("="*60 + "\n")


if __name__ == "__main__":
    asyncio.run(main())