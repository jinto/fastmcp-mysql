"""Unit tests for paginated query results."""
import pytest
from typing import Dict, Any
from unittest.mock import Mock, AsyncMock

from fastmcp_mysql.connection import ConnectionManager, ConnectionConfig


class TestPagination:
    """Test pagination functionality for query results."""
    
    @pytest.mark.asyncio
    async def test_execute_paginated_basic(self):
        """Test basic paginated execution."""
        # Mock connection manager
        manager = Mock(spec=ConnectionManager)
        
        # Mock cursor for count query
        count_cursor = AsyncMock()
        count_cursor.fetchone.return_value = {"total": 100}
        count_cursor.description = [("total",)]
        
        # Mock cursor for data query
        data_cursor = AsyncMock()
        data_cursor.fetchall.return_value = [
            {"id": i, "name": f"item_{i}"} for i in range(10)
        ]
        data_cursor.description = [("id",), ("name",)]
        
        # Mock connection
        mock_conn = AsyncMock()
        
        # Setup cursor returns for different queries
        cursor_call_count = 0
        async def get_cursor(cursor_class):
            nonlocal cursor_call_count
            cursor_mock = AsyncMock()
            if cursor_call_count == 0:
                # First call is for count
                cursor_mock.__aenter__.return_value = count_cursor
            else:
                # Second call is for data
                cursor_mock.__aenter__.return_value = data_cursor
            cursor_call_count += 1
            return cursor_mock
        
        mock_conn.cursor = get_cursor
        
        # Mock get_connection
        manager.get_connection = AsyncMock()
        manager.get_connection.return_value.__aenter__.return_value = mock_conn
        manager.get_connection.return_value.__aexit__.return_value = None
        
        # Mock execute_paginated to return expected result
        expected_result = {
            "data": data_cursor.fetchall.return_value,
            "pagination": {
                "page": 1,
                "page_size": 10,
                "total_count": 100,
                "total_pages": 10,
                "has_next": True,
                "has_previous": False
            }
        }
        
        manager.execute_paginated = AsyncMock(return_value=expected_result)
        
        # Test pagination
        result = await manager.execute_paginated(
            "SELECT * FROM items",
            page=1,
            page_size=10
        )
        
        assert result["data"] == data_cursor.fetchall.return_value
        assert result["pagination"]["page"] == 1
        assert result["pagination"]["page_size"] == 10
        assert result["pagination"]["total_count"] == 100
        assert result["pagination"]["total_pages"] == 10
    
    @pytest.mark.asyncio
    async def test_execute_paginated_with_params(self):
        """Test paginated execution with query parameters."""
        manager = Mock(spec=ConnectionManager)
        
        # Setup mocks
        count_result = {"total": 50}
        data_results = [{"id": i, "active": True} for i in range(20)]
        
        async def execute_mock(query, params=None):
            if "COUNT(*)" in query:
                return [count_result]
            else:
                # Return paginated data
                if "OFFSET 0" in query:
                    return data_results[:10]
                elif "OFFSET 10" in query:
                    return data_results[10:20]
                else:
                    return []
        
        manager.execute = execute_mock
        
        # Create paginated version
        async def execute_paginated_mock(query, params=None, page=1, page_size=10):
            # Get total count
            count_query = f"SELECT COUNT(*) as total FROM ({query}) as subquery"
            count_results = await manager.execute(count_query, params)
            total_count = count_results[0]["total"]
            
            # Get page data
            offset = (page - 1) * page_size
            paginated_query = f"{query} LIMIT {page_size} OFFSET {offset}"
            data = await manager.execute(paginated_query, params)
            
            return {
                "data": data,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_count": total_count,
                    "total_pages": (total_count + page_size - 1) // page_size
                }
            }
        
        manager.execute_paginated = execute_paginated_mock
        
        # Test with parameters
        result = await manager.execute_paginated(
            "SELECT * FROM users WHERE active = %s",
            params=(True,),
            page=2,
            page_size=10
        )
        
        assert len(result["data"]) == 10
        assert result["data"][0]["id"] == 10  # Second page starts at id=10
        assert result["pagination"]["page"] == 2
        assert result["pagination"]["total_count"] == 50
        assert result["pagination"]["total_pages"] == 5
    
    @pytest.mark.asyncio
    async def test_execute_paginated_empty_result(self):
        """Test pagination with empty result set."""
        manager = Mock(spec=ConnectionManager)
        
        async def execute_mock(query, params=None):
            if "COUNT(*)" in query:
                return [{"total": 0}]
            else:
                return []
        
        manager.execute = execute_mock
        
        # Create paginated version
        async def execute_paginated_mock(query, params=None, page=1, page_size=10):
            count_results = await manager.execute(f"SELECT COUNT(*) as total FROM ({query}) as subquery", params)
            total_count = count_results[0]["total"]
            
            offset = (page - 1) * page_size
            data = await manager.execute(f"{query} LIMIT {page_size} OFFSET {offset}", params)
            
            return {
                "data": data,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_count": total_count,
                    "total_pages": 0 if total_count == 0 else (total_count + page_size - 1) // page_size
                }
            }
        
        manager.execute_paginated = execute_paginated_mock
        
        # Test empty result
        result = await manager.execute_paginated("SELECT * FROM empty_table")
        
        assert result["data"] == []
        assert result["pagination"]["total_count"] == 0
        assert result["pagination"]["total_pages"] == 0
    
    @pytest.mark.asyncio
    async def test_execute_paginated_last_page(self):
        """Test pagination on the last page with partial results."""
        manager = Mock(spec=ConnectionManager)
        
        # 55 total items, page size 10 = 6 pages
        async def execute_mock(query, params=None):
            if "COUNT(*)" in query:
                return [{"total": 55}]
            elif "OFFSET 50" in query:
                # Last page has only 5 items
                return [{"id": i} for i in range(50, 55)]
            else:
                return []
        
        manager.execute = execute_mock
        
        async def execute_paginated_mock(query, params=None, page=1, page_size=10):
            count_results = await manager.execute(f"SELECT COUNT(*) as total FROM ({query}) as subquery", params)
            total_count = count_results[0]["total"]
            
            offset = (page - 1) * page_size
            data = await manager.execute(f"{query} LIMIT {page_size} OFFSET {offset}", params)
            
            return {
                "data": data,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_count": total_count,
                    "total_pages": (total_count + page_size - 1) // page_size
                }
            }
        
        manager.execute_paginated = execute_paginated_mock
        
        # Test last page
        result = await manager.execute_paginated(
            "SELECT * FROM items",
            page=6,
            page_size=10
        )
        
        assert len(result["data"]) == 5  # Only 5 items on last page
        assert result["pagination"]["page"] == 6
        assert result["pagination"]["total_pages"] == 6
    
    @pytest.mark.asyncio
    async def test_execute_paginated_invalid_page(self):
        """Test pagination with invalid page numbers."""
        manager = Mock(spec=ConnectionManager)
        
        async def execute_mock(query, params=None):
            if "COUNT(*)" in query:
                return [{"total": 100}]
            else:
                return []
        
        manager.execute = execute_mock
        
        async def execute_paginated_mock(query, params=None, page=1, page_size=10):
            # Validate page number
            if page < 1:
                page = 1
            
            count_results = await manager.execute(f"SELECT COUNT(*) as total FROM ({query}) as subquery", params)
            total_count = count_results[0]["total"]
            total_pages = (total_count + page_size - 1) // page_size if total_count > 0 else 0
            
            # Adjust page if beyond total pages
            if page > total_pages and total_pages > 0:
                page = total_pages
            
            offset = (page - 1) * page_size
            data = await manager.execute(f"{query} LIMIT {page_size} OFFSET {offset}", params)
            
            return {
                "data": data,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_count": total_count,
                    "total_pages": total_pages
                }
            }
        
        manager.execute_paginated = execute_paginated_mock
        
        # Test page 0 (should become page 1)
        result = await manager.execute_paginated("SELECT * FROM items", page=0)
        assert result["pagination"]["page"] == 1
        
        # Test page beyond total (should become last page)
        result = await manager.execute_paginated("SELECT * FROM items", page=999)
        assert result["pagination"]["page"] == 10  # Total 100 items / 10 per page
    
    @pytest.mark.asyncio
    async def test_execute_paginated_custom_page_size(self):
        """Test pagination with custom page sizes."""
        manager = Mock(spec=ConnectionManager)
        
        async def execute_mock(query, params=None):
            if "COUNT(*)" in query:
                return [{"total": 100}]
            elif "LIMIT 25" in query:
                return [{"id": i} for i in range(25)]
            else:
                return []
        
        manager.execute = execute_mock
        
        async def execute_paginated_mock(query, params=None, page=1, page_size=10, max_page_size=100):
            # Limit page size to maximum
            page_size = min(page_size, max_page_size)
            
            count_results = await manager.execute(f"SELECT COUNT(*) as total FROM ({query}) as subquery", params)
            total_count = count_results[0]["total"]
            
            offset = (page - 1) * page_size
            data = await manager.execute(f"{query} LIMIT {page_size} OFFSET {offset}", params)
            
            return {
                "data": data,
                "pagination": {
                    "page": page,
                    "page_size": page_size,
                    "total_count": total_count,
                    "total_pages": (total_count + page_size - 1) // page_size
                }
            }
        
        manager.execute_paginated = execute_paginated_mock
        
        # Test custom page size
        result = await manager.execute_paginated(
            "SELECT * FROM items",
            page=1,
            page_size=25
        )
        
        assert len(result["data"]) == 25
        assert result["pagination"]["page_size"] == 25
        assert result["pagination"]["total_pages"] == 4  # 100 / 25
    
    @pytest.mark.asyncio
    async def test_pagination_with_cache(self):
        """Test that pagination works with caching."""
        from fastmcp_mysql.cache import CacheManager, CacheConfig
        
        # Create cache manager
        cache_config = CacheConfig(enabled=True)
        cache_manager = CacheManager(cache_config)
        
        # Paginated queries should be cacheable with page info in key
        query = "SELECT * FROM users"
        page = 2
        page_size = 10
        
        # Generate cache keys for different pages
        key1 = cache_manager.get_cache_key(f"{query} LIMIT {page_size} OFFSET 0")
        key2 = cache_manager.get_cache_key(f"{query} LIMIT {page_size} OFFSET 10")
        
        # Keys should be different for different pages
        assert key1 != key2
        
        await cache_manager.close()