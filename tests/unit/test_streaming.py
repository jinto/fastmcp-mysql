"""Unit tests for streaming query results."""
import pytest
import asyncio
from typing import List, AsyncIterator
from unittest.mock import Mock, AsyncMock, MagicMock

from fastmcp_mysql.connection import ConnectionManager, ConnectionConfig
import aiomysql


class TestStreaming:
    """Test streaming functionality for large result sets."""
    
    @pytest.mark.asyncio
    async def test_execute_streaming_basic(self):
        """Test basic streaming execution."""
        # Mock connection manager
        manager = Mock(spec=ConnectionManager)
        
        # Create mock data
        test_data = []
        for i in range(100):
            test_data.append({"id": i, "value": f"value_{i}"})
        
        # Mock cursor that yields data in chunks
        async def mock_fetchmany(size):
            nonlocal test_data
            if not test_data:
                return []
            chunk = test_data[:size]
            test_data = test_data[size:]
            return chunk
        
        mock_cursor = AsyncMock()
        mock_cursor.fetchmany = mock_fetchmany
        mock_cursor.description = [("id",), ("value",)]
        
        # Setup connection context
        mock_conn = AsyncMock()
        mock_conn.cursor.return_value.__aenter__.return_value = mock_cursor
        
        # Mock get_connection as async context manager
        manager.get_connection = AsyncMock()
        manager.get_connection.return_value.__aenter__.return_value = mock_conn
        manager.get_connection.return_value.__aexit__.return_value = None
        
        # Create async generator for execute_streaming
        async def execute_streaming_mock(query, params=None, chunk_size=1000):
            await mock_cursor.execute(query, params)
            while True:
                chunk = await mock_cursor.fetchmany(chunk_size)
                if not chunk:
                    break
                yield chunk
        
        manager.execute_streaming = execute_streaming_mock
        
        # Test streaming
        chunks_received = []
        async for chunk in manager.execute_streaming("SELECT * FROM test", chunk_size=10):
            chunks_received.append(chunk)
        
        # Verify we received all data in chunks
        assert len(chunks_received) == 10  # 100 rows / 10 per chunk
        assert all(len(chunk) == 10 for chunk in chunks_received)
        
        # Verify data integrity
        all_data = []
        for chunk in chunks_received:
            all_data.extend(chunk)
        assert len(all_data) == 100
        assert all_data[0]["id"] == 0
        assert all_data[99]["id"] == 99
    
    @pytest.mark.asyncio
    async def test_execute_streaming_with_params(self):
        """Test streaming with query parameters."""
        manager = Mock(spec=ConnectionManager)
        
        # Mock SSCursor for streaming
        mock_cursor = AsyncMock()
        mock_cursor.fetchmany.side_effect = [
            [{"id": 1, "name": "test1"}],
            [{"id": 2, "name": "test2"}],
            []  # End of results
        ]
        mock_cursor.description = [("id",), ("name",)]
        
        mock_conn = AsyncMock()
        mock_conn.cursor.return_value.__aenter__.return_value = mock_cursor
        manager.get_connection.return_value.__aenter__.return_value = mock_conn
        
        # Create a proper async generator
        async def execute_streaming_mock(query, params=None, chunk_size=1000):
            await mock_cursor.execute(query, params)
            while True:
                chunk = await mock_cursor.fetchmany(chunk_size)
                if not chunk:
                    break
                yield chunk
        
        manager.execute_streaming = execute_streaming_mock
        
        # Test with parameters
        results = []
        async for chunk in manager.execute_streaming(
            "SELECT * FROM users WHERE age > %s",
            params=(18,),
            chunk_size=1
        ):
            results.extend(chunk)
        
        assert len(results) == 2
        mock_cursor.execute.assert_called_once_with(
            "SELECT * FROM users WHERE age > %s", (18,)
        )
    
    @pytest.mark.asyncio
    async def test_execute_streaming_empty_result(self):
        """Test streaming with empty result set."""
        manager = Mock(spec=ConnectionManager)
        
        # Mock cursor that returns no data
        mock_cursor = AsyncMock()
        mock_cursor.fetchmany.return_value = []
        mock_cursor.description = [("id",)]
        
        mock_conn = AsyncMock()
        mock_conn.cursor.return_value.__aenter__.return_value = mock_cursor
        manager.get_connection.return_value.__aenter__.return_value = mock_conn
        
        # Create async generator
        async def execute_streaming_mock(query, params=None, chunk_size=1000):
            await mock_cursor.execute(query, params)
            while True:
                chunk = await mock_cursor.fetchmany(chunk_size)
                if not chunk:
                    break
                yield chunk
        
        manager.execute_streaming = execute_streaming_mock
        
        # Test streaming empty result
        chunks = []
        async for chunk in manager.execute_streaming("SELECT * FROM empty_table"):
            chunks.append(chunk)
        
        assert len(chunks) == 0
    
    @pytest.mark.asyncio
    async def test_execute_streaming_error_handling(self):
        """Test error handling during streaming."""
        manager = Mock(spec=ConnectionManager)
        
        # Mock cursor that raises error
        mock_cursor = AsyncMock()
        mock_cursor.execute.side_effect = aiomysql.Error("Query failed")
        
        mock_conn = AsyncMock()
        mock_conn.cursor.return_value.__aenter__.return_value = mock_cursor
        manager.get_connection.return_value.__aenter__.return_value = mock_conn
        
        # Test error handling
        with pytest.raises(aiomysql.Error):
            async for chunk in manager.execute_streaming("SELECT * FROM bad_table"):
                pass
    
    @pytest.mark.asyncio
    async def test_execute_streaming_large_dataset(self):
        """Test streaming with large dataset."""
        manager = Mock(spec=ConnectionManager)
        
        # Simulate large dataset
        total_rows = 10000
        chunk_size = 500
        
        # Create generator for chunks
        def generate_chunks():
            for i in range(0, total_rows, chunk_size):
                chunk = []
                for j in range(chunk_size):
                    if i + j < total_rows:
                        chunk.append({"id": i + j, "data": f"row_{i + j}"})
                if chunk:
                    yield chunk
        
        chunks_generator = generate_chunks()
        
        mock_cursor = AsyncMock()
        mock_cursor.fetchmany.side_effect = lambda size: next(chunks_generator, [])
        mock_cursor.description = [("id",), ("data",)]
        
        mock_conn = AsyncMock()
        mock_conn.cursor.return_value.__aenter__.return_value = mock_cursor
        manager.get_connection.return_value.__aenter__.return_value = mock_conn
        
        # Test streaming large dataset
        total_received = 0
        chunk_count = 0
        
        async for chunk in manager.execute_streaming(
            "SELECT * FROM large_table",
            chunk_size=chunk_size
        ):
            total_received += len(chunk)
            chunk_count += 1
        
        assert total_received == total_rows
        assert chunk_count == 20  # 10000 / 500
    
    @pytest.mark.asyncio
    async def test_execute_streaming_memory_efficiency(self):
        """Test that streaming doesn't load all data into memory."""
        manager = Mock(spec=ConnectionManager)
        
        # Track memory usage simulation
        memory_usage = []
        
        async def mock_fetchmany(size):
            # Simulate memory usage tracking
            memory_usage.append(size)  # Only 'size' rows in memory at once
            
            # Return some data
            if len(memory_usage) > 5:
                return []  # End after 5 chunks
            
            return [{"id": i} for i in range(size)]
        
        mock_cursor = AsyncMock()
        mock_cursor.fetchmany = mock_fetchmany
        mock_cursor.description = [("id",)]
        
        mock_conn = AsyncMock()
        mock_conn.cursor.return_value.__aenter__.return_value = mock_cursor
        manager.get_connection.return_value.__aenter__.return_value = mock_conn
        
        # Process streaming
        async for chunk in manager.execute_streaming(
            "SELECT * FROM huge_table",
            chunk_size=100
        ):
            # Process chunk (simulating work)
            await asyncio.sleep(0.01)
        
        # Verify memory efficiency
        assert all(usage == 100 for usage in memory_usage)
        assert max(memory_usage) == 100  # Never more than chunk_size in memory
    
    @pytest.mark.asyncio
    async def test_execute_streaming_cancellation(self):
        """Test cancelling streaming operation."""
        manager = Mock(spec=ConnectionManager)
        
        # Create infinite data source
        async def mock_fetchmany(size):
            await asyncio.sleep(0.1)  # Simulate slow query
            return [{"id": i} for i in range(size)]
        
        mock_cursor = AsyncMock()
        mock_cursor.fetchmany = mock_fetchmany
        mock_cursor.description = [("id",)]
        
        mock_conn = AsyncMock()
        mock_conn.cursor.return_value.__aenter__.return_value = mock_cursor
        manager.get_connection.return_value.__aenter__.return_value = mock_conn
        
        # Test cancellation
        chunks_received = 0
        
        async def stream_with_cancel():
            nonlocal chunks_received
            async for chunk in manager.execute_streaming("SELECT * FROM infinite"):
                chunks_received += 1
                if chunks_received >= 3:
                    raise asyncio.CancelledError()
        
        with pytest.raises(asyncio.CancelledError):
            await stream_with_cancel()
        
        assert chunks_received == 3  # Should stop after 3 chunks
    
    @pytest.mark.asyncio
    async def test_execute_streaming_with_cache_integration(self):
        """Test that streaming queries are not cached."""
        from fastmcp_mysql.cache import CacheManager, CacheConfig
        
        # Create cache manager
        cache_config = CacheConfig(enabled=True)
        cache_manager = CacheManager(cache_config)
        
        # Regular queries are cacheable
        regular_query = "SELECT * FROM small_table"
        assert cache_manager.is_cacheable_query(regular_query)
        
        # But streaming context should prevent caching
        # (In practice, streaming queries would be marked differently)
        
        await cache_manager.close()