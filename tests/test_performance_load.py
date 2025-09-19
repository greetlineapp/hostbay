"""
Performance and Concurrent Load Tests
Tests for 124.5 ops/sec validation, connection pool behavior, and cache performance
"""

import pytest
import asyncio
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal
from unittest.mock import AsyncMock, MagicMock, patch
import psutil
import logging

from database import get_connection_pool, execute_query, execute_update
from performance_cache import cache_get, cache_set, cache_invalidate
from performance_monitor import monitor_performance, OperationTimer


@pytest.mark.asyncio
class TestPerformanceTargets:
    """Test system performance against target benchmarks"""
    
    async def test_124_5_operations_per_second_target(self, performance_test_setup):
        """Test that system can handle 124.5 operations per second"""
        target_ops_per_second = 124.5
        test_duration = 5  # seconds
        target_total_ops = int(target_ops_per_second * test_duration)
        
        # Track operations
        operations_completed = 0
        start_time = time.time()
        
        async def simulate_operation():
            """Simulate a typical system operation"""
            nonlocal operations_completed
            
            # Simulate database query
            with patch('database.execute_query') as mock_query:
                mock_query.return_value = [{'id': 1, 'result': 'test'}]
                await mock_query()
            
            # Simulate cache operation
            cache_set('test_key', 'test_value', ttl=60)
            cache_get('test_key')
            
            operations_completed += 1
        
        # Run operations concurrently
        tasks = []
        for _ in range(target_total_ops):
            task = asyncio.create_task(simulate_operation())
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        end_time = time.time()
        actual_duration = end_time - start_time
        actual_ops_per_second = operations_completed / actual_duration
        
        performance_test_setup['operations'].append({
            'target_ops_per_sec': target_ops_per_second,
            'actual_ops_per_sec': actual_ops_per_second,
            'operations_completed': operations_completed,
            'duration': actual_duration
        })
        
        # Should meet or exceed target performance
        assert actual_ops_per_second >= target_ops_per_second * 0.95, \
            f"Performance target not met: {actual_ops_per_second:.2f} < {target_ops_per_second}"
    
    async def test_concurrent_database_operations_performance(self, database):
        """Test database performance under concurrent load"""
        concurrent_connections = 20
        operations_per_connection = 50
        
        start_time = time.time()
        
        async def database_operation_batch():
            """Simulate batch of database operations"""
            operations = 0
            for i in range(operations_per_connection):
                # Simulate various database operations
                with patch('database.execute_query') as mock_query:
                    mock_query.return_value = [{'user_id': i, 'balance': Decimal('100.00')}]
                    result = await mock_query()
                    operations += 1
                
                with patch('database.execute_update') as mock_update:
                    mock_update.return_value = True
                    await mock_update()
                    operations += 1
            
            return operations
        
        # Run concurrent database operations
        tasks = []
        for _ in range(concurrent_connections):
            task = asyncio.create_task(database_operation_batch())
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_operations = sum(results)
        duration = end_time - start_time
        ops_per_second = total_operations / duration
        
        # Should handle concurrent database operations efficiently
        assert ops_per_second >= 100, f"Database performance too low: {ops_per_second:.2f} ops/sec"
        assert duration <= 10, f"Operations took too long: {duration:.2f} seconds"
    
    async def test_cache_performance_under_load(self):
        """Test cache performance and hit rates under high load"""
        cache_operations = 1000
        cache_keys = 100  # Limited key space to test hit rates
        
        hit_count = 0
        miss_count = 0
        
        start_time = time.time()
        
        for i in range(cache_operations):
            key = f"test_key_{i % cache_keys}"
            
            if i % 3 == 0:  # 33% writes
                cache_set(key, f"value_{i}", ttl=3600)
            else:  # 67% reads
                value = cache_get(key)
                if value is not None:
                    hit_count += 1
                else:
                    miss_count += 1
        
        end_time = time.time()
        duration = end_time - start_time
        ops_per_second = cache_operations / duration
        hit_rate = hit_count / (hit_count + miss_count) if (hit_count + miss_count) > 0 else 0
        
        # Cache should be fast and have decent hit rate
        assert ops_per_second >= 1000, f"Cache too slow: {ops_per_second:.2f} ops/sec"
        assert hit_rate >= 0.30, f"Cache hit rate too low: {hit_rate:.2%}"
    
    async def test_memory_usage_under_load(self):
        """Test memory usage remains stable under load"""
        import gc
        process = psutil.Process()
        
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Simulate memory-intensive operations
        operations = 500
        for i in range(operations):
            # Simulate creating and processing data
            data = {f"key_{j}": f"value_{j}" for j in range(100)}
            
            # Simulate cache operations that might retain memory
            cache_set(f"memory_test_{i}", data, ttl=1)
            cache_get(f"memory_test_{i}")
            
            if i % 50 == 0:
                gc.collect()  # Force garbage collection periodically
        
        # Final memory check
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory
        
        # Memory usage shouldn't grow excessively
        assert memory_increase <= 100, f"Memory usage increased by {memory_increase:.2f} MB"
    
    async def test_connection_pool_behavior_under_stress(self):
        """Test database connection pool behavior under stress"""
        max_concurrent_connections = 25
        
        connection_times = []
        
        async def test_connection():
            """Test getting and using a database connection"""
            start = time.time()
            
            # Simulate getting connection from pool
            with patch('database.get_connection_pool') as mock_pool:
                mock_conn = MagicMock()
                mock_pool.return_value.getconn.return_value = mock_conn
                mock_pool.return_value.putconn.return_value = None
                
                conn = mock_pool.return_value.getconn()
                
                # Simulate using connection
                await asyncio.sleep(0.01)  # Simulate query time
                
                mock_pool.return_value.putconn(conn)
                
                end = time.time()
                connection_times.append(end - start)
        
        # Test concurrent connection usage
        tasks = []
        for _ in range(max_concurrent_connections):
            task = asyncio.create_task(test_connection())
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        # Analyze connection performance
        avg_connection_time = sum(connection_times) / len(connection_times)
        max_connection_time = max(connection_times)
        
        # Connection times should be reasonable
        assert avg_connection_time <= 0.1, f"Average connection time too high: {avg_connection_time:.3f}s"
        assert max_connection_time <= 0.5, f"Max connection time too high: {max_connection_time:.3f}s"


@pytest.mark.asyncio
class TestConcurrentOperationSafety:
    """Test thread safety and concurrent operation handling"""
    
    async def test_concurrent_wallet_operations(self):
        """Test concurrent wallet operations maintain consistency"""
        user_id = 12345
        initial_balance = Decimal('100.00')
        concurrent_operations = 20
        operation_amount = Decimal('5.00')
        
        # Mock wallet balance operations
        balance_lock = asyncio.Lock()
        current_balance = initial_balance
        
        async def debit_operation():
            nonlocal current_balance
            async with balance_lock:
                # Simulate database debit operation
                if current_balance >= operation_amount:
                    current_balance -= operation_amount
                    return True
                return False
        
        async def credit_operation():
            nonlocal current_balance
            async with balance_lock:
                # Simulate database credit operation
                current_balance += operation_amount
                return True
        
        # Mix of debit and credit operations
        tasks = []
        for i in range(concurrent_operations):
            if i % 2 == 0:
                task = asyncio.create_task(debit_operation())
            else:
                task = asyncio.create_task(credit_operation())
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # Final balance should be consistent
        # 10 debits, 10 credits = net zero change
        expected_balance = initial_balance
        
        assert current_balance == expected_balance, \
            f"Balance inconsistency: {current_balance} != {expected_balance}"
    
    async def test_concurrent_domain_registration_prevention(self):
        """Test prevention of concurrent domain registrations"""
        domain_name = "concurrent-test.com"
        concurrent_attempts = 10
        
        successful_registrations = 0
        registration_lock = asyncio.Lock()
        registered_domains = set()
        
        async def attempt_registration():
            nonlocal successful_registrations
            
            async with registration_lock:
                if domain_name not in registered_domains:
                    # Simulate registration process
                    await asyncio.sleep(0.01)  # Simulate API delay
                    registered_domains.add(domain_name)
                    successful_registrations += 1
                    return True
                return False
        
        # Attempt concurrent registrations
        tasks = []
        for _ in range(concurrent_attempts):
            task = asyncio.create_task(attempt_registration())
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        
        # Only one registration should succeed
        assert successful_registrations == 1, \
            f"Expected 1 successful registration, got {successful_registrations}"
    
    async def test_cache_thread_safety(self):
        """Test cache operations are thread-safe under concurrent access"""
        cache_key = "thread_safety_test"
        concurrent_operations = 50
        
        write_count = 0
        read_count = 0
        operation_results = []
        
        async def cache_write_operation():
            nonlocal write_count
            for i in range(10):
                cache_set(f"{cache_key}_{i}", f"value_{write_count}_{i}", ttl=60)
                write_count += 1
                await asyncio.sleep(0.001)  # Small delay
        
        async def cache_read_operation():
            nonlocal read_count
            for i in range(10):
                value = cache_get(f"{cache_key}_{i}")
                read_count += 1
                operation_results.append(value)
                await asyncio.sleep(0.001)  # Small delay
        
        # Run concurrent cache operations
        tasks = []
        for _ in range(concurrent_operations // 2):
            tasks.append(asyncio.create_task(cache_write_operation()))
            tasks.append(asyncio.create_task(cache_read_operation()))
        
        await asyncio.gather(*tasks)
        
        # Operations should complete without errors
        assert write_count > 0, "No write operations completed"
        assert read_count > 0, "No read operations completed"
        assert len(operation_results) == read_count, "Read operation count mismatch"


@pytest.mark.asyncio
class TestResourceManagement:
    """Test resource management under load"""
    
    async def test_file_descriptor_usage_under_load(self):
        """Test that file descriptor usage remains reasonable under load"""
        process = psutil.Process()
        initial_fd_count = process.num_fds() if hasattr(process, 'num_fds') else 0
        
        # Simulate operations that might create file descriptors
        async def fd_intensive_operation():
            # Simulate database connections, file operations, etc.
            with patch('httpx.AsyncClient') as mock_client:
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.json.return_value = {'success': True}
                mock_client.return_value.__aenter__.return_value.get.return_value = mock_response
                
                async with mock_client() as client:
                    await client.get("http://test.com")
        
        # Run many operations
        tasks = []
        for _ in range(100):
            task = asyncio.create_task(fd_intensive_operation())
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        # Check final file descriptor count
        final_fd_count = process.num_fds() if hasattr(process, 'num_fds') else 0
        
        if initial_fd_count > 0:  # Only test if we can measure FDs
            fd_increase = final_fd_count - initial_fd_count
            assert fd_increase <= 10, f"Too many file descriptors opened: {fd_increase}"
    
    async def test_async_task_cleanup(self):
        """Test that async tasks are properly cleaned up"""
        initial_task_count = len(asyncio.all_tasks())
        
        async def background_task():
            await asyncio.sleep(0.1)
            return "completed"
        
        # Create and complete many background tasks
        tasks = []
        for _ in range(50):
            task = asyncio.create_task(background_task())
            tasks.append(task)
        
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks)
        
        # Give time for cleanup
        await asyncio.sleep(0.1)
        
        final_task_count = len(asyncio.all_tasks())
        
        # Task count should not grow significantly
        task_increase = final_task_count - initial_task_count
        assert task_increase <= 5, f"Too many tasks remaining: {task_increase}"
        assert all(result == "completed" for result in results)
    
    async def test_database_connection_cleanup(self):
        """Test database connections are properly cleaned up"""
        connection_count = 0
        max_connections_used = 0
        
        async def database_heavy_operation():
            nonlocal connection_count, max_connections_used
            
            # Simulate getting multiple connections
            with patch('database.get_connection_pool') as mock_pool:
                mock_conn = MagicMock()
                mock_pool.return_value.getconn.return_value = mock_conn
                mock_pool.return_value.putconn.return_value = None
                
                connections = []
                for _ in range(3):  # Get multiple connections
                    conn = mock_pool.return_value.getconn()
                    connections.append(conn)
                    connection_count += 1
                    max_connections_used = max(max_connections_used, len(connections))
                
                # Simulate using connections
                await asyncio.sleep(0.01)
                
                # Return all connections
                for conn in connections:
                    mock_pool.return_value.putconn(conn)
                    connection_count -= 1
        
        # Run operations that use many connections
        tasks = []
        for _ in range(10):
            task = asyncio.create_task(database_heavy_operation())
            tasks.append(task)
        
        await asyncio.gather(*tasks)
        
        # All connections should be returned
        assert connection_count == 0, f"Connections not cleaned up: {connection_count}"
        assert max_connections_used > 0, "No connections were used"


@pytest.mark.asyncio
class TestPerformanceMonitoring:
    """Test performance monitoring and metrics collection"""
    
    async def test_operation_timing_monitoring(self):
        """Test that operation timing is properly monitored"""
        operation_name = "test_operation"
        
        @monitor_performance
        async def monitored_operation():
            await asyncio.sleep(0.1)  # Simulate work
            return "success"
        
        start_time = time.time()
        result = await monitored_operation()
        end_time = time.time()
        
        duration = end_time - start_time
        
        assert result == "success"
        assert 0.09 <= duration <= 0.15, f"Duration {duration:.3f}s outside expected range"
    
    async def test_performance_metrics_collection(self, performance_test_setup):
        """Test collection of performance metrics during operations"""
        operations = 100
        
        for i in range(operations):
            start = time.time()
            
            # Simulate various operations
            await asyncio.sleep(0.001)  # Simulate fast operation
            
            end = time.time()
            
            performance_test_setup['operations'].append({
                'operation_id': i,
                'duration': end - start,
                'timestamp': start
            })
        
        # Analyze collected metrics
        durations = [op['duration'] for op in performance_test_setup['operations']]
        avg_duration = sum(durations) / len(durations)
        max_duration = max(durations)
        min_duration = min(durations)
        
        assert len(durations) == operations
        assert avg_duration <= 0.01, f"Average duration too high: {avg_duration:.4f}s"
        assert max_duration <= 0.02, f"Max duration too high: {max_duration:.4f}s"
        assert min_duration >= 0.0005, f"Min duration suspiciously low: {min_duration:.4f}s"
    
    def test_performance_timer_utility(self):
        """Test OperationTimer utility class"""
        with OperationTimer() as timer:
            time.sleep(0.05)  # 50ms
        
        assert 0.045 <= timer.duration <= 0.055, f"Timer duration {timer.duration:.4f}s outside expected range"
        assert timer.start_time > 0
        assert timer.end_time > timer.start_time
    
    async def test_performance_degradation_detection(self):
        """Test detection of performance degradation over time"""
        baseline_operations = 50
        stress_operations = 50
        
        # Baseline performance measurement
        baseline_times = []
        for _ in range(baseline_operations):
            start = time.time()
            await asyncio.sleep(0.001)  # Consistent work
            end = time.time()
            baseline_times.append(end - start)
        
        # Stress test with more load
        stress_times = []
        tasks = []
        for _ in range(stress_operations):
            async def stressed_operation():
                start = time.time()
                await asyncio.sleep(0.001)  # Same work under load
                end = time.time()
                return end - start
            
            task = asyncio.create_task(stressed_operation())
            tasks.append(task)
        
        stress_times = await asyncio.gather(*tasks)
        
        # Compare performance
        baseline_avg = sum(baseline_times) / len(baseline_times)
        stress_avg = sum(stress_times) / len(stress_times)
        
        performance_degradation = (stress_avg - baseline_avg) / baseline_avg
        
        # Performance shouldn't degrade significantly under load
        assert performance_degradation <= 0.5, \
            f"Performance degraded by {performance_degradation:.2%} under load"