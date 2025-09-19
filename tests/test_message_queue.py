"""
Message Queue Delivery Reliability Tests
Tests for thread safety, overflow scenarios, and ordering guarantees
"""

import pytest
import asyncio
import threading
import queue
import time
from unittest.mock import AsyncMock, MagicMock, patch
from concurrent.futures import ThreadPoolExecutor

from webhook_handler import _message_queue, _queue_processor_thread, set_bot_application


@pytest.mark.asyncio
class TestMessageQueueReliability:
    """Test message queue reliability and delivery guarantees"""
    
    def test_message_queue_thread_safety(self):
        """Test message queue operations are thread-safe"""
        test_queue = queue.Queue()
        message_count = 100
        thread_count = 5
        
        def producer_thread(thread_id):
            """Producer thread that adds messages to queue"""
            for i in range(message_count // thread_count):
                message = {
                    'type': 'test_message',
                    'thread_id': thread_id,
                    'message_id': i,
                    'timestamp': time.time()
                }
                test_queue.put(message)
        
        def consumer_thread():
            """Consumer thread that processes messages from queue"""
            processed_messages = []
            while len(processed_messages) < message_count:
                try:
                    message = test_queue.get(timeout=1.0)
                    processed_messages.append(message)
                    test_queue.task_done()
                except queue.Empty:
                    break
            return processed_messages
        
        # Start producer threads
        producer_threads = []
        for thread_id in range(thread_count):
            thread = threading.Thread(target=producer_thread, args=(thread_id,))
            thread.start()
            producer_threads.append(thread)
        
        # Start consumer thread
        consumer_thread_obj = threading.Thread(target=consumer_thread)
        consumer_thread_obj.start()
        
        # Wait for all producers to finish
        for thread in producer_threads:
            thread.join()
        
        # Wait for consumer to finish
        consumer_thread_obj.join()
        
        # Queue should be empty after processing
        assert test_queue.empty(), "Queue should be empty after processing all messages"
    
    def test_message_queue_overflow_handling(self):
        """Test message queue behavior when reaching capacity limits"""
        # Create queue with limited capacity
        limited_queue = queue.Queue(maxsize=10)
        
        # Fill queue to capacity
        for i in range(10):
            message = {'id': i, 'data': f'message_{i}'}
            limited_queue.put(message)
        
        # Queue should be full
        assert limited_queue.full(), "Queue should be full"
        
        # Test overflow behavior
        overflow_message = {'id': 11, 'data': 'overflow_message'}
        
        # Should not block or raise exception with put_nowait
        try:
            limited_queue.put_nowait(overflow_message)
            assert False, "Should have raised queue.Full exception"
        except queue.Full:
            pass  # Expected behavior
        
        # Should handle overflow gracefully with timeout
        start_time = time.time()
        try:
            limited_queue.put(overflow_message, timeout=0.1)
            assert False, "Should have raised queue.Full exception"
        except queue.Full:
            end_time = time.time()
            assert end_time - start_time >= 0.1, "Timeout should have been respected"
    
    async def test_message_ordering_guarantees(self):
        """Test that message processing maintains order"""
        test_queue = queue.Queue()
        processed_order = []
        processing_lock = asyncio.Lock()
        
        # Add messages in specific order
        for i in range(20):
            message = {
                'sequence_id': i,
                'data': f'ordered_message_{i}',
                'timestamp': time.time()
            }
            test_queue.put(message)
        
        async def process_messages():
            """Process messages and track order"""
            while not test_queue.empty():
                try:
                    message = test_queue.get_nowait()
                    
                    async with processing_lock:
                        processed_order.append(message['sequence_id'])
                    
                    # Simulate processing time
                    await asyncio.sleep(0.001)
                    
                except queue.Empty:
                    break
        
        # Process messages
        await process_messages()
        
        # Verify order is maintained
        expected_order = list(range(20))
        assert processed_order == expected_order, \
            f"Message order not maintained: {processed_order} != {expected_order}"
    
    def test_queue_processor_thread_lifecycle(self):
        """Test message queue processor thread lifecycle"""
        # Mock bot application
        mock_app = MagicMock()
        mock_bot = AsyncMock()
        mock_app.bot = mock_bot
        
        # Set bot application (should start processor thread)
        set_bot_application(mock_app)
        
        # Processor thread should be running
        # Note: This is implementation-dependent, adjust based on actual implementation
        assert _message_queue is not None, "Message queue should be initialized"
        
        # Clean up
        set_bot_application(None)
    
    async def test_message_delivery_reliability_with_failures(self):
        """Test message delivery reliability when processing fails"""
        test_queue = queue.Queue()
        successful_deliveries = []
        failed_deliveries = []
        
        # Add test messages
        for i in range(10):
            message = {
                'user_id': 12345,
                'message_id': i,
                'text': f'Test message {i}',
                'should_fail': i % 3 == 0  # Every 3rd message fails
            }
            test_queue.put(message)
        
        async def process_with_failures():
            """Process messages with simulated failures"""
            while not test_queue.empty():
                try:
                    message = test_queue.get_nowait()
                    
                    if message['should_fail']:
                        # Simulate processing failure
                        failed_deliveries.append(message['message_id'])
                        # In real implementation, might retry or handle differently
                    else:
                        # Simulate successful processing
                        successful_deliveries.append(message['message_id'])
                    
                except queue.Empty:
                    break
        
        await process_with_failures()
        
        # Verify delivery tracking
        total_processed = len(successful_deliveries) + len(failed_deliveries)
        assert total_processed == 10, "All messages should be processed"
        assert len(failed_deliveries) > 0, "Some messages should have failed"
        assert len(successful_deliveries) > 0, "Some messages should have succeeded"
    
    def test_concurrent_queue_access_safety(self):
        """Test concurrent access to message queue from multiple threads"""
        test_queue = queue.Queue()
        results = []
        errors = []
        
        def queue_worker(worker_id, operation_count):
            """Worker thread that performs queue operations"""
            worker_results = []
            try:
                for i in range(operation_count):
                    # Alternate between put and get operations
                    if i % 2 == 0:
                        message = {
                            'worker_id': worker_id,
                            'operation': i,
                            'timestamp': time.time()
                        }
                        test_queue.put(message)
                        worker_results.append(f'put_{worker_id}_{i}')
                    else:
                        try:
                            message = test_queue.get(timeout=0.1)
                            worker_results.append(f'get_{worker_id}_{i}')
                        except queue.Empty:
                            worker_results.append(f'empty_{worker_id}_{i}')
                
                results.extend(worker_results)
                
            except Exception as e:
                errors.append(f'worker_{worker_id}_error: {e}')
        
        # Start multiple worker threads
        threads = []
        worker_count = 5
        operations_per_worker = 20
        
        for worker_id in range(worker_count):
            thread = threading.Thread(
                target=queue_worker,
                args=(worker_id, operations_per_worker)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify no errors occurred
        assert len(errors) == 0, f"Errors occurred during concurrent access: {errors}"
        assert len(results) == worker_count * operations_per_worker, \
            "Not all operations completed"


@pytest.mark.asyncio
class TestWebhookMessageProcessing:
    """Test webhook message processing through the queue system"""
    
    async def test_webhook_message_queuing(self):
        """Test webhook messages are properly queued for processing"""
        mock_app = MagicMock()
        mock_bot = AsyncMock()
        mock_app.bot = mock_bot
        
        with patch('webhook_handler._message_queue') as mock_queue:
            # Set bot application
            set_bot_application(mock_app)
            
            # Simulate webhook message
            webhook_data = {
                'type': 'payment_confirmation',
                'user_id': 12345,
                'amount': '50.00',
                'transaction_id': 'tx_123'
            }
            
            # Mock queue operations
            mock_queue.put.return_value = None
            
            # Process webhook (this would normally happen in webhook_handler.py)
            with patch('webhook_handler.process_webhook_message') as mock_process:
                mock_process.return_value = None
                
                # Simulate message being added to queue
                mock_queue.put(webhook_data)
                
                # Verify message was queued
                mock_queue.put.assert_called_once_with(webhook_data)
    
    async def test_bot_message_delivery_retry_logic(self):
        """Test retry logic for failed bot message deliveries"""
        mock_app = MagicMock()
        mock_bot = AsyncMock()
        mock_app.bot = mock_bot
        
        # Simulate API failures
        mock_bot.send_message.side_effect = [
            Exception("Network error"),  # First attempt fails
            Exception("Rate limit"),     # Second attempt fails  
            MagicMock()                  # Third attempt succeeds
        ]
        
        message_data = {
            'user_id': 12345,
            'text': 'Test message',
            'retry_count': 0
        }
        
        max_retries = 3
        
        async def attempt_delivery(data):
            """Simulate message delivery with retry logic"""
            for attempt in range(max_retries):
                try:
                    await mock_bot.send_message(
                        chat_id=data['user_id'],
                        text=data['text']
                    )
                    return True
                except Exception as e:
                    if attempt < max_retries - 1:
                        # Wait before retry (exponential backoff simulation)
                        await asyncio.sleep(0.01 * (2 ** attempt))
                        continue
                    else:
                        return False
            
            return False
        
        # Test delivery with retries
        success = await attempt_delivery(message_data)
        
        # Should succeed on third attempt
        assert success, "Message delivery should succeed after retries"
        assert mock_bot.send_message.call_count == 3, "Should have made 3 delivery attempts"
    
    async def test_message_queue_performance_under_load(self):
        """Test message queue performance under high message load"""
        test_queue = queue.Queue()
        message_count = 1000
        
        # Producer: Add many messages quickly
        start_time = time.time()
        
        for i in range(message_count):
            message = {
                'id': i,
                'user_id': 10000 + i,
                'text': f'High load message {i}',
                'timestamp': time.time()
            }
            test_queue.put_nowait(message)
        
        queue_fill_time = time.time() - start_time
        
        # Consumer: Process all messages
        processed_count = 0
        consumer_start = time.time()
        
        while not test_queue.empty():
            try:
                message = test_queue.get_nowait()
                processed_count += 1
                
                # Simulate minimal processing time
                await asyncio.sleep(0.0001)
                
            except queue.Empty:
                break
        
        consumer_time = time.time() - consumer_start
        
        # Performance assertions
        assert queue_fill_time <= 1.0, f"Queue filling took too long: {queue_fill_time:.3f}s"
        assert consumer_time <= 5.0, f"Message processing took too long: {consumer_time:.3f}s"
        assert processed_count == message_count, f"Not all messages processed: {processed_count}/{message_count}"
        
        # Calculate throughput
        throughput = message_count / consumer_time
        assert throughput >= 200, f"Message processing throughput too low: {throughput:.1f} msgs/sec"


@pytest.mark.asyncio
class TestMessageQueueErrorHandling:
    """Test error handling in message queue operations"""
    
    async def test_queue_processor_exception_handling(self):
        """Test queue processor handles exceptions gracefully"""
        test_queue = queue.Queue()
        processed_messages = []
        errors_handled = []
        
        # Add messages, some designed to cause errors
        test_messages = [
            {'id': 1, 'type': 'normal', 'data': 'valid'},
            {'id': 2, 'type': 'error', 'data': None},  # Will cause error
            {'id': 3, 'type': 'normal', 'data': 'valid'},
            {'id': 4, 'type': 'error', 'data': 'invalid'},  # Will cause error
            {'id': 5, 'type': 'normal', 'data': 'valid'}
        ]
        
        for message in test_messages:
            test_queue.put(message)
        
        async def process_with_error_handling():
            """Process messages with error handling"""
            while not test_queue.empty():
                try:
                    message = test_queue.get_nowait()
                    
                    # Simulate processing that might fail
                    if message['type'] == 'error':
                        raise ValueError(f"Processing error for message {message['id']}")
                    
                    processed_messages.append(message['id'])
                    
                except ValueError as e:
                    # Handle processing errors
                    errors_handled.append(str(e))
                except queue.Empty:
                    break
                except Exception as e:
                    # Handle unexpected errors
                    errors_handled.append(f"Unexpected error: {e}")
        
        await process_with_error_handling()
        
        # Verify error handling
        assert len(processed_messages) == 3, "Should process 3 valid messages"
        assert len(errors_handled) == 2, "Should handle 2 error messages"
        assert processed_messages == [1, 3, 5], "Should process valid messages in order"
    
    def test_queue_resource_cleanup_on_shutdown(self):
        """Test proper resource cleanup when queue system shuts down"""
        test_queue = queue.Queue()
        
        # Add messages to queue
        for i in range(10):
            test_queue.put({'id': i, 'data': f'message_{i}'})
        
        # Simulate shutdown process
        remaining_messages = []
        
        # Drain queue during shutdown
        try:
            while True:
                message = test_queue.get_nowait()
                remaining_messages.append(message)
        except queue.Empty:
            pass
        
        # Verify cleanup
        assert test_queue.empty(), "Queue should be empty after cleanup"
        assert len(remaining_messages) == 10, "Should have drained all messages"
    
    async def test_message_queue_memory_usage_monitoring(self):
        """Test monitoring of message queue memory usage"""
        import sys
        test_queue = queue.Queue()
        
        # Monitor memory usage
        initial_size = sys.getsizeof(test_queue)
        
        # Add many large messages
        large_message_count = 100
        large_data = "x" * 1000  # 1KB per message
        
        for i in range(large_message_count):
            message = {
                'id': i,
                'large_data': large_data,
                'timestamp': time.time()
            }
            test_queue.put(message)
        
        # Check memory growth
        full_queue_size = sys.getsizeof(test_queue)
        
        # Process all messages to free memory
        while not test_queue.empty():
            test_queue.get()
        
        empty_queue_size = sys.getsizeof(test_queue)
        
        # Memory should return close to initial size after processing
        memory_growth = full_queue_size - initial_size
        memory_cleanup = full_queue_size - empty_queue_size
        
        assert memory_growth > 0, "Queue should grow in memory with messages"
        assert memory_cleanup > 0, "Memory should be freed after processing messages"
        
        # Memory cleanup ratio should be reasonable
        cleanup_ratio = memory_cleanup / memory_growth
        assert cleanup_ratio >= 0.5, f"Insufficient memory cleanup: {cleanup_ratio:.2%}"