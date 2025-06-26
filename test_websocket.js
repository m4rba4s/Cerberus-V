const WebSocket = require('ws');

console.log('Testing WebSocket connection to ws://localhost:8081/ws...');

const ws = new WebSocket('ws://localhost:8081/ws');

ws.on('open', function open() {
  console.log('✅ WebSocket connected successfully!');
  console.log('Sending ping...');
  ws.send('ping');
  
  setTimeout(() => {
    console.log('Closing connection...');
    ws.close();
  }, 2000);
});

ws.on('message', function message(data) {
  console.log('📨 Received:', data.toString());
});

ws.on('error', function error(err) {
  console.log('❌ WebSocket error:', err.message);
});

ws.on('close', function close() {
  console.log('🔌 WebSocket connection closed');
  process.exit(0);
});

// Timeout if connection takes too long
setTimeout(() => {
  console.log('⏰ Connection timeout - WebSocket did not connect within 10 seconds');
  ws.close();
  process.exit(1);
}, 10000); 