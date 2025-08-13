#!/usr/bin/env node

import http from 'http';

const testUrls = [
  'http://localhost:3000',
  'http://localhost:3000/vpp',
  'http://localhost:3000/ebpf',
  'http://localhost:3000/performance'
];

const testApiEndpoints = [
  'http://localhost:8081/api/vpp/status',
  'http://localhost:8081/api/ebpf/status',
  'http://localhost:8081/api/system/info'
];

function testUrl(url) {
  return new Promise((resolve) => {
    const req = http.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        resolve({
          url,
          status: res.statusCode,
          success: res.statusCode === 200,
          data: data.substring(0, 100) + '...'
        });
      });
    });
    
    req.on('error', (err) => {
      resolve({
        url,
        status: 'ERROR',
        success: false,
        error: err.message
      });
    });
    
    req.setTimeout(5000, () => {
      req.destroy();
      resolve({
        url,
        status: 'TIMEOUT',
        success: false,
        error: 'Request timeout'
      });
    });
  });
}

async function runTests() {
  console.log('🚀 Testing Cerberus-V Dashboard Pages...\n');
  
  console.log('📄 Testing Frontend Pages:');
  for (const url of testUrls) {
    const result = await testUrl(url);
    const status = result.success ? '✅' : '❌';
    console.log(`${status} ${url} - ${result.status}`);
  }
  
  console.log('\n🔌 Testing API Endpoints:');
  for (const url of testApiEndpoints) {
    const result = await testUrl(url);
    const status = result.success ? '✅' : '❌';
    console.log(`${status} ${url} - ${result.status}`);
  }
  
  console.log('\n🎯 Test Summary:');
  console.log('Frontend: http://localhost:3000');
  console.log('Backend API: http://localhost:8081');
  console.log('API Docs: http://localhost:8081/docs');
}

runTests().catch(console.error); 