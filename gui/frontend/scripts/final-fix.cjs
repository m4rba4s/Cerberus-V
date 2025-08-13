#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Функция для финального исправления
function finalFix(filePath) {
    let content = fs.readFileSync(filePath, 'utf8');
    let modified = false;

    // Исправляем _mode -> mode
    if (content.includes('_mode')) {
        content = content.replace(/_mode/g, 'mode');
        modified = true;
    }

    // Исправляем _uptime -> uptime
    if (content.includes('_uptime')) {
        content = content.replace(/_uptime/g, 'uptime');
        modified = true;
    }

    // Исправляем _isConnected -> isConnected
    if (content.includes('_isConnected')) {
        content = content.replace(/_isConnected/g, 'isConnected');
        modified = true;
    }

    // Исправляем _settingsSections -> settingsSections
    if (content.includes('_settingsSections')) {
        content = content.replace(/_settingsSections/g, 'settingsSections');
        modified = true;
    }

    // Удаляем дублирующиеся NetworkCheck
    if (content.includes('NetworkCheck,\n  NetworkCheck,')) {
        content = content.replace(/NetworkCheck,\n  NetworkCheck,/g, 'NetworkCheck,');
        modified = true;
    }

    // Исправляем WebSocketData интерфейс
    if (content.includes('Property \'_mode\' does not exist on type \'WebSocketData\'')) {
        // Добавляем недостающие свойства
        if (content.includes('interface WebSocketData')) {
            content = content.replace(
                /interface WebSocketData \{/,
                `interface WebSocketData {
  mode?: string;
  rules_count?: number;`
            );
            modified = true;
        }
    }

    // Исправляем formatTimestamp
    if (content.includes('formatTimestamp(wsData.timestamp)')) {
        content = content.replace(
            /formatTimestamp\(wsData\.timestamp\)/g,
            'formatTimestamp(wsData.timestamp || "")'
        );
        modified = true;
    }

    // Исправляем data.data.interfaces
    if (content.includes('data.data.interfaces[0].name')) {
        content = content.replace(
            /data\.data\.interfaces\[0\]\.name/g,
            'data.data?.interfaces?.[0]?.name || "unknown"'
        );
        modified = true;
    }

    if (modified) {
        fs.writeFileSync(filePath, content);
        console.log(`✅ Финально исправлен: ${filePath}`);
    }
}

// Файлы для финального исправления
const filesToFix = [
    'src/contexts/ModeContext.tsx',
    'src/pages/Analytics.tsx',
    'src/pages/Monitoring.tsx',
    'src/pages/Settings.tsx',
    'src/types/index.ts'
];

console.log('🔧 Финальное исправление ошибок...');

filesToFix.forEach(file => {
    const fullPath = path.join(__dirname, '..', file);
    if (fs.existsSync(fullPath)) {
        try {
            finalFix(fullPath);
        } catch (error) {
            console.error(`❌ Ошибка при обработке ${file}:`, error.message);
        }
    }
});

// Обновляем WebSocketData интерфейс
const typesPath = path.join(__dirname, '..', 'src', 'types', 'index.ts');
if (fs.existsSync(typesPath)) {
    let typesContent = fs.readFileSync(typesPath, 'utf8');
    
    if (typesContent.includes('interface WebSocketData')) {
        typesContent = typesContent.replace(
            /interface WebSocketData \{[\s\S]*?\}/,
            `interface WebSocketData {
  timestamp?: string;
  mode?: string;
  rules_count?: number;
  status?: string;
  uptime?: number;
  engine_status?: string;
  demo_mode?: boolean;
  interfaces?: Array<{
    name: string;
    status: string;
    speed: number;
  }>;
}`
        );
        fs.writeFileSync(typesPath, typesContent);
        console.log('✅ Обновлен WebSocketData интерфейс');
    }
}

console.log('✅ Финальное исправление завершено!'); 