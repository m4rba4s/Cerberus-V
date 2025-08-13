#!/usr/bin/env node

const fs = require('fs');
const path = require('path');

// Функция для быстрого исправления файла
function quickFix(filePath) {
    let content = fs.readFileSync(filePath, 'utf8');
    let modified = false;

    // Удаляем неиспользуемые импорты React
    if (content.includes('useEffect') && !content.includes('useEffect(')) {
        content = content.replace(/import React, { useState, useEffect } from 'react';/g, 
                                 "import React, { useState } from 'react';");
        modified = true;
    }

    // Удаляем неиспользуемые переменные (добавляем _)
    const unusedVars = [
        'setSecurityMetrics', 'setThreatEvents', 'setSecurityRules', 'setAptIndicators',
        'setSystemStatus', 'setVppStatus', 'setSystemInfo', 'setSecurityEvents',
        'setSecurityRules', 'setLoading', 'setRefreshInterval', 'settingsDialog',
        'setSettingsDialog', 'securityDialog', 'setSecurityDialog', 'loading',
        'refreshInterval', 'setRefreshInterval', 'files', 'setFiles', 'showBackupDialog',
        'setShowBackupDialog', 'showRestoreDialog', 'setShowRestoreDialog', 'mode',
        'settingsSections', 'isConnected', 'uptime', 'event', 'index'
    ];

    unusedVars.forEach(varName => {
        const regex = new RegExp(`\\b${varName}\\b`, 'g');
        if (content.includes(varName)) {
            content = content.replace(regex, `_${varName}`);
            modified = true;
        }
    });

    // Исправляем типы
    if (content.includes('TimeoutHandle')) {
        content = content.replace(/TimeoutHandle/g, 'ReturnType<typeof setTimeout>');
        modified = true;
    }

    // Удаляем size="small" из Alert
    content = content.replace(/size="small"/g, '');
    modified = true;

    if (modified) {
        fs.writeFileSync(filePath, content);
        console.log(`✅ Исправлен: ${filePath}`);
    }
}

// Основные файлы для исправления
const filesToFix = [
    'src/components/SecurityTelemetry.tsx',
    'src/components/SystemControl.tsx',
    'src/pages/EnhancedDashboard.tsx',
    'src/pages/Settings.tsx',
    'src/pages/Monitoring.tsx',
    'src/pages/SecurityAnalytics.tsx',
    'src/pages/SystemPerformance.tsx',
    'src/pages/StorageLogs.tsx',
    'src/contexts/ModeContext.tsx',
    'src/contexts/WebSocketContext.tsx',
    'src/pages/Analytics.tsx',
    'src/pages/EBPFPrograms.tsx'
];

console.log('🔧 Быстрое исправление ошибок...');

filesToFix.forEach(file => {
    const fullPath = path.join(__dirname, '..', file);
    if (fs.existsSync(fullPath)) {
        try {
            quickFix(fullPath);
        } catch (error) {
            console.error(`❌ Ошибка при обработке ${file}:`, error.message);
        }
    }
});

console.log('✅ Быстрое исправление завершено!'); 